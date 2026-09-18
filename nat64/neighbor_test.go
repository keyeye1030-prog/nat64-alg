package nat64

import (
	"net"
	"testing"
	"time"
)

func TestNeighborTable_CleanExpired(t *testing.T) {
	nt := NewNeighborTable()

	ipStatic := net.ParseIP("2001:db8:64::1")
	macStatic, _ := net.ParseMAC("00:11:22:33:44:55")
	nt.SetStatic(ipStatic, macStatic)

	ipFresh := net.ParseIP("2001:db8:64::10")
	macFresh, _ := net.ParseMAC("00:11:22:33:44:66")
	nt.Learn(ipFresh, macFresh)

	ipStale := net.ParseIP("2001:db8:64::20")
	macStale, _ := net.ParseMAC("00:11:22:33:44:77")
	nt.Learn(ipStale, macStale)

	// Manually backdate LastSeen for ipStale
	nt.mu.Lock()
	if entry, ok := nt.entries[ipStale.String()]; ok {
		entry.LastSeen = time.Now().Add(-6 * time.Minute)
	}
	nt.mu.Unlock()

	total, dyn, st := nt.Stats()
	if total != 3 || dyn != 2 || st != 1 {
		t.Fatalf("Stats before clean: total=%d, dyn=%d, st=%d; want (3, 2, 1)", total, dyn, st)
	}

	// Clean entries older than 5 minutes
	cleaned := nt.CleanExpired(5 * time.Minute)
	if cleaned != 1 {
		t.Fatalf("CleanExpired cleaned %d entries, want 1", cleaned)
	}

	// Verify ipStale is removed
	if _, ok := nt.Lookup(ipStale); ok {
		t.Errorf("Stale entry %s should have been removed", ipStale)
	}

	// Verify ipFresh is retained
	if mac, ok := nt.Lookup(ipFresh); !ok || mac.String() != macFresh.String() {
		t.Errorf("Fresh entry %s should be retained", ipFresh)
	}

	// Verify ipStatic is retained
	if mac, ok := nt.Lookup(ipStatic); !ok || mac.String() != macStatic.String() {
		t.Errorf("Static entry %s should be retained", ipStatic)
	}

	totalAfter, dynAfter, stAfter := nt.Stats()
	if totalAfter != 2 || dynAfter != 1 || stAfter != 1 {
		t.Fatalf("Stats after clean: total=%d, dyn=%d, st=%d; want (2, 1, 1)", totalAfter, dynAfter, stAfter)
	}
}

func TestNeighborTable_StartCleaner(t *testing.T) {
	nt := NewNeighborTable()

	ip := net.ParseIP("198.51.100.50")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	nt.Learn(ip, mac)

	// Manually backdate
	nt.mu.Lock()
	nt.entries[ip.String()].LastSeen = time.Now().Add(-100 * time.Millisecond)
	nt.mu.Unlock()

	stopCh := make(chan struct{})
	nt.StartCleaner(20*time.Millisecond, 50*time.Millisecond, stopCh)

	time.Sleep(80 * time.Millisecond)
	close(stopCh)

	if _, ok := nt.Lookup(ip); ok {
		t.Fatalf("Expected %s to be cleaned up by background cleaner goroutine", ip)
	}
}
