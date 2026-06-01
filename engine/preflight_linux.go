//go:build linux
// +build linux

package engine

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type PreflightConfig struct {
	Interfaces         []string
	MinSpeedMbps       int
	RequireFullDuplex  bool
	RequireCarrier     bool
	ExpectedQueues     int
	RequireOffloadsOff bool
}

func RunPreflight(cfg PreflightConfig) error {
	if len(cfg.Interfaces) == 0 {
		return nil
	}
	if cfg.MinSpeedMbps == 0 {
		cfg.MinSpeedMbps = 100
	}
	if cfg.ExpectedQueues == 0 {
		cfg.ExpectedQueues = 1
	}

	log.Printf("[Preflight] checking %d interface(s)", len(cfg.Interfaces))
	for _, name := range cfg.Interfaces {
		if err := checkInterfacePreflight(name, cfg); err != nil {
			return err
		}
	}
	return nil
}

func checkInterfacePreflight(name string, cfg PreflightConfig) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("preflight %s: interface not found: %w", name, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("preflight %s: interface is not UP", name)
	}

	if cfg.RequireCarrier {
		carrier, err := readSysfsInt(name, "carrier")
		if err != nil {
			return fmt.Errorf("preflight %s: cannot read carrier: %w", name, err)
		}
		if carrier != 1 {
			return fmt.Errorf("preflight %s: carrier is down", name)
		}
	}

	link, err := readEthtoolLink(name)
	if err != nil {
		return err
	}
	if cfg.MinSpeedMbps > 0 && link.SpeedMbps > 0 && link.SpeedMbps < cfg.MinSpeedMbps {
		return fmt.Errorf("preflight %s: link speed %dMb/s is below required %dMb/s", name, link.SpeedMbps, cfg.MinSpeedMbps)
	}
	if cfg.MinSpeedMbps > 0 && link.SpeedMbps <= 0 {
		return fmt.Errorf("preflight %s: cannot determine link speed from ethtool", name)
	}
	if cfg.RequireFullDuplex && !strings.EqualFold(link.Duplex, "Full") {
		return fmt.Errorf("preflight %s: duplex is %q, require Full", name, link.Duplex)
	}
	if cfg.RequireCarrier && link.LinkDetected != "" && !strings.EqualFold(link.LinkDetected, "yes") {
		return fmt.Errorf("preflight %s: ethtool reports Link detected: %s", name, link.LinkDetected)
	}

	if cfg.ExpectedQueues > 0 {
		combined, err := readCombinedQueues(name)
		if err != nil {
			return err
		}
		if combined != cfg.ExpectedQueues {
			return fmt.Errorf("preflight %s: combined queues=%d, require %d for current XSK queue binding", name, combined, cfg.ExpectedQueues)
		}
	}

	if cfg.RequireOffloadsOff {
		if err := checkOffloadsDisabled(name); err != nil {
			return err
		}
	}

	log.Printf("[Preflight] %s OK: speed=%dMb/s duplex=%s queues=%d carrier=up", name, link.SpeedMbps, link.Duplex, cfg.ExpectedQueues)
	return nil
}

type ethtoolLink struct {
	SpeedMbps    int
	Duplex       string
	LinkDetected string
}

func readEthtoolLink(name string) (ethtoolLink, error) {
	out, err := exec.Command("ethtool", name).CombinedOutput()
	if err != nil {
		return ethtoolLink{}, fmt.Errorf("preflight %s: ethtool failed: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	var link ethtoolLink
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := splitEthtoolLine(line)
		if !ok {
			continue
		}
		switch key {
		case "Speed":
			link.SpeedMbps = parseSpeedMbps(value)
		case "Duplex":
			link.Duplex = value
		case "Link detected":
			link.LinkDetected = value
		}
	}
	return link, nil
}

func readCombinedQueues(name string) (int, error) {
	out, err := exec.Command("ethtool", "-l", name).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("preflight %s: ethtool -l failed: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	inCurrent := false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Current hardware settings:") {
			inCurrent = true
			continue
		}
		if !inCurrent || !strings.HasPrefix(line, "Combined:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, fmt.Errorf("preflight %s: cannot parse combined queues from %q", name, line)
		}
		return n, nil
	}
	return 0, fmt.Errorf("preflight %s: cannot find current combined queue count in ethtool -l output", name)
}

func checkOffloadsDisabled(name string) error {
	out, err := exec.Command("ethtool", "-k", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("preflight %s: ethtool -k failed: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	requiredOff := map[string]struct{}{
		"tcp-segmentation-offload":     {},
		"generic-segmentation-offload": {},
		"generic-receive-offload":      {},
		"large-receive-offload":        {},
	}
	var enabled []string
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := splitEthtoolLine(line)
		if !ok {
			continue
		}
		if _, required := requiredOff[key]; required && strings.HasPrefix(value, "on") {
			enabled = append(enabled, key)
		}
	}
	if len(enabled) > 0 {
		return fmt.Errorf("preflight %s: offload(s) must be disabled: %s", name, strings.Join(enabled, ", "))
	}
	return nil
}

func splitEthtoolLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func parseSpeedMbps(value string) int {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, "Mb/s")
	value = strings.TrimSuffix(value, "Mbps")
	value = strings.TrimSpace(value)
	n, _ := strconv.Atoi(value)
	return n
}

func readSysfsInt(ifaceName, fileName string) (int, error) {
	path := filepath.Join("/sys/class/net", ifaceName, fileName)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	data = bytes.TrimSpace(data)
	n, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, err
	}
	return n, nil
}
