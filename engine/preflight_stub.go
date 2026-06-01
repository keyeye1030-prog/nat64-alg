//go:build !linux
// +build !linux

package engine

import "log"

type PreflightConfig struct {
	Interfaces         []string
	MinSpeedMbps       int
	RequireFullDuplex  bool
	RequireCarrier     bool
	ExpectedQueues     int
	RequireOffloadsOff bool
}

func RunPreflight(cfg PreflightConfig) error {
	if len(cfg.Interfaces) > 0 {
		log.Printf("[Preflight-Stub] skipped physical NIC checks outside Linux")
	}
	return nil
}
