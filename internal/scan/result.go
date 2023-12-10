package scan

import "time"

type Result struct {
	Host     string        `json:"host"`
	Port     int           `json:"port"`
	ScanType string        `json:"scan_type"`
	Cost     time.Duration `json:"cost"`
}
