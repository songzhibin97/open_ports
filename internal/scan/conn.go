package scan

import (
	"fmt"
	"net"
	"time"

	"github.com/songzhibin97/go-baseutils/base/options"

	"github.com/songzhibin97/open_ports/diagnostic"
)

var _ Scan = (*ConnScan)(nil)

type ConnScan struct {
	config *Config
}

func (s ConnScan) Scan(host string, port int) *diagnostic.Diagnostic {
	start := time.Now()
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), s.config.Timeout)
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}
	return diagnostic.NewDiagnostic(diagnostic.DiagnosisLevelTrace, Result{
		Host:     host,
		Port:     port,
		ScanType: "conn",
		Cost:     time.Since(start),
	})
}

func NewConnScan(options ...options.Option[*Config]) *ConnScan {
	config := NewDefaultConfig()
	for _, option := range options {
		option(config)
	}
	return &ConnScan{
		config: config,
	}
}
