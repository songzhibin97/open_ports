package scan

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/songzhibin97/go-baseutils/base/options"
	"github.com/songzhibin97/open_ports/diagnostic"
)

var _ Scan = (*ConnScan)(nil)

type UdpScan struct {
	config *Config
}

func (s UdpScan) Scan(host string, port int) *diagnostic.Diagnostic {
	start := time.Now()
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}
	defer conn.Close()
	data := []byte{}
	_, err = conn.Write(data)
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}
	err = conn.SetReadDeadline(time.Now().Add(s.config.Timeout))
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}

	buffer := make([]byte, 1024)
	_, _, err = conn.ReadFromUDP(buffer)
	if err != nil {
		var netErr net.Error
		ok := errors.As(err, &netErr)
		if ok && netErr.Timeout() {
			return nil
		} else {
			return diagnostic.NewErrorDiagnostic(err)
		}
	}

	return diagnostic.NewDiagnostic(diagnostic.DiagnosisLevelTrace, Result{
		Host:     host,
		Port:     port,
		ScanType: "udp",
		Cost:     time.Since(start),
	})
}

func NewUdpScan(options ...options.Option[*Config]) *UdpScan {
	config := NewDefaultConfig()
	for _, option := range options {
		option(config)
	}
	return &UdpScan{
		config: config,
	}
}
