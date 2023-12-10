package scan

import "github.com/songzhibin97/open_ports/diagnostic"

const (
	mtu = 1500
)

const (
	protocolICMP = 1
	snapshotLen  = 1024
)

var (
	ErrScanClosed = diagnostic.NewErrorDiagnostic("scan closed")
)
