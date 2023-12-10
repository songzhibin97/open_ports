package scan

import (
	"context"

	"github.com/songzhibin97/open_ports/diagnostic"
)

type Scan interface {
	Scan(host string, port int) *diagnostic.Diagnostic
}

type Accept interface {
	Accept(ctx context.Context) chan *diagnostic.Diagnostic
}

type Close interface {
	Close()
}
