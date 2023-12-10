package scan

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/songzhibin97/go-baseutils/base/options"

	"github.com/songzhibin97/open_ports/retry"

	"github.com/songzhibin97/open_ports/diagnostic"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var (
	invalidResponse = errors.New("invalid ICMP Echo Reply message")
)

var _ Scan = (*ICMPScan)(nil)

type ICMPScan struct {
	config *Config
}

func (i ICMPScan) Scan(host string, port int) *diagnostic.Diagnostic {
	dst, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}

	defer conn.Close()

	id := os.Getpid() & 0xffff

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  1,
			Data: []byte(""),
		},
	}

	encodeMsg, err := msg.Marshal(nil)
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}

	start := time.Now()
	_, err = conn.WriteTo(encodeMsg, dst)
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}
	reply := make([]byte, mtu)
	var result Result

	err = retry.DoRetry("icmp", func() error {
		err := conn.SetReadDeadline(time.Now().Add(i.config.Timeout))
		if err != nil {
			return err
		}

		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			return err
		}
		msg, err = icmp.ParseMessage(protocolICMP, reply[:n])
		if err != nil {
			return err
		}

		switch msg.Type {
		case ipv4.ICMPTypeEchoReply:
			echoReply, ok := msg.Body.(*icmp.Echo)
			if !ok {
				return invalidResponse
			}

			if peer.String() == host && echoReply.ID == id && echoReply.Seq == 1 {
				result = Result{
					Host:     host,
					Port:     0,
					ScanType: "icmp",
					Cost:     time.Since(start),
				}
				return nil
			}
			return errors.New(fmt.Sprintf("unexpected ICMP Echo Reply Host: %v, pid: %d, reply: %v\n", peer.String(), id, echoReply))

		default:
			return errors.New(fmt.Sprintf("unexpected ICMP message type: %v\n", msg.Type))
		}
	}, nil, i.config.Retry)
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}

	return diagnostic.NewDiagnostic(diagnostic.DiagnosisLevelTrace, result)
}

func NewICMPScan(options ...options.Option[*Config]) *ICMPScan {
	config := NewDefaultConfig()
	for _, option := range options {
		option(config)
	}
	return &ICMPScan{
		config: config,
	}
}
