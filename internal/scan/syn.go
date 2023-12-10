package scan

import (
	"context"
	"math/rand"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/songzhibin97/go-baseutils/app/bcache"
	"github.com/songzhibin97/open_ports/internal/router"

	"github.com/google/gopacket"

	"github.com/google/gopacket/layers"

	"github.com/songzhibin97/go-baseutils/base/options"

	"github.com/songzhibin97/open_ports/diagnostic"
)

var _ Scan = (*SynScan)(nil)
var _ Accept = (*SynScan)(nil)
var _ Close = (*SynScan)(nil)

type SynScan struct {
	config    *Config
	extraInfo *router.ExtraInfo
	handle    *pcap.Handle
	close     atomic.Bool
	buffer    *bcache.BCache[pair, time.Time]
	srcPort   int
}

func (s *SynScan) Accept(ctx context.Context) chan *diagnostic.Diagnostic {
	ch := make(chan *diagnostic.Diagnostic)
	go func() {
		defer close(ch)
		if s.close.Load() {
			ch <- ErrScanClosed
			return
		}
		packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
		for {
			select {
			case <-ctx.Done():
				return
			case pkg, ok := <-packetSource.Packets():
				if !ok {
					return
				}
				tcpPackage := pkg.Layer(layers.LayerTypeTCP)
				if tcpPackage == nil {
					continue
				}
				tcp, ok := tcpPackage.(*layers.TCP)
				if !ok {
					continue
				}
				if tcp.SYN && tcp.ACK {
					v, ok := s.buffer.Get(pair{
						host: pkg.NetworkLayer().NetworkFlow().Src().String(),
						port: int(tcp.SrcPort),
					})
					rs := Result{
						Host:     pkg.NetworkLayer().NetworkFlow().Src().String(),
						Port:     int(tcp.SrcPort),
						ScanType: "syc-ack",
						Cost:     0,
					}
					if ok {
						rs.Cost = time.Since(v)
					}
					ch <- diagnostic.NewDiagnostic(diagnostic.DiagnosisLevelTrace, rs)
				}
			}
		}
	}()
	return ch
}
func (s *SynScan) Close() {
	if s.close.CompareAndSwap(false, true) {
		s.handle.Close()
	}
}

func (s *SynScan) Scan(host string, port int) *diagnostic.Diagnostic {
	if s.close.Load() {
		return ErrScanClosed
	}

	dstIP := net.ParseIP(host)
	dstPort := layers.TCPPort(port)

	srcIP := s.extraInfo.SrcIP

	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	ethLayer := &layers.Ethernet{
		SrcMAC:       s.extraInfo.IFace.HardwareAddr,
		DstMAC:       s.extraInfo.DstHWAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(s.srcPort),
		Seq:     uint32(r.Intn(1 << 32)),
		DstPort: dstPort,
		SYN:     true,
	}

	err := tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer)
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}
	outgoingPacket := buf.Bytes()

	start := time.Now()

	err = s.handle.WritePacketData(outgoingPacket)
	if err != nil {
		return diagnostic.NewErrorDiagnostic(err)
	}

	s.buffer.SetDefault(pair{
		host: host,
		port: port,
	}, start)

	return nil
}

func NewSyncScan(dst string, options ...options.Option[*Config]) (*SynScan, error) {
	config := NewDefaultConfig()
	for _, option := range options {
		option(config)
	}
	extraInfo, err := router.GetRouterInfo(net.ParseIP(dst))
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(extraInfo.IFace.Name, snapshotLen, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	srcPort, err := router.GetFreePort()
	if err != nil {
		return nil, err
	}

	err = handle.SetBPFFilter("tcp and dst host " + extraInfo.SrcIP.String() + " and dst port " + strconv.Itoa(srcPort))
	if err != nil {
		return nil, err
	}
	return &SynScan{
		config:    config,
		extraInfo: extraInfo,
		handle:    handle,
		buffer: bcache.New[pair, time.Time](func(a, b pair) int {
			return 0
		},
			bcache.SetDefaultExpire[pair, time.Time](config.Timeout),
			bcache.SetCapture[pair, time.Time](nil),
		),
		srcPort: srcPort,
	}, nil
}
