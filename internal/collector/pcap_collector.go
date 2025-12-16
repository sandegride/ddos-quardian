//go:build pcap

package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketEvent struct {
	Ts     time.Time
	SrcIP  string
	DstIP  string
	Proto  string // TCP/UDP/ICMP/OTHER
	Length int
	TCPSYN bool
	TCPACK bool
}

type Options struct {
	// HTTP mode options (ignored here)
	ListenAddr string
	BackendURL string

	// pcap mode options
	Interface string
	BPF       string
	SnapLen   int32
	Promisc   bool
	Timeout   time.Duration
}

func Run(ctx context.Context, opt Options, out chan<- PacketEvent) error {
	if opt.SnapLen == 0 {
		opt.SnapLen = 65535
	}
	if opt.Timeout == 0 {
		opt.Timeout = pcap.BlockForever
	}

	handle, err := pcap.OpenLive(opt.Interface, opt.SnapLen, opt.Promisc, opt.Timeout)
	if err != nil {
		return fmt.Errorf("pcap open: %w", err)
	}
	defer handle.Close()

	if opt.BPF != "" {
		if err := handle.SetBPFFilter(opt.BPF); err != nil {
			return fmt.Errorf("set BPF: %w", err)
		}
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := src.Packets()

	for {
		select {
		case <-ctx.Done():
			return nil
		case p, ok := <-packets:
			if !ok {
				return nil
			}
			ev := PacketEvent{
				Ts:     p.Metadata().Timestamp,
				Length: len(p.Data()),
				Proto:  "OTHER",
			}

			if ip4 := p.Layer(layers.LayerTypeIPv4); ip4 != nil {
				l := ip4.(*layers.IPv4)
				ev.SrcIP, ev.DstIP = l.SrcIP.String(), l.DstIP.String()
			} else if ip6 := p.Layer(layers.LayerTypeIPv6); ip6 != nil {
				l := ip6.(*layers.IPv6)
				ev.SrcIP, ev.DstIP = l.SrcIP.String(), l.DstIP.String()
			}

			if tcpL := p.Layer(layers.LayerTypeTCP); tcpL != nil {
				ev.Proto = "TCP"
				tcp := tcpL.(*layers.TCP)
				ev.TCPSYN = tcp.SYN && !tcp.ACK
				ev.TCPACK = tcp.ACK
			} else if p.Layer(layers.LayerTypeUDP) != nil {
				ev.Proto = "UDP"
			} else if p.Layer(layers.LayerTypeICMPv4) != nil || p.Layer(layers.LayerTypeICMPv6) != nil {
				ev.Proto = "ICMP"
			}

			select {
			case out <- ev:
			case <-ctx.Done():
				return nil
			}
		}
	}
}
