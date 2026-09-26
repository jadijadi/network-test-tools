package main

import (
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/mdlayher/packet"
)

const ethPAll = 0x0003 // ETH_P_ALL: every protocol

type sniffConfig struct {
	iface       string
	promisc     bool
	reportEvery time.Duration
	duration    time.Duration
}

// source is what we learned about one sender MAC. Seeing a frame whose
// source MAC is X proves X is on our L2 segment: a router would have
// rewritten it to its own MAC.
type source struct {
	mac        macKey
	frames     int
	bytes      int
	toBcast    int
	toMcast    int
	toMe       int
	toOthers   int // unicast not addressed to us: flooding, promisc or a hub
	etherTypes map[uint16]int
	ips        map[netip.Addr]bool // from ARP, which is only ever sent by the owner
	lastSeen   time.Time
}

type sniffer struct {
	cfg     sniffConfig
	self    macKey
	start   time.Time
	mu      sync.Mutex
	total   int
	sources map[macKey]*source
}

var etherTypeNames = map[uint16]string{
	0x0800: "ipv4",
	0x0806: "arp",
	0x86dd: "ipv6",
	0x8100: "vlan",
	0x88a8: "qinq",
	0x88cc: "lldp",
	0x888e: "eapol",
	0x4305: "batman",
	0x88b5: "l2ct",
	0x8809: "slow",
	0x8847: "mpls",
	0x8863: "pppoe-d",
	0x8864: "pppoe-s",
}

func etherTypeName(t uint16) string {
	if n, ok := etherTypeNames[t]; ok {
		return n
	}
	if t < 0x0600 {
		return "802.3/llc"
	}
	return fmt.Sprintf("0x%04x", t)
}

func runSniff(cfg sniffConfig) error {
	ifi, err := net.InterfaceByName(cfg.iface)
	if err != nil {
		return err
	}
	if len(ifi.HardwareAddr) != 6 {
		return fmt.Errorf("%s has no Ethernet (48-bit) MAC address", cfg.iface)
	}
	conn, err := packet.Listen(ifi, packet.Raw, ethPAll, nil)
	if err != nil {
		return fmt.Errorf("open raw socket on %s (are you root?): %w", cfg.iface, err)
	}
	if cfg.promisc {
		if err := conn.SetPromiscuous(true); err != nil {
			log.Printf("promiscuous mode: %v (continuing without it)", err)
		}
	}

	s := &sniffer{cfg: cfg, self: keyOf(ifi.HardwareAddr), start: time.Now(), sources: make(map[macKey]*source)}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.duration)
		defer cancel()
	}

	var closing atomic.Bool
	go func() {
		buf := make([]byte, ifi.MTU+64)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				if closing.Load() {
					return
				}
				log.Printf("read: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			s.observe(buf[:n], time.Now())
		}
	}()

	t := time.NewTicker(cfg.reportEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			closing.Store(true)
			conn.Close()
			s.render(os.Stdout, time.Now(), false)
			return nil
		case <-t.C:
			s.render(os.Stdout, time.Now(), isTerminal(os.Stdout))
		}
	}
}

func (s *sniffer) observe(f []byte, now time.Time) {
	if len(f) < 14 {
		return
	}
	dst, src := f[0:6], keyOf(f[6:12])
	et := binary.BigEndian.Uint16(f[12:14])
	payload := f[14:]
	// Skip VLAN tags to reach the real EtherType.
	for (et == 0x8100 || et == 0x88a8) && len(payload) >= 4 {
		et = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.total++
	// Our own outgoing frames are looped back to ETH_P_ALL sockets.
	if src == s.self {
		return
	}
	rec := s.sources[src]
	if rec == nil {
		rec = &source{mac: src, etherTypes: make(map[uint16]int), ips: make(map[netip.Addr]bool)}
		s.sources[src] = rec
	}
	rec.frames++
	rec.bytes += len(f)
	rec.etherTypes[et]++
	rec.lastSeen = now
	switch {
	case keyOf(dst) == keyOf(broadcastMAC):
		rec.toBcast++
	case dst[0]&1 == 1:
		rec.toMcast++
	case keyOf(dst) == s.self:
		rec.toMe++
	default:
		rec.toOthers++
	}
	// ARP sender protocol address (Ethernet/IPv4 ARP only).
	if et == 0x0806 && len(payload) >= 28 && binary.BigEndian.Uint16(payload[0:2]) == 1 &&
		binary.BigEndian.Uint16(payload[2:4]) == 0x0800 {
		if ip := netip.AddrFrom4([4]byte(payload[14:18])); !ip.IsUnspecified() {
			rec.ips[ip] = true
		}
	}
}

func (s *sniffer) render(w io.Writer, now time.Time, clear bool) {
	// Copy what we print under the lock so the reader is not held up by
	// formatting and output.
	type row struct {
		mac                               macKey
		frames, bytes, bc, mc, me, others int
		types, ips                        string
		age                               time.Duration
	}
	s.mu.Lock()
	total := s.total
	rows := make([]row, 0, len(s.sources))
	for _, src := range s.sources {
		rows = append(rows, row{
			mac: src.mac, frames: src.frames, bytes: src.bytes,
			bc: src.toBcast, mc: src.toMcast, me: src.toMe, others: src.toOthers,
			types: fmtEtherTypes(src.etherTypes), ips: fmtIPs(src.ips), age: now.Sub(src.lastSeen),
		})
	}
	s.mu.Unlock()
	slices.SortFunc(rows, func(a, b row) int { return cmp.Compare(b.frames, a.frames) })

	var sb strings.Builder
	if clear {
		sb.WriteString("\033[H\033[2J")
	}
	fmt.Fprintf(&sb, "l2-connectivity sniff  %s  iface %s  mac %s  promisc %v  running %s\n",
		now.Format("2006-01-02 15:04:05"), s.cfg.iface, s.self, s.cfg.promisc, now.Sub(s.start).Truncate(time.Second))
	fmt.Fprintf(&sb, "%d frames seen, %d L2 neighbours (source MACs other than ours)\n\n", total, len(rows))
	tw := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "source mac\tframes\tbytes\tbcast\tmcast\tto me\tto others\tlast seen\tarp ips\tethertypes\t")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s ago\t%s\t%s\t\n",
			r.mac, r.frames, r.bytes, r.bc, r.mc, r.me, r.others, r.age.Truncate(100*time.Millisecond), r.ips, r.types)
	}
	tw.Flush()
	sb.WriteString("\nOne direction only: this proves these MACs' frames reach us, not that ours reach them. Use `agent` for that.\n")
	io.WriteString(w, sb.String())
}

func fmtEtherTypes(m map[uint16]int) string {
	types := make([]uint16, 0, len(m))
	for t := range m {
		types = append(types, t)
	}
	slices.SortFunc(types, func(a, b uint16) int { return cmp.Compare(m[b], m[a]) })
	parts := make([]string, len(types))
	for i, t := range types {
		parts[i] = fmt.Sprintf("%s:%d", etherTypeName(t), m[t])
	}
	return strings.Join(parts, " ")
}

func fmtIPs(m map[netip.Addr]bool) string {
	if len(m) == 0 {
		return "-"
	}
	ips := make([]netip.Addr, 0, len(m))
	for ip := range m {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	parts := make([]string, len(ips))
	for i, ip := range ips {
		parts[i] = ip.String()
	}
	return strings.Join(parts, ",")
}
