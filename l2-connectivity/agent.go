package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mdlayher/packet"
)

type agentConfig struct {
	iface       string
	name        string
	etherType   int
	helloEvery  time.Duration
	probeEvery  time.Duration
	probeSize   int
	mtuEvery    time.Duration
	timeout     time.Duration
	window      int
	forget      time.Duration
	reportEvery time.Duration
	duration    time.Duration
	staticPeers []net.HardwareAddr
}

type macKey [6]byte

func keyOf(hw net.HardwareAddr) macKey {
	var k macKey
	copy(k[:], hw)
	return k
}

func (k macKey) String() string { return net.HardwareAddr(k[:]).String() }

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type peer struct {
	mac      macKey
	name     string
	ifaceMTU int
	static   bool

	// Broadcast path: HELLOs we received from this peer.
	lastHello time.Time
	helloSeq  uint32
	helloSeen bool
	bcast     *ring

	// Unicast path: our probes and their replies.
	ucast   *ring
	mtuAcks map[int]time.Time // probe size -> last time it was acknowledged

	// The peer's own view of everyone, from its last HELLO.
	report   []reportEntry
	reportAt time.Time

	lastActivity time.Time // any sign of life, used to forget dead peers
}

type pendingProbe struct {
	peer macKey
	kind uint8
	size int
	sent time.Time
}

type agent struct {
	cfg      agentConfig
	conn     *packet.Conn
	self     macKey
	ifaceMTU int
	mtuSizes []int
	closing  atomic.Bool

	mu       sync.Mutex
	seq      uint32
	helloSeq uint32
	peers    map[macKey]*peer
	pending  map[uint32]pendingProbe
}

// mtuCandidates lists the probe sizes used for path MTU discovery: common
// MTU values below the interface MTU, plus the interface MTU itself.
func mtuCandidates(ifaceMTU int) []int {
	sizes := []int{ifaceMTU}
	for _, s := range []int{576, 1000, 1280, 1400, 1480, 1492, 1500, 4000, 9000} {
		if s < ifaceMTU && s >= minProbeSize {
			sizes = append(sizes, s)
		}
	}
	slices.Sort(sizes)
	return slices.Compact(sizes)
}

// runAgent runs until interrupted (or cfg.duration passes) and returns the
// process exit code.
func runAgent(cfg agentConfig) (int, error) {
	ifi, err := net.InterfaceByName(cfg.iface)
	if err != nil {
		return 0, err
	}
	if len(ifi.HardwareAddr) != 6 {
		return 0, fmt.Errorf("%s has no Ethernet (48-bit) MAC address", cfg.iface)
	}
	conn, err := packet.Listen(ifi, packet.Datagram, cfg.etherType, nil)
	if err != nil {
		return 0, fmt.Errorf("open raw socket on %s (are you root?): %w", cfg.iface, err)
	}

	a := &agent{
		cfg:      cfg,
		conn:     conn,
		self:     keyOf(ifi.HardwareAddr),
		ifaceMTU: ifi.MTU,
		mtuSizes: mtuCandidates(ifi.MTU),
		peers:    make(map[macKey]*peer),
		pending:  make(map[uint32]pendingProbe),
	}
	now := time.Now()
	for _, hw := range cfg.staticPeers {
		p := a.peerFor(keyOf(hw), now)
		p.static = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.duration)
		defer cancel()
	}

	go a.readLoop()

	helloT := time.NewTicker(cfg.helloEvery)
	probeT := time.NewTicker(cfg.probeEvery)
	mtuT := time.NewTicker(cfg.mtuEvery)
	expireT := time.NewTicker(100 * time.Millisecond)
	reportT := time.NewTicker(cfg.reportEvery)
	defer func() {
		helloT.Stop()
		probeT.Stop()
		mtuT.Stop()
		expireT.Stop()
		reportT.Stop()
	}()
	// Run the first MTU round as soon as the initial HELLOs had a chance to
	// arrive instead of waiting a full mtu interval.
	firstMTU := time.After(2 * cfg.helloEvery)

	a.sendHello()
	for {
		select {
		case <-ctx.Done():
			a.closing.Store(true)
			conn.Close()
			// Probes still in flight are neither answered nor lost yet;
			// leave them out of the final numbers.
			v := a.snapshot(time.Now())
			render(os.Stdout, v, false)
			return v.exitCode(), nil
		case <-helloT.C:
			a.sendHello()
		case <-probeT.C:
			a.sendPings()
		case <-firstMTU:
			a.sendMTUProbes()
		case <-mtuT.C:
			a.sendMTUProbes()
		case <-expireT.C:
			a.expire(time.Now())
		case <-reportT.C:
			render(os.Stdout, a.snapshot(time.Now()), isTerminal(os.Stdout))
		}
	}
}

func (a *agent) send(dst net.HardwareAddr, b []byte) {
	if _, err := a.conn.WriteTo(b, &packet.Addr{HardwareAddr: dst}); err != nil && !a.closing.Load() {
		log.Printf("send %d bytes to %s: %v", len(b), dst, err)
	}
}

// peerFor returns the peer for mac, creating it if needed. Caller holds a.mu.
func (a *agent) peerFor(mac macKey, now time.Time) *peer {
	p, ok := a.peers[mac]
	if !ok {
		p = &peer{
			mac:          mac,
			bcast:        newRing(a.cfg.window),
			ucast:        newRing(a.cfg.window),
			mtuAcks:      make(map[int]time.Time),
			lastActivity: now,
		}
		a.peers[mac] = p
	}
	return p
}

// peerList returns all known peers; expire already dropped the forgotten
// ones. Caller holds a.mu.
func (a *agent) peerList() []*peer {
	ps := make([]*peer, 0, len(a.peers))
	for _, p := range a.peers {
		ps = append(ps, p)
	}
	return ps
}

func (a *agent) heardRecently(p *peer, now time.Time) bool {
	return p.helloSeen && now.Sub(p.lastHello) < 3*a.cfg.helloEvery
}

// pathMTU is the largest probe size the peer acknowledged over the last few
// MTU rounds. Looking at several rounds keeps one unlucky drop on a lossy
// link from shrinking the result.
func (a *agent) pathMTU(p *peer, now time.Time) int {
	best := 0
	for size, at := range p.mtuAcks {
		if now.Sub(at) < 3*a.cfg.mtuEvery+a.cfg.timeout && size > best {
			best = size
		}
	}
	return best
}

func (a *agent) localEntry(p *peer, now time.Time) reportEntry {
	u := p.ucast.stats()
	e := reportEntry{
		MAC:           p.mac,
		RTTMicros:     unknownRTT,
		ULossPermille: u.lossPermille(),
		BLossPermille: p.bcast.stats().lossPermille(),
		MTU:           uint16(a.pathMTU(p, now)),
	}
	if u.answered > 0 {
		e.RTTMicros = uint32(u.avgRTT / time.Microsecond)
	}
	if a.heardRecently(p, now) {
		e.Flags |= flagHeardHello
	}
	return e
}

func (a *agent) sendHello() {
	now := time.Now()
	a.mu.Lock()
	m := hello{Name: a.cfg.name, IfaceMTU: uint16(a.ifaceMTU)}
	for _, p := range a.peers {
		m.Entries = append(m.Entries, a.localEntry(p, now))
	}
	a.helloSeq++
	b := encodeHello(a.helloSeq, m, a.ifaceMTU)
	a.mu.Unlock()
	a.send(broadcastMAC, b)
}

// queueProbe registers a probe as in flight and returns the frame to send.
// Caller holds a.mu.
func (a *agent) queueProbe(p *peer, kind uint8, size int, now time.Time) []byte {
	a.seq++
	a.pending[a.seq] = pendingProbe{peer: p.mac, kind: kind, size: size, sent: now}
	return encodeProbe(a.seq, kind, size)
}

type outFrame struct {
	dst net.HardwareAddr
	b   []byte
}

func (a *agent) sendPings() {
	now := time.Now()
	var out []outFrame
	a.mu.Lock()
	for _, p := range a.peerList() {
		out = append(out, outFrame{net.HardwareAddr(p.mac[:]), a.queueProbe(p, probeKindPing, a.cfg.probeSize, now)})
	}
	a.mu.Unlock()
	for _, f := range out {
		a.send(f.dst, f.b)
	}
}

func (a *agent) sendMTUProbes() {
	now := time.Now()
	var out []outFrame
	a.mu.Lock()
	for _, p := range a.peerList() {
		for _, size := range a.mtuSizes {
			out = append(out, outFrame{net.HardwareAddr(p.mac[:]), a.queueProbe(p, probeKindMTU, size, now)})
		}
	}
	a.mu.Unlock()
	for _, f := range out {
		a.send(f.dst, f.b)
	}
}

// expire counts unanswered probes as lost and forgets peers that went quiet.
func (a *agent) expire(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for seq, pp := range a.pending {
		if now.Sub(pp.sent) < a.cfg.timeout {
			continue
		}
		delete(a.pending, seq)
		if p, ok := a.peers[pp.peer]; ok && pp.kind == probeKindPing {
			p.ucast.add(false, 0)
		}
	}
	for mac, p := range a.peers {
		if !p.static && now.Sub(p.lastActivity) > a.cfg.forget {
			delete(a.peers, mac)
		}
	}
}

func (a *agent) readLoop() {
	buf := make([]byte, a.ifaceMTU+64)
	for {
		n, addr, err := a.conn.ReadFrom(buf)
		if err != nil {
			if a.closing.Load() {
				return
			}
			log.Printf("read: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		src := keyOf(addr.(*packet.Addr).HardwareAddr)
		if src == a.self {
			continue
		}
		h, body, err := decode(buf[:n])
		if err != nil {
			if err != errNotOurs {
				log.Printf("from %s: %v", src, err)
			}
			continue
		}
		now := time.Now()
		switch h.Type {
		case msgHello:
			m, err := parseHello(body)
			if err != nil {
				log.Printf("hello from %s: %v", src, err)
				continue
			}
			a.onHello(src, h.Seq, m, now)
		case msgProbe:
			kind, err := parseProbeKind(body)
			if err != nil {
				continue
			}
			a.send(net.HardwareAddr(src[:]), encodeReply(h.Seq, reply{Kind: kind, RxLen: h.Length}))
			// Someone reaching us is a peer even if its broadcasts don't
			// (e.g. broadcast filtered, or it was given us with -peer).
			a.mu.Lock()
			a.peerFor(src, now).lastActivity = now
			a.mu.Unlock()
		case msgReply:
			r, err := parseReply(body)
			if err != nil {
				continue
			}
			a.onReply(src, h.Seq, r, now)
		}
	}
}

func (a *agent) onHello(src macKey, seq uint32, m hello, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.peerFor(src, now)
	p.name = m.Name
	p.ifaceMTU = int(m.IfaceMTU)

	// Sequence gaps are HELLOs the air (or the switch) ate.
	switch diff := seq - p.helloSeq; {
	case !p.helloSeen:
		p.bcast.add(true, 0)
	case diff == 0:
		return // duplicate
	case diff < 1<<16:
		for i := uint32(1); i < diff && i <= uint32(a.cfg.window); i++ {
			p.bcast.add(false, 0)
		}
		p.bcast.add(true, 0)
	default:
		// Went backwards: the peer restarted.
		p.bcast.reset()
		p.bcast.add(true, 0)
	}
	p.helloSeen = true
	p.helloSeq = seq
	p.lastHello = now
	p.lastActivity = now
	p.report = m.Entries
	p.reportAt = now

	// Learn about nodes the peer can reach, so we probe them too even if
	// their broadcasts never reach us.
	for _, e := range m.Entries {
		if e.MAC == a.self {
			continue
		}
		if e.Flags&flagHeardHello != 0 || e.ULossPermille < 1000 {
			a.peerFor(e.MAC, now).lastActivity = now
		}
	}
}

func (a *agent) onReply(src macKey, seq uint32, r reply, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	pp, ok := a.pending[seq]
	if !ok || pp.peer != src {
		return // late (already counted as lost) or not ours
	}
	delete(a.pending, seq)
	p, ok := a.peers[src]
	if !ok {
		return
	}
	p.lastActivity = now
	switch pp.kind {
	case probeKindPing:
		p.ucast.add(true, now.Sub(pp.sent))
	case probeKindMTU:
		if int(r.RxLen) == pp.size {
			p.mtuAcks[pp.size] = now
		}
	}
}
