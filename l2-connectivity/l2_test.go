package main

import (
	"bytes"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func mac(s string) macKey { return keyOf(must(net.ParseMAC(s))) }

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestHelloRoundTrip(t *testing.T) {
	in := hello{
		Name:     "node-a",
		IfaceMTU: 1500,
		Entries: []reportEntry{
			{MAC: mac("02:00:00:00:00:01"), RTTMicros: 1234, ULossPermille: 10, BLossPermille: 50, MTU: 1500, Flags: flagHeardHello},
			{MAC: mac("02:00:00:00:00:02"), RTTMicros: unknownRTT, ULossPermille: unknownLoss, BLossPermille: unknownLoss},
		},
	}
	b := encodeHello(7, in, 1500)
	// Simulate Ethernet padding: trailing garbage must be ignored.
	b = append(b, 0xAA, 0xBB, 0xCC)
	h, body, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != msgHello || h.Seq != 7 {
		t.Fatalf("header = %+v", h)
	}
	out, err := parseHello(body)
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != in.Name || out.IfaceMTU != in.IfaceMTU || !slices.Equal(out.Entries, in.Entries) {
		t.Fatalf("got %+v, want %+v", out, in)
	}
}

func TestHelloTruncatesToFit(t *testing.T) {
	entries := make([]reportEntry, 200)
	b := encodeHello(1, hello{Name: "n", Entries: entries}, 1500)
	if len(b) > 1500 {
		t.Fatalf("hello is %d bytes, want <= 1500", len(b))
	}
	_, body, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseHello(body)
	if err != nil {
		t.Fatal(err)
	}
	if want := (1500 - headerLen - helloFixedLen - 1) / reportEntryLen; len(m.Entries) != want {
		t.Fatalf("got %d entries, want %d", len(m.Entries), want)
	}
}

func TestProbeAndReply(t *testing.T) {
	p := encodeProbe(42, probeKindMTU, 1500)
	if len(p) != 1500 {
		t.Fatalf("probe is %d bytes, want 1500", len(p))
	}
	h, body, err := decode(p)
	if err != nil {
		t.Fatal(err)
	}
	if kind, _ := parseProbeKind(body); h.Type != msgProbe || h.Seq != 42 || h.Length != 1500 || kind != probeKindMTU {
		t.Fatalf("probe header %+v kind %d", h, kind)
	}

	r := encodeReply(42, reply{Kind: probeKindMTU, RxLen: h.Length})
	h, body, err = decode(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseReply(body)
	if err != nil || h.Type != msgReply || got.RxLen != 1500 || got.Kind != probeKindMTU {
		t.Fatalf("reply %+v %+v %v", h, got, err)
	}
}

func TestDecodeRejects(t *testing.T) {
	good := encodeProbe(1, probeKindPing, 64)
	cases := map[string][]byte{
		"short":     good[:5],
		"magic":     append([]byte("XXXX"), good[4:]...),
		"truncated": good[:40], // length field says 64
	}
	for name, b := range cases {
		if _, _, err := decode(b); err == nil {
			t.Errorf("%s: decode succeeded", name)
		}
	}
}

func TestRingStats(t *testing.T) {
	r := newRing(4)
	if s := r.stats(); s.lossPermille() != unknownLoss {
		t.Fatalf("empty ring loss = %d", s.lossPermille())
	}
	r.add(true, 10*time.Millisecond)
	r.add(false, 0)
	r.add(true, 30*time.Millisecond)
	s := r.stats()
	if s.samples != 3 || s.lost != 1 || s.avgRTT != 20*time.Millisecond || s.minRTT != 10*time.Millisecond || s.maxRTT != 30*time.Millisecond {
		t.Fatalf("stats = %+v", s)
	}
	// Overflow the window: only the last 4 count.
	for range 4 {
		r.add(false, 0)
	}
	if s := r.stats(); s.samples != 4 || s.lossPermille() != 1000 {
		t.Fatalf("after overflow = %+v", s)
	}
}

func TestMTUCandidates(t *testing.T) {
	if got, want := mtuCandidates(1500), []int{576, 1000, 1280, 1400, 1480, 1492, 1500}; !slices.Equal(got, want) {
		t.Errorf("1500: got %v want %v", got, want)
	}
	if got, want := mtuCandidates(1420), []int{576, 1000, 1280, 1400, 1420}; !slices.Equal(got, want) {
		t.Errorf("1420: got %v want %v", got, want)
	}
}

func testAgent() *agent {
	return &agent{
		cfg:      agentConfig{iface: "test0", name: "self", helloEvery: time.Second, mtuEvery: 5 * time.Second, timeout: time.Second, window: 100, forget: time.Minute},
		self:     mac("02:00:00:00:00:00"),
		ifaceMTU: 1500,
		peers:    make(map[macKey]*peer),
		pending:  make(map[uint32]pendingProbe),
	}
}

func TestHelloSequenceGapsCountAsBroadcastLoss(t *testing.T) {
	a := testAgent()
	b := mac("02:00:00:00:00:0b")
	now := time.Now()
	for _, seq := range []uint32{1, 2, 5, 5, 6} { // 3 and 4 lost, second 5 is a duplicate
		a.onHello(b, seq, hello{Name: "b"}, now)
	}
	s := a.peers[b].bcast.stats()
	if s.samples != 6 || s.lost != 2 {
		t.Fatalf("bcast stats = %+v, want 6 samples 2 lost", s)
	}
	// Restart: sequence goes backwards, history resets.
	a.onHello(b, 1, hello{Name: "b"}, now)
	if s := a.peers[b].bcast.stats(); s.samples != 1 || s.lost != 0 {
		t.Fatalf("after restart = %+v", s)
	}
}

func TestProbeLifecycle(t *testing.T) {
	a := testAgent()
	b := mac("02:00:00:00:00:0b")
	t0 := time.Now()
	p := a.peerFor(b, t0)

	a.queueProbe(p, probeKindPing, 64, t0)  // seq 1: answered
	a.queueProbe(p, probeKindPing, 64, t0)  // seq 2: lost
	a.queueProbe(p, probeKindMTU, 1500, t0) // seq 3: answered whole
	a.queueProbe(p, probeKindMTU, 1400, t0) // seq 4: answered truncated
	a.onReply(b, 1, reply{Kind: probeKindPing, RxLen: 64}, t0.Add(3*time.Millisecond))
	a.onReply(b, 3, reply{Kind: probeKindMTU, RxLen: 1500}, t0.Add(5*time.Millisecond))
	a.onReply(b, 4, reply{Kind: probeKindMTU, RxLen: 1000}, t0.Add(5*time.Millisecond))
	a.onReply(mac("02:00:00:00:00:0c"), 2, reply{}, t0) // wrong sender: ignored
	a.expire(t0.Add(2 * time.Second))
	late := t0.Add(2 * time.Second)
	a.onReply(b, 2, reply{Kind: probeKindPing, RxLen: 64}, late) // too late: ignored

	s := p.ucast.stats()
	if s.samples != 2 || s.lost != 1 || s.avgRTT != 3*time.Millisecond {
		t.Fatalf("ucast = %+v", s)
	}
	if got := a.pathMTU(p, late); got != 1500 {
		t.Fatalf("pathMTU = %d, want 1500", got)
	}
	if len(a.pending) != 0 {
		t.Fatalf("%d probes still pending", len(a.pending))
	}
}

func TestMatrixUsesPeerReports(t *testing.T) {
	a := testAgent()
	b, c := mac("02:00:00:00:00:0b"), mac("02:00:00:00:00:0c")
	now := time.Now()
	a.onHello(b, 1, hello{Name: "bob", IfaceMTU: 1500, Entries: []reportEntry{
		{MAC: a.self, RTTMicros: 2000, ULossPermille: 0, BLossPermille: 0, MTU: 1500, Flags: flagHeardHello},
		{MAC: c, RTTMicros: unknownRTT, ULossPermille: 1000, BLossPermille: unknownLoss},
	}}, now)
	p := a.peers[b]
	p.ucast.add(true, 4*time.Millisecond)

	v := a.snapshot(now)
	if len(v.nodes) != 3 || v.nodes[0].mac != a.self || v.nodes[1].name != "bob" {
		t.Fatalf("nodes = %+v", v.nodes)
	}
	if got := formatCell(v.cells[[2]macKey{a.self, b}]); got != "4.00ms u0% b0% ?" {
		t.Errorf("self->bob = %q", got)
	}
	if got := formatCell(v.cells[[2]macKey{b, a.self}]); got != "2.00ms u0% b0% 1500" {
		t.Errorf("bob->self = %q", got)
	}
	if got := formatCell(v.cells[[2]macKey{b, c}]); got != "DOWN u100% b- ?" {
		t.Errorf("bob->c = %q", got)
	}
	// c was reported dead, so we must not have started probing it.
	if _, ok := a.peers[c]; ok {
		t.Errorf("dead node from report became a peer")
	}

	var out bytes.Buffer
	render(&out, v, false)
	for _, want := range []string{"[0] self", "[1] bob", "4.00ms u0% b0% ?", "local view:"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("render output lacks %q:\n%s", want, out.String())
		}
	}
	if code := v.exitCode(); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestSniffObserve(t *testing.T) {
	s := &sniffer{self: mac("02:00:00:00:00:00"), sources: make(map[macKey]*source)}
	other := mac("02:00:00:00:00:0b")
	arp := make([]byte, 14+28)
	copy(arp[0:6], broadcastMAC)
	copy(arp[6:12], other[:])
	arp[12], arp[13] = 0x08, 0x06
	copy(arp[14:], []byte{0, 1, 8, 0, 6, 4, 0, 1})
	copy(arp[14+14:], []byte{192, 168, 1, 7})
	s.observe(arp, time.Now())

	ownFrame := slices.Clone(arp)
	copy(ownFrame[6:12], s.self[:])
	s.observe(ownFrame, time.Now())

	if len(s.sources) != 1 {
		t.Fatalf("sources = %d, want 1 (own frames excluded)", len(s.sources))
	}
	src := s.sources[other]
	if src.toBcast != 1 || src.etherTypes[0x0806] != 1 || !src.ips[netip.MustParseAddr("192.168.1.7")] {
		t.Fatalf("source = %+v", src)
	}
}
