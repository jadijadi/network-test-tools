package main

import (
	"cmp"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

type node struct {
	mac  macKey
	name string
}

func (n node) label() string {
	if n.name != "" {
		return n.name
	}
	return n.mac.String()
}

type cell struct {
	entry reportEntry
	stale bool // taken from a HELLO that is older than expected
}

type peerDetail struct {
	node
	heard     bool
	helloSeen bool
	helloAge  time.Duration
	bcast     ringStats
	ucast     ringStats
	pathMTU   int
	ifaceMTU  int
	static    bool
}

// view is a consistent copy of the agent state, taken under the lock and
// rendered without it.
type view struct {
	at       time.Time
	iface    string
	ifaceMTU int
	nodes    []node // this node first
	cells    map[[2]macKey]cell
	details  []peerDetail
}

func (a *agent) snapshot(now time.Time) view {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := view{
		at:       now,
		iface:    a.cfg.iface,
		ifaceMTU: a.ifaceMTU,
		cells:    make(map[[2]macKey]cell),
	}
	self := node{mac: a.self, name: a.cfg.name}
	names := map[macKey]string{a.self: a.cfg.name}
	for _, p := range a.peers {
		if p.name != "" {
			names[p.mac] = p.name
		}
	}
	// Every MAC mentioned anywhere becomes a matrix node.
	seen := map[macKey]bool{a.self: true}
	var others []node
	addNode := func(m macKey) {
		if !seen[m] {
			seen[m] = true
			others = append(others, node{mac: m, name: names[m]})
		}
	}
	for _, p := range a.peers {
		addNode(p.mac)
		v.cells[[2]macKey{a.self, p.mac}] = cell{entry: a.localEntry(p, now)}
		v.details = append(v.details, peerDetail{
			node:      node{mac: p.mac, name: p.name},
			heard:     a.heardRecently(p, now),
			helloSeen: p.helloSeen,
			helloAge:  now.Sub(p.lastHello),
			bcast:     p.bcast.stats(),
			ucast:     p.ucast.stats(),
			pathMTU:   a.pathMTU(p, now),
			ifaceMTU:  p.ifaceMTU,
			static:    p.static,
		})
		stale := now.Sub(p.reportAt) > 3*a.cfg.helloEvery
		for _, e := range p.report {
			addNode(e.MAC)
			v.cells[[2]macKey{p.mac, e.MAC}] = cell{entry: e, stale: stale}
		}
	}
	// Named nodes first, then the ones only known by MAC from reports.
	byLabel := func(x, y node) int {
		return cmp.Or(compareBool(x.name == "", y.name == ""),
			cmp.Compare(x.label(), y.label()), cmp.Compare(x.mac.String(), y.mac.String()))
	}
	slices.SortFunc(others, byLabel)
	slices.SortFunc(v.details, func(x, y peerDetail) int { return byLabel(x.node, y.node) })
	v.nodes = append([]node{self}, others...)
	return v
}

func compareBool(x, y bool) int {
	switch {
	case x == y:
		return 0
	case !x:
		return -1
	default:
		return 1
	}
}

// exitCode: 0 all peers answer, 1 some peer never answers, 2 no peer found.
func (v view) exitCode() int {
	if len(v.details) == 0 {
		return 2
	}
	for _, d := range v.details {
		if d.ucast.samples == 0 || d.ucast.answered == 0 {
			return 1
		}
	}
	return 0
}

func fmtRTT(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	switch {
	case ms < 10:
		return fmt.Sprintf("%.2fms", ms)
	case ms < 100:
		return fmt.Sprintf("%.1fms", ms)
	case ms < 1000:
		return fmt.Sprintf("%.0fms", ms)
	default:
		return fmt.Sprintf("%.1fs", ms/1000)
	}
}

func fmtLoss(permille uint16) string {
	if permille == unknownLoss {
		return "?"
	}
	return fmt.Sprintf("%d%%", (int(permille)+5)/10)
}

func fmtMTU(mtu int) string {
	if mtu == 0 {
		return "?"
	}
	return fmt.Sprint(mtu)
}

// formatCell renders one observer->target measurement as
// "RTT u<unicast loss> b<broadcast loss> MTU".
func formatCell(c cell) string {
	e := c.entry
	rtt := "-"
	if e.RTTMicros != unknownRTT {
		rtt = fmtRTT(time.Duration(e.RTTMicros) * time.Microsecond)
	}
	if e.ULossPermille == 1000 {
		rtt = "DOWN"
	}
	b := "b" + fmtLoss(e.BLossPermille)
	if e.Flags&flagHeardHello == 0 {
		b = "b-"
	}
	s := fmt.Sprintf("%s u%s %s %s", rtt, fmtLoss(e.ULossPermille), b, fmtMTU(int(e.MTU)))
	if c.stale {
		s = "~" + s
	}
	return s
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func render(w io.Writer, v view, clear bool) {
	var sb strings.Builder
	if clear {
		sb.WriteString("\033[H\033[2J")
	}
	self := v.nodes[0]
	fmt.Fprintf(&sb, "l2-connectivity agent  %s  iface %s  mac %s  mtu %d\n\n",
		v.at.Format("2006-01-02 15:04:05"), v.iface, self.mac, v.ifaceMTU)

	// Matrix: row = observer, column = target.
	tw := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
	fmt.Fprint(tw, "from \\ to\t")
	for i := range v.nodes {
		fmt.Fprintf(tw, "[%d]\t", i)
	}
	fmt.Fprintln(tw)
	for i, from := range v.nodes {
		fmt.Fprintf(tw, "[%d] %s\t", i, truncate(from.label(), 16))
		for _, to := range v.nodes {
			switch c, ok := v.cells[[2]macKey{from.mac, to.mac}]; {
			case from.mac == to.mac:
				fmt.Fprint(tw, "·\t")
			case ok:
				fmt.Fprintf(tw, "%s\t", formatCell(c))
			default:
				fmt.Fprint(tw, ".\t")
			}
		}
		fmt.Fprintln(tw)
	}
	tw.Flush()
	sb.WriteString("\ncell: avg RTT, u=unicast probe loss, b=HELLO (broadcast) loss from target, path MTU\n")
	sb.WriteString("      DOWN=no probe answered  b-=target's HELLOs not heard  ~=observer's report is stale  .=no data\n")

	sb.WriteString("\nnodes:\n")
	tw = tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
	for i, n := range v.nodes {
		note := ""
		if i == 0 {
			note = "(this node)"
		}
		fmt.Fprintf(tw, "  [%d] %s\t%s\t%s\n", i, n.label(), n.mac, note)
	}
	tw.Flush()

	if len(v.details) > 0 {
		sb.WriteString("\nlocal view:\n")
		tw = tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  peer\thello age\tbcast loss\tprobes\tloss\trtt min/avg/max\tpath mtu\tpeer if mtu\t")
		for _, d := range v.details {
			age := "never"
			if d.helloSeen {
				age = d.helloAge.Truncate(100 * time.Millisecond).String()
			}
			rtt := "-"
			if d.ucast.answered > 0 {
				rtt = fmt.Sprintf("%s/%s/%s", fmtRTT(d.ucast.minRTT), fmtRTT(d.ucast.avgRTT), fmtRTT(d.ucast.maxRTT))
			}
			name := truncate(d.label(), 20)
			if d.static {
				name += " (static)"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t\n",
				name, age, fmtLoss(d.bcast.lossPermille()), d.ucast.samples,
				fmtLoss(d.ucast.lossPermille()), rtt, fmtMTU(d.pathMTU), fmtMTU(d.ifaceMTU))
		}
		tw.Flush()
	} else {
		sb.WriteString("\nno peers yet (is the agent running on another machine on the same segment?)\n")
	}
	io.WriteString(w, sb.String())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
