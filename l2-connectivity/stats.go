package main

import "time"

// ring keeps the outcome of the last N events (a probe answered or lost, a
// HELLO received or missed) so loss and RTT describe recent behaviour rather
// than the whole run.
type ring struct {
	ok   []bool
	rtt  []time.Duration
	next int
	n    int
}

func newRing(size int) *ring {
	return &ring{ok: make([]bool, size), rtt: make([]time.Duration, size)}
}

func (r *ring) add(ok bool, rtt time.Duration) {
	r.ok[r.next] = ok
	r.rtt[r.next] = rtt
	r.next = (r.next + 1) % len(r.ok)
	if r.n < len(r.ok) {
		r.n++
	}
}

func (r *ring) reset() { r.next, r.n = 0, 0 }

type ringStats struct {
	samples, lost  int
	minRTT, avgRTT time.Duration
	maxRTT         time.Duration
	answered       int
}

func (r *ring) stats() ringStats {
	var s ringStats
	var sum time.Duration
	for i := 0; i < r.n; i++ {
		s.samples++
		if !r.ok[i] {
			s.lost++
			continue
		}
		d := r.rtt[i]
		if s.answered == 0 || d < s.minRTT {
			s.minRTT = d
		}
		if d > s.maxRTT {
			s.maxRTT = d
		}
		sum += d
		s.answered++
	}
	if s.answered > 0 {
		s.avgRTT = sum / time.Duration(s.answered)
	}
	return s
}

// lossPermille returns loss in 1/1000 units, or unknownLoss without samples.
func (s ringStats) lossPermille() uint16 {
	if s.samples == 0 {
		return unknownLoss
	}
	return uint16(s.lost * 1000 / s.samples)
}
