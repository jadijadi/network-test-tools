package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire format. Every message is carried directly in an Ethernet frame with
// our EtherType (default 0x88B5, IEEE "local experimental"), no IP involved.
//
//	0      4    5    6        8        12
//	+------+----+----+--------+--------+---------- ... ----+
//	| L2CT | v  | ty | length |  seq   |  type specific body |
//	+------+----+----+--------+--------+---------- ... ----+
//
// length is the full message length including the header. Short frames get
// padded to the 46 byte Ethernet minimum on the wire, so the receiver must
// rely on it instead of the frame size.

const (
	defaultEtherType = 0x88B5
	protoVersion     = 1
	headerLen        = 12

	msgHello = 1 // broadcast: who I am + what I see
	msgProbe = 2 // unicast: please echo
	msgReply = 3 // unicast: echo of a probe

	probeKindPing = 0 // small probe, feeds RTT and loss
	probeKindMTU  = 1 // large probe, feeds path MTU

	helloFixedLen  = 1 + 2 + 2 // nameLen + ifaceMTU + entry count (name excluded)
	reportEntryLen = 6 + 4 + 2 + 2 + 2 + 1
	probeBodyLen   = 1
	replyBodyLen   = 1 + 2
	minProbeSize   = headerLen + probeBodyLen
	maxNameLen     = 64

	unknownRTT  = 0xFFFFFFFF
	unknownLoss = 0xFFFF

	flagHeardHello = 1 << 0 // reporter heard the target's HELLOs recently
)

var magic = [4]byte{'L', '2', 'C', 'T'}

var errNotOurs = errors.New("not an l2-connectivity message")

type header struct {
	Type   uint8
	Length uint16
	Seq    uint32
}

// reportEntry is one line of a node's view of a peer, shipped inside HELLO so
// every node can draw the full matrix.
type reportEntry struct {
	MAC           [6]byte
	RTTMicros     uint32 // average RTT of ping probes, unknownRTT if none answered
	ULossPermille uint16 // unicast probe loss, unknownLoss if no samples
	BLossPermille uint16 // HELLO (broadcast) loss from that peer, unknownLoss if none heard
	MTU           uint16 // largest acknowledged probe size, 0 if unknown
	Flags         uint8
}

type hello struct {
	Name     string
	IfaceMTU uint16
	Entries  []reportEntry
}

type reply struct {
	Kind  uint8
	RxLen uint16 // size of the probe as received, lets the prober verify it arrived whole
}

func putHeader(b []byte, typ uint8, seq uint32) {
	copy(b[0:4], magic[:])
	b[4] = protoVersion
	b[5] = typ
	binary.BigEndian.PutUint16(b[6:8], uint16(len(b)))
	binary.BigEndian.PutUint32(b[8:12], seq)
}

// decode validates the header and returns the body with padding stripped.
func decode(b []byte) (header, []byte, error) {
	var h header
	if len(b) < headerLen || [4]byte(b[0:4]) != magic {
		return h, nil, errNotOurs
	}
	if b[4] != protoVersion {
		return h, nil, fmt.Errorf("unsupported protocol version %d", b[4])
	}
	h.Type = b[5]
	h.Length = binary.BigEndian.Uint16(b[6:8])
	h.Seq = binary.BigEndian.Uint32(b[8:12])
	if int(h.Length) < headerLen || int(h.Length) > len(b) {
		return h, nil, fmt.Errorf("bad length %d (frame has %d bytes)", h.Length, len(b))
	}
	return h, b[headerLen:h.Length], nil
}

// encodeHello builds a HELLO no larger than maxLen, dropping report entries
// that do not fit.
func encodeHello(seq uint32, m hello, maxLen int) []byte {
	name := m.Name
	if len(name) > maxNameLen {
		name = name[:maxNameLen]
	}
	fixed := headerLen + helloFixedLen + len(name)
	entries := m.Entries
	if room := (maxLen - fixed) / reportEntryLen; len(entries) > room {
		entries = entries[:max(room, 0)]
	}
	b := make([]byte, fixed+len(entries)*reportEntryLen)
	p := b[headerLen:]
	p[0] = uint8(len(name))
	p = p[1:]
	copy(p, name)
	p = p[len(name):]
	binary.BigEndian.PutUint16(p[0:2], m.IfaceMTU)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(entries)))
	p = p[4:]
	for _, e := range entries {
		copy(p[0:6], e.MAC[:])
		binary.BigEndian.PutUint32(p[6:10], e.RTTMicros)
		binary.BigEndian.PutUint16(p[10:12], e.ULossPermille)
		binary.BigEndian.PutUint16(p[12:14], e.BLossPermille)
		binary.BigEndian.PutUint16(p[14:16], e.MTU)
		p[16] = e.Flags
		p = p[reportEntryLen:]
	}
	putHeader(b, msgHello, seq)
	return b
}

func parseHello(body []byte) (hello, error) {
	var m hello
	if len(body) < 1 {
		return m, errors.New("short hello")
	}
	nameLen := int(body[0])
	body = body[1:]
	if len(body) < nameLen+4 {
		return m, errors.New("short hello")
	}
	m.Name = string(body[:nameLen])
	body = body[nameLen:]
	m.IfaceMTU = binary.BigEndian.Uint16(body[0:2])
	n := int(binary.BigEndian.Uint16(body[2:4]))
	body = body[4:]
	if len(body) < n*reportEntryLen {
		return m, fmt.Errorf("hello claims %d entries but has room for %d", n, len(body)/reportEntryLen)
	}
	m.Entries = make([]reportEntry, n)
	for i := range m.Entries {
		e := &m.Entries[i]
		copy(e.MAC[:], body[0:6])
		e.RTTMicros = binary.BigEndian.Uint32(body[6:10])
		e.ULossPermille = binary.BigEndian.Uint16(body[10:12])
		e.BLossPermille = binary.BigEndian.Uint16(body[12:14])
		e.MTU = binary.BigEndian.Uint16(body[14:16])
		e.Flags = body[16]
		body = body[reportEntryLen:]
	}
	return m, nil
}

// encodeProbe builds a probe of exactly size bytes (the Ethernet payload size).
func encodeProbe(seq uint32, kind uint8, size int) []byte {
	b := make([]byte, max(size, minProbeSize))
	b[headerLen] = kind
	// Fill with a non-zero pattern so compression or zero-stripping on the
	// path cannot make a large probe look smaller than it is.
	for i := headerLen + probeBodyLen; i < len(b); i++ {
		b[i] = byte(i)
	}
	putHeader(b, msgProbe, seq)
	return b
}

func parseProbeKind(body []byte) (uint8, error) {
	if len(body) < probeBodyLen {
		return 0, errors.New("short probe")
	}
	return body[0], nil
}

func encodeReply(seq uint32, r reply) []byte {
	b := make([]byte, headerLen+replyBodyLen)
	b[headerLen] = r.Kind
	binary.BigEndian.PutUint16(b[headerLen+1:], r.RxLen)
	putHeader(b, msgReply, seq)
	return b
}

func parseReply(body []byte) (reply, error) {
	if len(body) < replyBodyLen {
		return reply{}, errors.New("short reply")
	}
	return reply{Kind: body[0], RxLen: binary.BigEndian.Uint16(body[1:3])}, nil
}
