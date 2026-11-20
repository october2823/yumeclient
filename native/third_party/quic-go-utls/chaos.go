package quic

import (
	"math/rand/v2"

	"github.com/bogdanfinn/quic-go-utls/internal/ackhandler"
	"github.com/bogdanfinn/quic-go-utls/internal/protocol"
	"github.com/bogdanfinn/quic-go-utls/internal/wire"
)

// Chromium's "chaos protection" of the first flight: the ClientHello goes out in
// CRYPTO frames of random sizes and order, mixed with PING frames and runs of
// PADDING. The layout is planned once the whole ClientHello is known.

// chaosReserve is the room a scrambled packet keeps for extra CRYPTO frame headers
// and PING frames.
const chaosReserve = 80

type chaosRange struct{ start, end protocol.ByteCount }

type chaosPacket struct {
	ranges   []chaosRange
	scramble bool
}

// setChaos makes the stream hold back the ClientHello until it is complete, and
// leaves its layout to the packer.
func (s *initialCryptoStream) setChaos() {
	s.chaos = true
	s.scramble = false
}

// helloComplete says whether the whole first handshake message is buffered.
func helloComplete(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	return len(b) >= 4+n
}

func (s *initialCryptoStream) chaosPending() bool {
	if !s.chaos {
		return false
	}
	if !s.chaosPlanned {
		return s.writeOffset == 0 && helloComplete(s.writeBuf)
	}
	return len(s.chaosPlan) > 0
}

// chaosPadding is a run of PADDING frames.
type chaosPadding struct{ n protocol.ByteCount }

func (f *chaosPadding) Append(b []byte, _ protocol.Version) ([]byte, error) {
	return append(b, make([]byte, f.n)...), nil
}

func (f *chaosPadding) Length(protocol.Version) protocol.ByteCount { return f.n }

// planChaos lays the ClientHello of length l out over packets with room bytes of
// frames each.
func planChaos(mode ChaosMode, l, room protocol.ByteCount, r *rand.Rand) []chaosPacket {
	if mode != ChaosOff && l+chaosReserve <= room {
		return []chaosPacket{{ranges: []chaosRange{{0, l}}, scramble: true}}
	}
	inOrder := func(from protocol.ByteCount, scrambleLast bool) []chaosPacket {
		var out []chaosPacket
		for from < l {
			f := &wire.CryptoFrame{Offset: from}
			n := min(f.MaxDataLen(room), l-from)
			last := from+n == l
			if last && scrambleLast && n+chaosReserve > room {
				// the last packet needs room to scramble: leave part of it for one more
				n = max(n-chaosReserve, 1)
				last = false
			}
			out = append(out, chaosPacket{ranges: []chaosRange{{from, from + n}}, scramble: last && scrambleLast})
			from += n
		}
		return out
	}
	switch mode {
	case ChaosSNISlice:
		return nil // planned by planSNISlice
	case ChaosLastPacket:
		return inOrder(0, true)
	case ChaosMultiPacket:
		usable := room - chaosReserve
		if l <= 2*usable {
			// the second packet carries the middle, the first one both ends
			second := min((l+1)/2+2, usable)
			rest := l - second
			x := protocol.ByteCount(1)
			if rest > 1 {
				x += protocol.ByteCount(r.IntN(int(min(rest, 80))))
			}
			first := []chaosRange{{0, x}}
			if x+second < l {
				first = append(first, chaosRange{x + second, l})
			}
			return []chaosPacket{
				{ranges: first, scramble: true},
				{ranges: []chaosRange{{x, x + second}}, scramble: true},
			}
		}
		var out []chaosPacket
		for from := protocol.ByteCount(0); from < l; from += usable {
			out = append(out, chaosPacket{ranges: []chaosRange{{from, min(from+usable, l)}}, scramble: true})
		}
		return out
	default:
		return inOrder(0, false)
	}
}

// chaosFrames returns the frames of the next packet of the planned first flight.
func (p *packetPacker) chaosFrames(room protocol.ByteCount, v protocol.Version) []wire.Frame {
	s := p.initialStream
	if !s.chaosPlanned {
		l := 4 + (protocol.ByteCount(s.writeBuf[1])<<16 | protocol.ByteCount(s.writeBuf[2])<<8 | protocol.ByteCount(s.writeBuf[3]))
		s.chaosHello = s.writeBuf[:l:l]
		s.writeBuf = s.writeBuf[l:]
		s.writeOffset = l
		if p.chaos == ChaosSNISlice {
			s.chaosPlan = planSNISlice(s.chaosHello, room)
		} else {
			s.chaosPlan = planChaos(p.chaos, l, room, &p.rand)
		}
		s.chaosPlanned = true
	}
	if len(s.chaosPlan) == 0 {
		return nil
	}
	pkt := s.chaosPlan[0]
	s.chaosPlan = s.chaosPlan[1:]
	var frames []*wire.CryptoFrame
	for _, r := range pkt.ranges {
		frames = append(frames, &wire.CryptoFrame{Offset: r.start, Data: s.chaosHello[r.start:r.end]})
	}
	if !pkt.scramble {
		out := make([]wire.Frame, len(frames))
		for i, f := range frames {
			out[i] = f
		}
		return out
	}
	return scramble(frames, room, v, &p.rand)
}

func scramble(crypto []*wire.CryptoFrame, room protocol.ByteCount, v protocol.Version, r *rand.Rand) []wire.Frame {
	var used protocol.ByteCount
	for _, f := range crypto {
		used += f.Length(v)
	}
	left := room - min(room, used)
	// split CRYPTO frames at random points
	for range r.IntN(11) {
		var candidates []int
		for i, f := range crypto {
			if len(f.Data) >= 2 {
				candidates = append(candidates, i)
			}
		}
		if len(candidates) == 0 {
			break
		}
		i := candidates[r.IntN(len(candidates))]
		f := crypto[i]
		cut := 1 + r.IntN(len(f.Data)-1)
		a := &wire.CryptoFrame{Offset: f.Offset, Data: f.Data[:cut]}
		b := &wire.CryptoFrame{Offset: f.Offset + protocol.ByteCount(cut), Data: f.Data[cut:]}
		extra := a.Length(v) + b.Length(v) - f.Length(v)
		if extra > left {
			break
		}
		left -= extra
		crypto = append(crypto[:i], append([]*wire.CryptoFrame{a, b}, crypto[i+1:]...)...)
	}
	frames := make([]wire.Frame, 0, len(crypto)+12)
	for _, f := range crypto {
		frames = append(frames, f)
	}
	pings := min(protocol.ByteCount(r.IntN(11)), left)
	for range pings {
		frames = append(frames, &wire.PingFrame{})
	}
	left -= pings
	r.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })
	if left == 0 {
		return frames
	}
	// spread the remaining room over runs of PADDING between the frames
	runs := 1 + r.IntN(min(len(frames)+1, 8))
	sizes := make([]protocol.ByteCount, runs)
	for i := range sizes {
		sizes[i] = 1
	}
	for rest := left - protocol.ByteCount(runs); rest > 0; {
		if rest < protocol.ByteCount(runs) || runs == 1 {
			sizes[r.IntN(runs)] += rest
			break
		}
		n := protocol.ByteCount(r.IntN(int(rest)) + 1)
		sizes[r.IntN(runs)] += n
		rest -= n
	}
	if protocol.ByteCount(runs) > left { // not even one byte per run
		runs = int(left)
		sizes = sizes[:runs]
		for i := range sizes {
			sizes[i] = 1
		}
	}
	gaps := r.Perm(len(frames) + 1)[:runs]
	at := make(map[int]protocol.ByteCount, runs)
	for i, g := range gaps {
		at[g] = sizes[i]
	}
	out := make([]wire.Frame, 0, len(frames)+runs)
	for i := 0; i <= len(frames); i++ {
		if n, ok := at[i]; ok {
			out = append(out, &chaosPadding{n: n})
		}
		if i < len(frames) {
			out = append(out, frames[i])
		}
	}
	return out
}

// chaosHandler: PINGs and PADDING are not retransmitted.
var _ ackhandler.FrameHandler = emptyHandler{}

// planSNISlice follows neqo's SNI slicing: the ClientHello is cut at the middle of
// the SNI, the part after the cut goes first, and the chunks are trimmed so the
// packets carry about the same amount of data.
func planSNISlice(hello []byte, room protocol.ByteCount) []chaosPacket {
	l := protocol.ByteCount(len(hello))
	sniPos, sniLen, _, err := findSNIAndECH(hello)
	if err != nil || sniPos <= 0 {
		return planChaos(ChaosOff, l, room, nil)
	}
	mid := protocol.ByteCount(sniPos + sniLen/2)
	usable := room - 10 // two CRYPTO frame headers
	packets := (l + usable - 1) / usable
	limit := l / packets
	left, right := mid, l-mid
	var first []chaosRange
	var rest []chaosRange
	switch {
	case left+right <= limit:
		first = []chaosRange{{mid, l}, {0, mid}}
	case left <= limit:
		rightLen := right + left - limit
		first = []chaosRange{{mid + rightLen, l}, {0, mid}}
		rest = []chaosRange{{mid, mid + rightLen}}
	case right <= limit:
		first = []chaosRange{{mid, l}, {0, limit - right}}
		rest = []chaosRange{{limit - right, mid}}
	default:
		first = []chaosRange{{mid, mid + limit/2}, {0, limit / 2}}
		rest = []chaosRange{{limit / 2, mid}, {mid + limit/2, l}}
	}
	out := []chaosPacket{{ranges: first}}
	for _, r := range rest {
		for from := r.start; from < r.end; {
			f := &wire.CryptoFrame{Offset: from}
			n := min(f.MaxDataLen(room), r.end-from)
			out = append(out, chaosPacket{ranges: []chaosRange{{from, from + n}}})
			from += n
		}
	}
	return out
}
