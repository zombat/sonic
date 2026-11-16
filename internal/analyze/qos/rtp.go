// Package qos tracks per-stream RTP sequencing, clock-rate estimation,
// and RFC 3550 interarrival jitter calculation.
package qos

import (
	"math"

	"github.com/zombat/sonic/internal/model"
)

const (
	maxRTPStreams = 2000
	minRTPPackets = 10
)

var (
	staticClock = map[int]int{
		0: 8000, 3: 8000, 4: 8000, 8: 8000, 9: 8000, 13: 8000, 18: 8000,
	}
	clockChoices = []int{8000, 16000, 32000, 44100, 48000, 90000}
	audioPT      = map[int]bool{
		0: true, 3: true, 4: true, 8: true, 9: true, 13: true, 18: true,
	}
)

type rtpKey struct {
	src   string
	sport int
	dst   string
	dport int
	ssrc  uint32
}

type tsSample struct {
	t  float64
	ts uint32
}

type rtpStream struct {
	key         rtpKey
	ssrc        uint32
	pt          int
	firstT      float64
	lastT       float64
	packets     int
	bytes       int
	hasFirstSeq bool
	firstSeq    uint16
	lastSeq     uint16
	maxExt      int
	cycles      int
	recent      map[int]bool
	dups        int
	ooo         int
	ones        int
	deltas      int
	warmup      []tsSample
	clock       int
	clockSource string
	jitter      float64
	maxJitter   float64
	jitterSum   float64
	jitterN     int
	hasPrev     bool
	prevT       float64
	prevTS      uint32
	dscp        map[int]int
	frames      []int
	tunneled    bool
}

func newRTPStream(key rtpKey, pt int, t float64, tunneled bool) *rtpStream {
	clk := staticClock[pt]
	src := ""
	if clk != 0 {
		src = "static"
	}
	return &rtpStream{
		key:         key,
		ssrc:        key.ssrc,
		pt:          pt,
		firstT:      t,
		lastT:       t,
		recent:      make(map[int]bool),
		clock:       clk,
		clockSource: src,
		dscp:        make(map[int]int),
		frames:      []int{},
		tunneled:    tunneled,
	}
}

func (s *rtpStream) add(t float64, n int, seq uint16, ts uint32, dscp, size int) {
	s.packets++
	s.bytes += size
	s.lastT = t
	s.dscp[dscp]++
	model.AddFrame(&s.frames, n)

	if !s.hasFirstSeq {
		s.hasFirstSeq = true
		s.firstSeq = seq
		s.lastSeq = seq
		s.maxExt = int(seq)
	} else {
		delta := (int(seq) - int(s.lastSeq)) & 0xFFFF
		s.deltas++
		if delta == 1 {
			s.ones++
		}
		ext := s.cycles + int(seq)
		if int(seq) < (s.maxExt&0xFFFF) && (s.maxExt&0xFFFF)-int(seq) > 0x8000 {
			s.cycles += 0x10000
			ext = s.cycles + int(seq)
		}
		if s.recent[ext] {
			s.dups++
			s.lastSeq = seq
			return
		}
		if ext < s.maxExt {
			s.ooo++
		}
		if ext > s.maxExt {
			s.maxExt = ext
		}
		s.lastSeq = seq
	}

	s.recent[s.cycles+int(seq)] = true
	if len(s.recent) > 1024 {
		for k := range s.recent {
			if k <= s.maxExt-512 {
				delete(s.recent, k)
			}
		}
	}

	if s.clock == 0 {
		s.warmup = append(s.warmup, tsSample{t: t, ts: ts})
		if len(s.warmup) >= 20 {
			first, last := s.warmup[0], s.warmup[len(s.warmup)-1]
			rate := 8000.0
			if last.t > first.t {
				rate = float64(last.ts-first.ts) / (last.t - first.t)
			}
			bestClk := clockChoices[0]
			bestDiff := math.Abs(float64(bestClk) - rate)
			for _, cand := range clockChoices[1:] {
				diff := math.Abs(float64(cand) - rate)
				if diff < bestDiff {
					bestDiff = diff
					bestClk = cand
				}
			}
			s.clock = bestClk
			s.clockSource = "estimated"
			pending := s.warmup
			s.warmup = nil
			for _, w := range pending {
				s.recordJitter(w.t, w.ts)
			}
		}
		return
	}
	s.recordJitter(t, ts)
}

func (s *rtpStream) recordJitter(t float64, ts uint32) {
	if s.hasPrev {
		tsDiff := int64(int32(ts - s.prevTS))
		d := (t - s.prevT) - float64(tsDiff)/float64(s.clock)
		s.jitter += (math.Abs(d) - s.jitter) / 16.0
		if s.jitter > s.maxJitter {
			s.maxJitter = s.jitter
		}
		s.jitterSum += s.jitter
		s.jitterN++
	}
	s.hasPrev = true
	s.prevT = t
	s.prevTS = ts
}

func (s *rtpStream) finish() {
	if s.clock == 0 && len(s.warmup) > 0 {
		s.clock = 8000
		s.clockSource = "assumed"
		pending := s.warmup
		s.warmup = nil
		for _, w := range pending {
			s.recordJitter(w.t, w.ts)
		}
	}
}

func (s *rtpStream) looksLikeRTP() bool {
	return s.packets >= minRTPPackets && s.deltas > 0 && float64(s.ones)/float64(s.deltas) >= 0.5
}
