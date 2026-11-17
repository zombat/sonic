// Package convergence Detector state, ESP gap analysis, and packet rate calculation.
package convergence

import (
	"cmp"
	"slices"

	"github.com/zombat/sonic/internal/analyze/ipsec"
	"github.com/zombat/sonic/internal/analyze/reach"
	"github.com/zombat/sonic/internal/analyze/routing"
	"github.com/zombat/sonic/internal/model"
)

// espGap records one inter-packet gap >= gapRecordS on a directional protected tunnel.
type espGap struct {
	lastT float64
	lastN int
	nextT float64
	nextN int
}

// espDirection tracks gap samples and 1-second packet buckets for one (src, dst) protected flow.
type espDirection struct {
	firstT  float64
	firstN  int
	lastT   float64
	lastN   int
	gaps    []espGap
	buckets map[int]int
	count   int
	sample  []float64
}

// newEspDirection initializes espDirection at the first observed packet (matching Python's count=1 seed).
func newEspDirection(t float64, n int) *espDirection {
	buckets := map[int]int{int(t): 1}
	return &espDirection{
		firstT:  t,
		firstN:  n,
		lastT:   t,
		lastN:   n,
		buckets: buckets,
		count:   1,
	}
}

// feed appends one timestamp/frame sample to espDirection, capping gap and sample buffers.
func (d *espDirection) feed(t float64, n int) {
	gap := t - d.lastT
	if gap >= gapRecordS && len(d.gaps) < 20000 {
		d.gaps = append(d.gaps, espGap{lastT: d.lastT, lastN: d.lastN, nextT: t, nextN: n})
	}
	if d.count > 0 && len(d.sample) < 2000 {
		d.sample = append(d.sample, gap)
	}
	d.lastT = t
	d.lastN = n
	d.buckets[int(t)]++
	d.count++
}

// espStop records one period of protected-traffic silence on (src, dst).
type espStop struct {
	src          string
	dst          string
	lastT        float64
	lastFrame    int
	resumedT     *float64
	resumedFrame *int
	silenceS     float64
	oneSided     bool
}

// Detector correlates IPsec, routing, ICMP reachability, and ESP rate dynamics into a failover timeline.
type Detector struct {
	eventTimeRaw string
	failedPeer   string
	holdTime     *float64
	silenceGiven bool
	silenceS     float64

	ipsec   *ipsec.Detector
	routing *routing.Detector
	reach   *reach.ReachabilityDetector

	espOrder [][2]string
	esp      map[[2]string]*espDirection
	hasStart bool
	start    float64
	hasEnd   bool
	end      float64
}

// NewDetector constructs a ConvergenceDetector with the supplied correlation options.
func NewDetector(opts Options) *Detector {
	silence := defaultSilence
	if opts.SilenceS != nil && *opts.SilenceS != 0 {
		silence = *opts.SilenceS
	}
	return &Detector{
		eventTimeRaw: opts.EventTime,
		failedPeer:   opts.FailedPeer,
		holdTime:     opts.HoldTime,
		silenceGiven: opts.SilenceS != nil,
		silenceS:     silence,
		ipsec:        ipsec.NewDetector(nil),
		routing:      routing.NewDetector(nil),
		reach:        reach.NewReachabilityDetector(),
		esp:          make(map[[2]string]*espDirection),
	}
}

// Name returns the registry identifier "convergence".
func (d *Detector) Name() string { return "convergence" }

// Present reports whether ESP/IKE protected traffic, routing, ICMP reachability, or IKE SAs were seen.
func (d *Detector) Present() bool {
	return len(d.esp) > 0 || d.routing.Present() || d.reach.Present() || d.ipsec.Present()
}

// Feed ingests one normalized packet record into sub-detectors and ESP rate buckets.
func (d *Detector) Feed(rec *model.Record) {
	if rec == nil {
		return
	}
	if rec.T != 0 {
		if !d.hasStart || rec.T < d.start {
			d.start = rec.T
			d.hasStart = true
		}
		if !d.hasEnd || rec.T > d.end {
			d.end = rec.T
			d.hasEnd = true
		}
	}
	d.ipsec.Feed(rec)
	d.routing.Feed(rec)
	d.reach.Feed(rec)

	if rec.IP != nil && (rec.ESP != nil || rec.IKE != nil || (rec.NATKeepalive != nil && *rec.NATKeepalive)) {
		key := [2]string{rec.IP.Src, rec.IP.Dst}
		dir, ok := d.esp[key]
		if !ok {
			d.esp[key] = newEspDirection(rec.T, rec.N)
			d.espOrder = append(d.espOrder, key)
		} else {
			dir.feed(rec.T, rec.N)
		}
	}
}

// threshold returns the silence duration in seconds that qualifies as a stop on direction dir.
func (d *Detector) threshold(dir *espDirection, livenessInterval *float64) float64 {
	if d.silenceGiven {
		return d.silenceS
	}
	limit := d.silenceS
	if len(dir.sample) >= 5 {
		ordered := slices.Clone(dir.sample)
		slices.Sort(ordered)
		idx := min(len(ordered)-1, int(0.95*float64(len(ordered))))
		limit = max(limit, 2.0*ordered[idx])
	}
	if livenessInterval != nil && *livenessInterval != 0 {
		limit = max(limit, 1.5*(*livenessInterval))
	}
	return limit
}

// stops collects every protected-traffic gap >= threshold and trailing silence until capture end.
func (d *Detector) stops(liveness map[[2]string]float64) []espStop {
	var out []espStop
	for _, key := range d.espOrder {
		dir := d.esp[key]
		src, dst := key[0], key[1]
		var livPtr *float64
		if liv, ok := liveness[model.PairKey(src, dst)]; ok {
			v := liv
			livPtr = &v
		}
		limit := d.threshold(dir, livPtr)
		for _, g := range dir.gaps {
			if g.nextT-g.lastT >= limit {
				nt := g.nextT
				nf := g.nextN
				out = append(out, espStop{
					src:          src,
					dst:          dst,
					lastT:        g.lastT,
					lastFrame:    g.lastN,
					resumedT:     &nt,
					resumedFrame: &nf,
					silenceS:     model.Round(g.nextT-g.lastT, 3),
				})
			}
		}
		if d.hasEnd && d.end-dir.lastT >= limit {
			out = append(out, espStop{
				src:       src,
				dst:       dst,
				lastT:     dir.lastT,
				lastFrame: dir.lastN,
				silenceS:  model.Round(d.end-dir.lastT, 3),
			})
		}
	}
	slices.SortStableFunc(out, func(a, b espStop) int {
		return cmp.Compare(a.lastT, b.lastT)
	})
	return out
}

// oneSided reports whether the reverse direction kept sending during stop's silent window.
func (d *Detector) oneSided(stop espStop) bool {
	reverse, ok := d.esp[[2]string{stop.dst, stop.src}]
	if !ok {
		return false
	}
	windowStart := stop.lastT + 1.0
	endT := stop.lastT
	if stop.resumedT != nil {
		endT = *stop.resumedT
	} else if d.hasEnd {
		endT = d.end
	}
	windowEnd := endT - 0.5
	if windowEnd <= windowStart {
		return false
	}
	if reverse.lastT <= windowStart || reverse.firstT >= windowEnd {
		return false
	}
	for _, g := range reverse.gaps {
		if g.lastT <= windowStart && g.nextT >= windowEnd {
			return false
		}
	}
	return true
}

// rate computes the average packets/s across pairs over integer seconds [start, end).
func (d *Detector) rate(pairs [][2]string, start, end int) float64 {
	if end <= start {
		return 0.0
	}
	total := 0
	for _, key := range pairs {
		dir, ok := d.esp[key]
		if !ok {
			continue
		}
		for sec := start; sec < end; sec++ {
			total += dir.buckets[sec]
		}
	}
	return float64(total) / float64(end-start)
}
