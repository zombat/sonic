// Package ipsec per-SPI ESP sequence tracking, stale SPI detection, and ESP reporting.
package ipsec

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

// espFlowKey identifies one directional ESP SA by (src, dst, spi).
type espFlowKey struct {
	src string
	dst string
	spi uint32
}

// dirKey identifies a directional IP pair.
type dirKey struct {
	src string
	dst string
}

// espFlow tracks packet counts, sliding sequence replay window, and stale usage for one SPI.
type espFlow struct {
	src           string
	dst           string
	spi           uint32
	udp           bool
	packets       int
	bytes         int
	hasTime       bool
	firstT        float64
	lastT         float64
	hasSeq        bool
	firstSeq      uint32
	maxSeq        uint32
	missing       int
	duplicates    int
	outOfOrder    int
	window        []uint32
	windowSet     map[uint32]bool
	frames        []int
	dupFrames     []int
	stale         int
	staleFrames   []int
	hasStaleSPI   bool
	staleAfter    uint32
	hasFirstStale bool
	firstStaleT   float64
}

// newESPFlow constructs an initialized espFlow.
func newESPFlow(src, dst string, spi uint32, udp bool) *espFlow {
	return &espFlow{
		src:         src,
		dst:         dst,
		spi:         spi,
		udp:         udp,
		windowSet:   make(map[uint32]bool),
		frames:      []int{},
		dupFrames:   []int{},
		staleFrames: []int{},
	}
}

// feed updates counters and sliding sequence window state for one ESP packet record.
func (f *espFlow) feed(rec *model.Record) {
	seq := rec.ESP.Seq
	f.packets++
	f.bytes += rec.Len
	if !f.hasTime {
		f.hasTime = true
		f.firstT = rec.T
	}
	f.lastT = rec.T
	model.AddFrame(&f.frames, rec.N)

	if !f.hasSeq {
		f.hasSeq = true
		f.firstSeq = seq
		f.maxSeq = seq
	} else if seq > f.maxSeq {
		f.missing += int(seq - f.maxSeq - 1)
		f.maxSeq = seq
	} else if f.windowSet[seq] {
		f.duplicates++
		model.AddFrame(&f.dupFrames, rec.N)
		return
	} else {
		f.outOfOrder++
		if f.missing > 0 {
			f.missing--
		}
	}

	f.window = append(f.window, seq)
	f.windowSet[seq] = true
	if len(f.window) > replayWindow {
		old := f.window[0]
		f.window = f.window[1:]
		delete(f.windowSet, old)
	}
}

// feedESPRecord routes an incoming ESP record to its flow and detects stale older SPIs.
func (d *Detector) feedESPRecord(rec *model.Record, src, dst string) {
	esp := rec.ESP
	fk := espFlowKey{src: src, dst: dst, spi: esp.SPI}
	dk := dirKey{src: src, dst: dst}
	flow, ok := d.esp[fk]
	current := d.espCurrent[dk]
	if !ok {
		flow = newESPFlow(src, dst, esp.SPI, esp.UDP)
		d.esp[fk] = flow
		d.espCurrent[dk] = flow
	} else if current != nil && flow != current && flow.hasTime && current.hasTime &&
		flow.firstT < current.firstT && rec.T-current.firstT > staleSPIGraceS {
		flow.stale++
		model.AddFrame(&flow.staleFrames, rec.N)
		flow.hasStaleSPI = true
		flow.staleAfter = current.spi
		if !flow.hasFirstStale {
			flow.hasFirstStale = true
			flow.firstStaleT = rec.T
		}
	}
	flow.feed(rec)
}

// reportESP emits per-flow ESP stats, duplicate/gap/stale-SPI issues, and SPI lifecycle events.
func (d *Detector) reportESP(ctx model.Context, issues *[]model.Issue, events *[]model.Event) []ESPFlowReport {
	flows := make([]*espFlow, 0, len(d.esp))
	for _, fl := range d.esp {
		flows = append(flows, fl)
	}
	slices.SortStableFunc(flows, func(a, b *espFlow) int {
		at, bt := 0.0, 0.0
		if a.hasTime {
			at = a.firstT
		}
		if b.hasTime {
			bt = b.firstT
		}
		if c := cmp.Compare(at, bt); c != 0 {
			return c
		}
		if c := cmp.Compare(a.src, b.src); c != 0 {
			return c
		}
		if c := cmp.Compare(a.dst, b.dst); c != 0 {
			return c
		}
		return cmp.Compare(a.spi, b.spi)
	})

	out := make([]ESPFlowReport, 0, len(flows))
	var dirOrder []dirKey
	byDir := make(map[dirKey][]*espFlow)

	for _, flow := range flows {
		dk := dirKey{src: flow.src, dst: flow.dst}
		if _, exists := byDir[dk]; !exists {
			dirOrder = append(dirOrder, dk)
		}
		byDir[dk] = append(byDir[dk], flow)
		spiStr := fmt.Sprintf("0x%08x", flow.spi)

		if flow.duplicates > 0 {
			iss := model.MakeIssue(
				model.SeverityWarning, "ESP_DUPLICATE_SEQUENCE",
				fmt.Sprintf("ESP SPI %s %s->%s: %d packet(s) repeated a sequence number already seen (possible replay, or the capture saw the same packet twice)",
					spiStr, flow.src, flow.dst, flow.duplicates),
				flow.dupFrames,
			)
			iss.SPI = spiStr
			*issues = append(*issues, iss)
		}
		if flow.missing > 0 {
			iss := model.MakeIssue(
				model.SeverityWarning, "ESP_SEQUENCE_GAP",
				fmt.Sprintf("ESP SPI %s %s->%s: %d sequence number(s) missing (loss before the capture point)",
					spiStr, flow.src, flow.dst, flow.missing),
				flow.frames,
			)
			iss.SPI = spiStr
			*issues = append(*issues, iss)
		}
		if flow.stale > 0 {
			newerStr := fmt.Sprintf("0x%08x", flow.staleAfter)
			iss := model.MakeIssue(
				model.SeverityWarning, "ESP_STALE_SPI",
				fmt.Sprintf("ESP SPI %s %s->%s was still used %d time(s) more than %s s after SPI %s took over that direction: the receiver may have deleted the old SA (an SPI mismatch after a rekey, answered with INVALID_SPI inside the encrypted IKE SA), or two child SAs are in use after an IKE SA collision",
					spiStr, flow.src, flow.dst, flow.stale, model.FormatPyFloat(staleSPIGraceS), newerStr),
				flow.staleFrames,
			)
			iss.SPI = spiStr
			iss.NewerSPI = newerStr
			*issues = append(*issues, iss)
			if flow.hasFirstStale {
				var fr *int
				if len(flow.staleFrames) > 0 {
					v := flow.staleFrames[0]
					fr = &v
				}
				*events = append(*events, model.MakeEvent(
					ctx, flow.firstStaleT, "esp", "stale_spi",
					fmt.Sprintf("%s->%s ESP on old SPI %s after %s took over", flow.src, flow.dst, spiStr, newerStr),
					fr,
				))
			}
		}

		var ft, lt *float64
		if flow.hasTime {
			ft = ctx.Rel(&flow.firstT)
			lt = ctx.Rel(&flow.lastT)
		}
		var fs, ls *uint32
		if flow.hasSeq {
			a, b := flow.firstSeq, flow.maxSeq
			fs, ls = &a, &b
		}
		out = append(out, ESPFlowReport{
			Src:                      flow.src,
			Dst:                      flow.dst,
			SPI:                      spiStr,
			UDPEncapsulated:          flow.udp,
			Packets:                  flow.packets,
			Bytes:                    flow.bytes,
			FirstT:                   ft,
			LastT:                    lt,
			FirstSeq:                 fs,
			LastSeq:                  ls,
			MissingSequenceNumbers:   flow.missing,
			DuplicateSequenceNumbers: flow.duplicates,
			OutOfOrder:               flow.outOfOrder,
			Frames:                   nonNilInts(flow.frames),
			StalePackets:             flow.stale,
			StaleFrames:              nonNilInts(flow.staleFrames),
		})
	}

	for _, dk := range dirOrder {
		group := byDir[dk]
		for i := 0; i+1 < len(group); i++ {
			oldF, newF := group[i], group[i+1]
			var fr *int
			if len(newF.frames) > 0 {
				v := newF.frames[0]
				fr = &v
			}
			*events = append(*events, model.MakeEvent(
				ctx, newF.firstT, "esp", "spi_change",
				fmt.Sprintf("%s->%s ESP SPI 0x%08x replaced by 0x%08x (rekey)", dk.src, dk.dst, oldF.spi, newF.spi),
				fr,
			))
		}
		if len(group) > 0 && group[0].hasTime {
			var fr *int
			if len(group[0].frames) > 0 {
				v := group[0].frames[0]
				fr = &v
			}
			*events = append(*events, model.MakeEvent(
				ctx, group[0].firstT, "esp", "esp_start",
				fmt.Sprintf("first ESP %s->%s (SPI 0x%08x)", dk.src, dk.dst, group[0].spi),
				fr,
			))
		}
	}

	for _, dk := range dirOrder {
		if _, hasRev := byDir[dirKey{src: dk.dst, dst: dk.src}]; !hasRev {
			group := byDir[dk]
			*issues = append(*issues, model.MakeIssue(
				model.SeverityWarning, "ESP_ONE_WAY",
				fmt.Sprintf("ESP flows %s->%s only; nothing returns from %s at this capture point (return path, SA mismatch, or asymmetric routing)",
					dk.src, dk.dst, dk.dst),
				group[0].frames,
			))
		}
	}
	return out
}
