// Package timeline merges detector event timelines across multiple captures and
// evaluates failover, outage, and protocol convergence timings.
package timeline

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sync"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/model"
)

// MergeTimelines runs network detectors across captures concurrently, aligns events onto a
// shared clock, and measures explicit or automatic failover/outage durations.
func MergeTimelines(ctx context.Context, captures []CaptureInput, opts Options) Report {
	labels, paths, absOutput, errRep := validateInputs(captures, opts)
	if errRep != nil {
		return *errRep
	}

	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = 500
	}

	falseVal := false
	reports := make([]netorch.NetworkReport, len(paths))
	sem := make(chan struct{}, min(4, len(paths)))
	var wg sync.WaitGroup
	for i, path := range paths {
		wg.Add(1)
		go func(idx int, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			reports[idx] = netorch.AnalyzeNetworkCapture(ctx, p, netorch.Options{
				Detectors:    opts.Detectors,
				IncludeSIP:   &falseVal,
				MaxItems:     1000,
				DetectorOpts: opts.DetectorOpts,
			})
		}(i, path)
	}
	wg.Wait()

	for i, rep := range reports {
		if rep.Status != "success" {
			return Report{
				Status:  "error",
				Error:   fmt.Sprintf("%s: %s", labels[i], rep.Error),
				Capture: labels[i],
			}
		}
	}

	events := make([]TimelineEvent, 0, len(paths)*32)
	perCapture := make([]CaptureSummary, 0, len(paths))
	for i, label := range labels {
		rep := reports[i]
		offset := opts.ClockOffsetsS[label]
		capCount := 0
		for _, ev := range rep.Timeline {
			ep, ok := parseEpoch(ev.Time)
			if !ok {
				continue
			}
			capCount++
			events = append(events, TimelineEvent{
				Capture:  label,
				Detector: ev.Detector,
				Protocol: ev.Protocol,
				Event:    ev.Event,
				Detail:   ev.Detail,
				Frame:    ev.Frame,
				epoch:    ep + offset,
				capIdx:   i,
			})
		}
		verdicts := make(map[string]string, len(rep.Verdicts))
		for k, v := range rep.Verdicts {
			verdicts[k] = v
		}
		perCapture = append(perCapture, CaptureSummary{
			Label:           label,
			Path:            paths[i],
			Packets:         rep.Capture.Packets,
			Start:           rep.Capture.Start,
			End:             rep.Capture.End,
			ClockOffsetS:    offset,
			OverallStatus:   rep.OverallStatus,
			Events:          capCount,
			TimelineOmitted: rep.TimelineOmitted,
			Verdicts:        verdicts,
		})
	}

	slices.SortStableFunc(events, func(a, b TimelineEvent) int {
		if c := cmp.Compare(a.epoch, b.epoch); c != 0 {
			return c
		}
		if c := cmp.Compare(a.capIdx, b.capIdx); c != 0 {
			return c
		}
		af, bf := 0, 0
		if a.Frame != nil {
			af = *a.Frame
		}
		if b.Frame != nil {
			bf = *b.Frame
		}
		return cmp.Compare(af, bf)
	})

	var originPtr *float64
	for _, c := range perCapture {
		if ep, ok := parseEpoch(c.Start); ok {
			val := ep + c.ClockOffsetS
			if originPtr == nil || val < *originPtr {
				v := val
				originPtr = &v
			}
		}
	}
	if originPtr == nil && len(events) > 0 {
		v := events[0].epoch
		originPtr = &v
	}

	if originPtr != nil {
		for i := range events {
			events[i].T = model.Round(events[i].epoch-*originPtr, 3)
			ep := events[i].epoch
			events[i].Time = model.ISOTime(&ep)
		}
	}

	measured := []MeasurementResult{}
	auto := []AutoMeasurement{}
	if len(opts.Measurements) > 0 {
		measured = make([]MeasurementResult, 0, len(opts.Measurements))
		for _, spec := range opts.Measurements {
			measured = append(measured, evaluateMeasurement(events, spec))
		}
	} else {
		auto = buildAutoMeasurements(events, reports, labels, opts.FailoverMaxS)
	}

	failing := 0
	for _, m := range measured {
		switch m.Verdict {
		case "exceeded", "below_min", "not_found":
			failing++
		}
	}
	for _, m := range auto {
		switch m.Verdict {
		case "exceeded", "below_min", "not_found", "not_recovered":
			failing++
		}
	}
	totalMeas := len(measured) + len(auto)
	var verdict string
	if totalMeas > 0 {
		tail := "all within threshold"
		if failing > 0 {
			tail = fmt.Sprintf("%d outside the threshold or not found", failing)
		}
		verdict = fmt.Sprintf("%d event(s) from %d capture(s); %d measurement(s), %s.", len(events), len(labels), totalMeas, tail)
	} else {
		verdict = fmt.Sprintf("%d event(s) from %d capture(s); nothing to measure.", len(events), len(labels))
	}

	capped, omitted := model.Cap(events, maxEvents)
	if capped == nil {
		capped = []TimelineEvent{}
	}
	detectorsUsed := slices.Clone(opts.Detectors)
	if len(detectorsUsed) == 0 {
		detectorsUsed = slices.Clone(netorch.DetectorNames)
	}

	rep := Report{
		Status:           "success",
		Schema:           ReportSchema,
		Verdict:          verdict,
		Origin:           model.ISOTime(originPtr),
		Captures:         perCapture,
		Measurements:     measured,
		AutoMeasurements: auto,
		Timeline:         capped,
		TimelineOmitted:  omitted,
		Detectors:        detectorsUsed,
		Limits:           slices.Clone(Limits),
	}

	if opts.OutputPath != "" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return errReport(err.Error())
		}
		if err := os.WriteFile(opts.OutputPath, buf.Bytes(), 0o600); err != nil {
			return errReport(err.Error())
		}
		rep.WrittenTo = absOutput
	}
	return rep
}
