// Package correlate validates multi-capture correlation inputs and coordinates
// concurrent record extraction and streaming packet matching.
package correlate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func errReport(msg string) Report {
	return Report{Status: "error", Error: msg}
}

func pyRepr(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}

func pyStringList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = pyRepr(s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// CorrelateCaptures follows packets across two or more captures and reports transit timing,
// NAT mappings, path verdicts, drops, and DSCP rewrites matching analyzers/correlate.py.
func CorrelateCaptures(ctx context.Context, captures []CaptureInput, opts Options) Report {
	if len(captures) < 2 {
		return errReport(`captures needs two or more entries, each {"path": ..., "label": ...}`)
	}
	labels := make([]string, 0, len(captures))
	paths := make([]string, 0, len(captures))
	labelSet := make(map[string]bool, len(captures))
	for _, entry := range captures {
		if entry.Path == "" {
			return errReport(`each capture needs a "path" (and a "label")`)
		}
		label := entry.Label
		if label == "" {
			label = filepath.Base(entry.Path)
		}
		if labelSet[label] {
			return errReport(fmt.Sprintf("duplicate capture label %s", pyRepr(label)))
		}
		if _, err := os.Stat(entry.Path); err != nil {
			return errReport("File not found: " + entry.Path)
		}
		labelSet[label] = true
		labels = append(labels, label)
		paths = append(paths, entry.Path)
	}

	var unknownOffsets []string
	for k := range opts.ClockOffsetsS {
		if !labelSet[k] {
			unknownOffsets = append(unknownOffsets, k)
		}
	}
	if len(unknownOffsets) > 0 {
		slices.Sort(unknownOffsets)
		r := errReport(fmt.Sprintf("clock_offsets_s names unknown label(s): %s", pyStringList(unknownOffsets)))
		r.Labels = labels
		return r
	}

	windowS := DefaultWindowS
	if opts.WindowS != nil {
		windowS = *opts.WindowS
	}
	if windowS <= 0 || windowS > 60 {
		return errReport("window_s must be between 0 and 60 seconds")
	}

	maxHeld := opts.MaxPacketsHeld
	if maxHeld == 0 {
		maxHeld = DefaultMaxHeld
	}
	if maxHeld < 100 {
		return errReport("max_packets_held must be at least 100")
	}

	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = 25
	}

	offsets := make([]float64, len(labels))
	for i, lbl := range labels {
		offsets[i] = opts.ClockOffsetsS[lbl]
	}

	cursors, infos, err := extractAll(ctx, paths, offsets, labels, opts.MaxPackets)
	if err != nil {
		return errReport(err.Error())
	}
	corr := newCorrelator(labels, windowS, maxHeld, infos)
	streamIntoCorrelator(cursors, corr)
	return buildReport(corr, labels, infos, windowS, maxHeld, maxItems)
}
