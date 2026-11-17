// Package timeline validates capture inputs, measurement selectors, and JSON output paths.
package timeline

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// errReport builds a minimal error Report payload.
func errReport(msg string) Report {
	return Report{Status: "error", Error: msg}
}

// pyRepr formats s with single quotes matching Python repr for error message parity.
func pyRepr(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}

// pyStringList renders a Python-style list literal of quoted strings.
func pyStringList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = pyRepr(s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// validateInputs checks captures, offsets, measurement selectors, and optional output path.
func validateInputs(captures []CaptureInput, opts Options) ([]string, []string, string, *Report) {
	if len(captures) == 0 {
		r := errReport(`captures needs one or more entries, each {"path": ..., "label": ...}`)
		return nil, nil, "", &r
	}
	labels := make([]string, 0, len(captures))
	paths := make([]string, 0, len(captures))
	labelSet := make(map[string]bool, len(captures))
	for _, entry := range captures {
		if entry.Path == "" {
			r := errReport(`each capture needs a "path" (and a "label")`)
			return nil, nil, "", &r
		}
		label := entry.Label
		if label == "" {
			label = filepath.Base(entry.Path)
		}
		if labelSet[label] {
			r := errReport(fmt.Sprintf("duplicate capture label %s", pyRepr(label)))
			return nil, nil, "", &r
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
		return nil, nil, "", &r
	}

	validKeys := make([]string, 0, len(SelectorKeys))
	for k := range SelectorKeys {
		validKeys = append(validKeys, k)
	}
	slices.Sort(validKeys)

	for _, spec := range opts.Measurements {
		if spec.From == nil || spec.To == nil {
			r := errReport(`each measurement needs "from" and "to" selectors (objects)`)
			return nil, nil, "", &r
		}
		for _, side := range []*Selector{spec.From, spec.To} {
			if len(side.UnknownKeys) > 0 {
				r := errReport(fmt.Sprintf("unknown selector key(s) %s in measurement %s", pyStringList(side.UnknownKeys), pyRepr(spec.Name)))
				r.ValidKeys = validKeys
				return nil, nil, "", &r
			}
			if side.Capture != nil && !labelSet[*side.Capture] {
				r := errReport(fmt.Sprintf("measurement %s names unknown capture %s", pyRepr(spec.Name), pyRepr(*side.Capture)))
				r.Labels = labels
				return nil, nil, "", &r
			}
		}
	}

	var absOutput string
	if opts.OutputPath != "" {
		if !strings.HasSuffix(opts.OutputPath, ".json") {
			r := errReport("output_path must end in .json")
			return nil, nil, "", &r
		}
		if _, err := os.Stat(opts.OutputPath); err == nil && !opts.Overwrite {
			r := errReport(fmt.Sprintf("output_path exists: %s (pass overwrite=true to replace it)", opts.OutputPath))
			return nil, nil, "", &r
		}
		var err error
		absOutput, err = filepath.Abs(opts.OutputPath)
		if err != nil {
			r := errReport(err.Error())
			return nil, nil, "", &r
		}
		parent := filepath.Dir(absOutput)
		if info, statErr := os.Stat(parent); statErr != nil || !info.IsDir() {
			r := errReport(fmt.Sprintf("output_path directory does not exist: %s", parent))
			return nil, nil, "", &r
		}
	}
	return labels, paths, absOutput, nil
}
