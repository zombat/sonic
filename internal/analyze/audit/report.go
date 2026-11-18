// Package audit builds final AuditReport structures and provides the
// top-level AuditCleartextCapture runner.
package audit

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

// Report finalizes TCP sessions and builds a model.AuditReport for the audited capture.
func (d *Detector) Report(ctx model.Context, filePath string, capInfo model.CaptureInfo, families []string) model.AuditReport {
	issues := []model.Issue{}
	sessions := d.settleSessions()

	rows := make([]*violationAgg, 0, len(d.violationOrder))
	for _, k := range d.violationOrder {
		rows = append(rows, d.violations[k])
	}
	slices.SortStableFunc(rows, func(a, b *violationAgg) int {
		return a.firstFrame - b.firstFrame
	})

	var protoOrder []string
	byProtoMap := make(map[string]*model.ByProtocol)
	for _, r := range rows {
		agg, ok := byProtoMap[r.protocol]
		if !ok {
			agg = &model.ByProtocol{
				Protocol:   r.protocol,
				Category:   r.category,
				FirstFrame: r.firstFrame,
			}
			byProtoMap[r.protocol] = agg
			protoOrder = append(protoOrder, r.protocol)
		}
		agg.Packets += r.packets
		agg.Bytes += r.bytes
		agg.Pairs++
	}
	byProto := make([]model.ByProtocol, 0, len(protoOrder))
	for _, name := range protoOrder {
		byProto = append(byProto, *byProtoMap[name])
	}
	slices.SortStableFunc(byProto, func(a, b model.ByProtocol) int {
		return a.FirstFrame - b.FirstFrame
	})

	violationsOut := make([]model.AuditViolation, 0, len(rows))
	events := make([]model.Event, 0, len(rows))
	violating := 0
	for _, r := range rows {
		violating += r.packets
		var srcPtr, dstPtr *string
		pair := "(layer 2, no addresses)"
		if r.hasAddr {
			s, dt := r.src, r.dst
			srcPtr, dstPtr = &s, &dt
			pair = s + " -> " + dt
		}
		hint := Hints[r.category]
		if hint == "" {
			hint = Hints["cleartext"]
		}
		firstT := 0.0
		if rt := ctx.Rel(&r.firstT); rt != nil {
			firstT = *rt
		}
		lastT := 0.0
		if rt := ctx.Rel(&r.lastT); rt != nil {
			lastT = *rt
		}
		av := model.AuditViolation{
			Protocol:   r.protocol,
			Category:   r.category,
			Hint:       hint,
			Src:        srcPtr,
			Dst:        dstPtr,
			Packets:    r.packets,
			Bytes:      r.bytes,
			FirstFrame: r.firstFrame,
			LastFrame:  r.lastFrame,
			FirstT:     firstT,
			LastT:      lastT,
			Frames:     nonNilInts(r.frames),
			Protection: r.protection,
			Reasons:    r.reasons,
		}
		violationsOut = append(violationsOut, av)
		frameCopy := r.firstFrame
		events = append(events, model.MakeEvent(ctx, r.firstT, "audit", "first_leak",
			fmt.Sprintf("first %s frame outside the allowlist %s", r.protocol, pair), &frameCopy))

		msg := fmt.Sprintf("%d %s frame(s) %s outside the allowlist (%s)", r.packets, r.protocol, pair, hint)
		if len(r.reasons) > 0 {
			msg += ": " + strings.Join(r.reasons, "; ")
		}
		switch r.category {
		case "encrypted":
			issue := model.MakeIssue(model.SeverityWarning, "ENCRYPTED_OUTSIDE_ALLOWLIST", msg, r.frames)
			issue.Protocol = r.protocol
			issue.Category = r.category
			issues = append(issues, issue)
		case "layer2":
			issue := model.MakeIssue(model.SeverityWarning, "CLEARTEXT_OUTSIDE_ALLOWLIST", msg, r.frames)
			issue.Protocol = r.protocol
			issue.Category = r.category
			issues = append(issues, issue)
		default:
			issue := model.MakeIssue(model.SeverityError, "CLEARTEXT_OUTSIDE_ALLOWLIST", msg, r.frames)
			issue.Protocol = r.protocol
			issue.Category = r.category
			issues = append(issues, issue)
		}
	}

	encSummary, outsideTunnel := encryptionFindings(sessions, &issues)
	passed := violating == 0 && d.frames > 0
	clean := passed && encSummary.Weak == 0 && encSummary.Unverified == 0
	cleartext := d.protection["cleartext"]

	protectionOut := map[string]int{
		"encrypted":          d.protection["encrypted"],
		"key_exchange":       d.protection["key_exchange"],
		"authenticated_only": d.protection["authenticated_only"],
		"layer2":             d.protection["layer2"],
		"cleartext":          d.protection["cleartext"],
	}

	verdict := buildVerdict(d.frames, passed, clean, d.allowText, protectionOut, cleartext, encSummary, outsideTunnel, rows, byProto, &issues)
	listedViolations, omittedViolations := model.Cap(violationsOut, ctx.MaxItems)
	listedSessions, omittedSessions := model.Cap(sessions, ctx.MaxItems)

	var firstViolFrame *int
	if len(rows) > 0 {
		ff := rows[0].firstFrame
		firstViolFrame = &ff
	}
	result := "fail"
	if passed {
		result = "pass"
	}

	return model.AuditReport{
		Status:                 "success",
		Passed:                 passed,
		Clean:                  clean,
		Result:                 result,
		Verdict:                verdict,
		Allowlist:              d.allowText,
		FramesAudited:          d.frames,
		FramesAllowed:          d.allowed,
		FramesOutsideAllowlist: violating,
		CleartextFrames:        cleartext,
		Protection:             protectionOut,
		Encryption:             encSummary,
		FirstViolationFrame:    firstViolFrame,
		ByProtocol:             byProto,
		Violations:             listedViolations,
		ViolationsOmitted:      omittedViolations,
		TCPSessions:            listedSessions,
		TCPSessionsOmitted:     omittedSessions,
		AllowedByRule:          d.allowedBy,
		CannotShow:             CannotShow,
		Issues:                 issues,
		File:                   filePath,
		Capture:                capInfo,
		ProtocolsPresent:       nonNilStrings(families),
		Events:                 events,
	}
}

// AuditOptions configures an AuditCleartextCapture run.
type AuditOptions struct {
	Binary        string
	FilePath      string
	Allow         []string
	DisplayFilter string
	MaxPackets    *int
	MaxItems      int
	// SNMPPorts are UDP ports to decode as SNMP, for a manager or agent that
	// does not use the standard port 161 or 162.
	SNMPPorts []int
}

// AuditCleartextCapture runs tshark extraction and audits every frame against the allowlist.
func AuditCleartextCapture(ctx context.Context, opts AuditOptions) (model.AuditReport, error) {
	det, err := NewDetector(opts.Allow)
	if err != nil {
		return model.AuditReport{Status: "error", Error: err.Error()}, err
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = 25
	}

	recordsOut, err := extract.OpenNetworkRecords(ctx, tshark.StreamOptions{
		Binary:        opts.Binary,
		FilePath:      opts.FilePath,
		DisplayFilter: opts.DisplayFilter,
		MaxPackets:    opts.MaxPackets,
		DecodeAs:      SNMPDecodeAs(opts.SNMPPorts),
	})
	if err != nil {
		return model.AuditReport{Status: "error", Error: err.Error()}, err
	}

	totalBytes := 0
	var startPtr, endPtr *float64
	for i := range recordsOut.Records {
		rec := &recordsOut.Records[i]
		totalBytes += rec.Len
		if rec.T != 0 {
			tVal := rec.T
			if startPtr == nil || tVal < *startPtr {
				v := tVal
				startPtr = &v
			}
			if endPtr == nil || tVal > *endPtr {
				v := tVal
				endPtr = &v
			}
		}
		det.Feed(rec)
	}

	var durPtr *float64
	if startPtr != nil && endPtr != nil {
		dVal := math.Round((*endPtr-*startPtr)*1000) / 1000
		if dVal == 0 {
			dVal = 0
		}
		durPtr = &dVal
	}
	var dfPtr *string
	if opts.DisplayFilter != "" {
		s := opts.DisplayFilter
		dfPtr = &s
	}

	capInfo := model.CaptureInfo{
		Backend:             recordsOut.Backend,
		Packets:             len(recordsOut.Records),
		Bytes:               totalBytes,
		Start:               model.ISOTime(startPtr),
		End:                 model.ISOTime(endPtr),
		DurationS:           durPtr,
		DisplayFilter:       dfPtr,
		MaxPackets:          opts.MaxPackets,
		MissingTsharkFields: nonNilStrings(recordsOut.MissingFields),
		Warnings:            nonNilStrings(recordsOut.Warnings),
	}
	families := extract.DetectFamilies(recordsOut.Records)
	mCtx := model.Context{Start: startPtr, End: endPtr, MaxItems: maxItems}
	return det.Report(mCtx, opts.FilePath, capInfo, families), nil
}

func nonNilInts(in []int) []int {
	if in == nil {
		return []int{}
	}
	return in
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
