// Package correlate formats transit timings, NAT translations, DSCP rewrites,
// connections, and summary verdicts for sonic.correlation_report/1 outputs.
package correlate

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

func buildReport(corr *correlator, labels []string, infos []*streamInfo, windowS float64, maxHeld, maxItems int) Report {
	var startPtr *float64
	for _, inf := range infos {
		if inf.start != nil && (startPtr == nil || *inf.start < *startPtr) {
			v := *inf.start
			startPtr = &v
		}
	}

	captures := make([]CaptureRow, 0, len(infos))
	for i, inf := range infos {
		captures = append(captures, CaptureRow{
			Label:            inf.label,
			Path:             inf.path,
			Backend:          inf.back,
			Packets:          corr.packets[i],
			UnmatchedPackets: corr.unmatched[i],
			Start:            model.ISOTime(inf.start),
			End:              model.ISOTime(inf.end),
			ClockOffsetS:     inf.offset,
			Warnings:         inf.warns,
		})
	}

	transit := buildTransit(corr, labels)
	natAll := buildNAT(corr, labels)
	dscpAll := buildDSCPChanges(corr, labels)
	connections := buildConnections(corr, labels, startPtr)

	verdictOrder := map[string]int{
		"reply_lost": 0, "partial_loss": 1, "asymmetric": 2,
		"seen_only_at": 3, "ok": 4, "not_on_other_paths": 5,
	}
	slices.SortStableFunc(connections, func(a, b ConnectionRow) int {
		oa, ok := verdictOrder[a.Verdict]
		if !ok {
			oa = 9
		}
		ob, ok := verdictOrder[b.Verdict]
		if !ok {
			ob = 9
		}
		if oa != ob {
			return oa - ob
		}
		fa, fb := 0.0, 0.0
		if a.FirstT != nil {
			fa = *a.FirstT
		}
		if b.FirstT != nil {
			fb = *b.FirstT
		}
		return cmp.Compare(fa, fb)
	})

	counts := make(map[string]int)
	issues := []CorrelateIssue{}
	sevForVerdict := map[string]string{
		"reply_lost": "error", "partial_loss": "warning", "asymmetric": "warning", "seen_only_at": "warning",
	}
	for _, conn := range connections {
		counts[conn.Verdict]++
		if sev, ok := sevForVerdict[conn.Verdict]; ok {
			fRaw, _ := json.Marshal(conn.Frames)
			issues = append(issues, CorrelateIssue{
				Severity: sev,
				Code:     "CORRELATE_" + strings.ToUpper(conn.Verdict),
				Message:  conn.Detail,
				Frames:   fRaw,
			})
		}
	}
	for _, chg := range dscpAll {
		fRaw, _ := json.Marshal(chg.Frames)
		issues = append(issues, CorrelateIssue{
			Severity: "warning",
			Code:     "CORRELATE_DSCP_REWRITTEN",
			Message: fmt.Sprintf(
				"%s: DSCP %s at %s became %s at %s (%d packet(s))",
				chg.Flow, chg.DSCPBefore, chg.From, chg.DSCPAfter, chg.To, chg.Packets,
			),
			Frames: fRaw,
		})
	}

	matched := corr.groupsMatched
	var verdict string
	if matched == 0 {
		verdict = "No packet was seen in more than one capture. If the captures overlap in time and carry the same traffic, their clocks may differ by more than window_s: pass clock_offsets_s."
	} else {
		bits := []string{fmt.Sprintf("%d packet(s) matched across %d captures", matched, len(labels))}
		if len(natAll) > 0 {
			bits = append(bits, fmt.Sprintf("%d NAT translation(s)", len(natAll)))
		}
		for _, name := range []string{"reply_lost", "partial_loss", "asymmetric", "seen_only_at"} {
			if counts[name] > 0 {
				bits = append(bits, fmt.Sprintf("%d %s", counts[name], strings.ReplaceAll(name, "_", " ")))
			}
		}
		if len(dscpAll) > 0 {
			dscpPkts := 0
			for _, chg := range dscpAll {
				dscpPkts += chg.Packets
			}
			bits = append(bits, fmt.Sprintf("DSCP rewritten on %d packet(s)", dscpPkts))
		}
		verdict = strings.Join(bits, "; ") + "."
	}

	connList, connOmitted := model.Cap(connections, maxItems)
	if connList == nil {
		connList = []ConnectionRow{}
	}
	natList, natOmitted := model.Cap(natAll, maxItems)
	if natList == nil {
		natList = []NATRow{}
	}
	dscpList, _ := model.Cap(dscpAll, maxItems)
	if dscpList == nil {
		dscpList = []DSCPChangeRow{}
	}
	issueList, _ := model.Cap(issues, maxItems*4)
	if issueList == nil {
		issueList = []CorrelateIssue{}
	}

	return Report{
		Status:   "success",
		Schema:   ReportSchema,
		Verdict:  verdict,
		Captures: captures,
		Matching: MatchingInfo{
			WindowS:           windowS,
			MaxPacketsHeld:    maxHeld,
			EvictedEarly:      corr.evictedEarly,
			FlowsDroppedAtCap: corr.nodesDropped,
			PacketsMatched:    matched,
		},
		Summary: Summary{
			Connections:     len(connections),
			ByVerdict:       counts,
			NATTranslations: len(natAll),
			DSCPChanges:     len(dscpAll),
		},
		Issues:             issueList,
		Transit:            transit,
		NAT:                natList,
		NATOmitted:         natOmitted,
		Connections:        connList,
		ConnectionsOmitted: connOmitted,
		DSCPChanges:        dscpList,
		Limits:             slices.Clone(Limits),
	}
}
