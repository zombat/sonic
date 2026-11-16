// Package tcphealth constructs final TCP health reports and verdict summaries.
package tcphealth

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// Report finalizes connection verdicts, RTO stats, and health issues into a Report.
func (d *Detector) Report(ctx model.Context) Report {
	issues := []model.Issue{}
	events := []model.Event{}
	endT := 0.0
	if ctx.End != nil {
		endT = *ctx.End
	}
	conns := make([]ConnectionEntry, 0, len(d.connOrder))
	for _, k := range d.connOrder {
		conn := d.conns[k]
		sum := d.summarizeConnection(ctx, conn, endT)
		conns = append(conns, sum)
		label := fmt.Sprintf("%s -> %s", sum.Client, sum.Server)
		if (sum.Verdict == "no_answer" || sum.Verdict == "refused") && conn.syn != nil {
			f := conn.syn.frames[0]
			events = append(events, model.MakeEvent(ctx, conn.syn.firstT, "tcp", sum.Verdict, label+": "+sum.Detail, &f))
		}
		for _, ev := range conn.eventList {
			f := ev.n
			msg := fmt.Sprintf("%s: first %s", label, strings.ReplaceAll(ev.kind, "_", " "))
			events = append(events, model.MakeEvent(ctx, ev.t, "tcp", ev.kind, msg, &f))
		}
		for i := 0; i < len(conn.rst) && i < 2; i++ {
			r := conn.rst[i]
			f := r.n
			msg := fmt.Sprintf("%s: RST from %s", label, model.Endpoint(r.from.ip, &r.from.port))
			events = append(events, model.MakeEvent(ctx, r.t, "tcp", "rst", msg, &f))
		}
	}

	rank := make(map[string]int, len(verdictOrder))
	for i, v := range verdictOrder {
		rank[v] = i
	}
	slices.SortStableFunc(conns, func(a, b ConnectionEntry) int {
		if ra, rb := rank[a.Verdict], rank[b.Verdict]; ra != rb {
			return ra - rb
		}
		at, bt := 0.0, 0.0
		if a.FirstT != nil {
			at = *a.FirstT
		}
		if b.FirstT != nil {
			bt = *b.FirstT
		}
		if at < bt {
			return -1
		}
		if at > bt {
			return 1
		}
		return 0
	})

	counts := make(map[string]int, len(verdictOrder))
	for _, v := range verdictOrder {
		counts[v] = 0
	}
	for _, c := range conns {
		counts[c.Verdict]++
	}

	issueSpecs := []struct {
		verdict string
		sev     model.Severity
		code    string
		title   string
	}{
		{"no_answer", model.SeverityError, "TCP_NO_ANSWER", "SYN without SYN-ACK"},
		{"refused", model.SeverityWarning, "TCP_REFUSED", "SYN answered by RST"},
		{"receiver_buffer_exhausted", model.SeverityWarning, "TCP_ZERO_WINDOW", "receive buffer exhausted (zero window)"},
		{"loss_on_path", model.SeverityWarning, "TCP_LOSS", "loss on the path"},
		{"receive_window_limited", model.SeverityInfo, "TCP_WINDOW_FULL", "limited by the receive window"},
		{"reset", model.SeverityInfo, "TCP_RESET", "reset mid-connection"},
	}
	for _, spec := range issueSpecs {
		var hit []ConnectionEntry
		for _, c := range conns {
			if c.Verdict == spec.verdict {
				hit = append(hit, c)
			}
		}
		if len(hit) == 0 {
			continue
		}
		var samples []string
		var frames []int
		for i := 0; i < len(hit) && i < 3; i++ {
			samples = append(samples, fmt.Sprintf("%s -> %s: %s", hit[i].Client, hit[i].Server, hit[i].Detail))
			frames = append(frames, hit[i].Frames...)
		}
		msg := fmt.Sprintf("%d connection(s) %s. %s", len(hit), spec.title, strings.Join(samples, "; "))
		iss := model.MakeIssue(spec.sev, spec.code, msg, frames)
		cnt := len(hit)
		iss.Connections = &cnt
		issues = append(issues, iss)
	}

	mssSet := make(map[int]bool)
	for _, c := range conns {
		for _, dm := range c.Directions {
			if dm.MSS != nil && *dm.MSS != 0 {
				mssSet[*dm.MSS] = true
			}
		}
	}
	mssVals := make([]int, 0, len(mssSet))
	for m := range mssSet {
		mssVals = append(mssVals, m)
	}
	slices.Sort(mssVals)
	var clampedStr []string
	for _, m := range mssVals {
		if m < 1460 {
			clampedStr = append(clampedStr, strconv.Itoa(m))
		}
	}
	if len(clampedStr) > 0 {
		msg := fmt.Sprintf("MSS offered below 1460: %s (a lower interface MTU, or ip tcp adjust-mss clamping for a tunnel)",
			strings.Join(clampedStr, ", "))
		issues = append(issues, model.MakeIssue(model.SeverityInfo, "TCP_MSS_BELOW_1460", msg, nil))
	}

	present := d.Present()
	status := model.StatusFromIssues(issues, present)
	verdict := buildTCPVerdict(present, conns, counts, mssVals)

	listed, omitted := model.Cap(conns, ctx.MaxItems)
	return Report{
		Detector: d.Name(), Status: status, Verdict: verdict,
		Summary: Summary{
			Connections: len(conns), ByVerdict: counts, MSSOffered: mssVals,
			ConnectionsDroppedCap: d.dropped,
		},
		Connections: listed, ConnectionsOmitted: omitted,
		Limits: Limits, Issues: model.SortIssues(issues), Events: events,
	}
}

// buildTCPVerdict formats the top-level TCP health summary sentence.
func buildTCPVerdict(present bool, conns []ConnectionEntry, counts map[string]int, mssVals []int) string {
	if !present {
		return "No TCP in this capture."
	}
	var badParts []string
	for _, v := range verdictOrder {
		if n := counts[v]; n > 0 && v != "healthy" {
			badParts = append(badParts, fmt.Sprintf("%d %s", n, strings.ReplaceAll(v, "_", " ")))
		}
	}
	verdict := fmt.Sprintf("%d TCP connection(s): ", len(conns))
	if len(badParts) > 0 {
		verdict += strings.Join(badParts, ", ")
	} else {
		verdict += "all healthy"
	}
	if len(mssVals) > 0 {
		mStr := make([]string, len(mssVals))
		for i, m := range mssVals {
			mStr[i] = strconv.Itoa(m)
		}
		verdict += "; MSS offered " + strings.Join(mStr, ", ")
	}
	return verdict + "."
}
