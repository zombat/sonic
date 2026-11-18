// Package routing combines BGP, OSPFv2, and EIGRP analyzers into Detector.
package routing

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// Detector orchestrates BGP, OSPFv2, and EIGRP health checks across outer or GRE-tunneled traffic.
type Detector struct {
	bgp   *BgpAnalyzer
	ospf  *OspfAnalyzer
	eigrp *EigrpAnalyzer
}

// NewDetector returns an initialized combined routing Detector.
func NewDetector(expectedMSS *int) *Detector {
	return &Detector{
		bgp:   NewBgpAnalyzer(expectedMSS),
		ospf:  NewOspfAnalyzer(),
		eigrp: NewEigrpAnalyzer(),
	}
}

// Name returns "routing".
func (d *Detector) Name() string { return "routing" }

// Present reports whether any BGP, OSPF, or EIGRP traffic was observed.
func (d *Detector) Present() bool {
	return d.bgp.Present() || d.ospf.Present() || d.eigrp.Present()
}

// BGPAllUpdates exposes up to 200 stored BGP updates per speaker for convergence timing.
func (d *Detector) BGPAllUpdates(peers [2]string) map[string][]BGPUpdateSample {
	return d.bgp.allUpdates(peers)
}

// Feed dispatches outer or GRE-encapsulated IPv4 records to BGP, OSPF, and EIGRP analyzers.
func (d *Detector) Feed(rec *model.Record) {
	view := rec
	tunneled := false
	if rec.Inner != nil && (rec.Inner.TCP != nil || rec.Inner.OSPF != nil || rec.Inner.EIGRP != nil) {
		tunneled = true
		proj := model.Record{
			N:            rec.N,
			T:            rec.T,
			Len:          rec.Len,
			IP:           &model.IPHeader{V: 4, Src: rec.Inner.Src, Dst: rec.Inner.Dst, Proto: rec.Inner.Proto},
			TCP:          rec.Inner.TCP,
			UDP:          rec.Inner.UDP,
			BGP:          rec.Inner.BGP,
			BGPNLRI:      rec.Inner.BGPNLRI,
			BGPWithdrawn: rec.Inner.BGPWithdrawn,
			OSPF:         rec.Inner.OSPF,
			EIGRP:        rec.Inner.EIGRP,
		}
		view = &proj
	}
	switch {
	case view.TCP != nil:
		d.bgp.Feed(view, tunneled)
	case view.OSPF != nil:
		d.ospf.Feed(view, tunneled)
	case view.EIGRP != nil:
		d.eigrp.Feed(view, tunneled)
	}
}

// Report finalizes BGP, OSPF, and EIGRP health sections, merged issues, and failover timeline.
func (d *Detector) Report(ctx model.Context) Report {
	var rep Report
	rep.Detector = d.Name()

	allIssues := []model.Issue{}
	allEvents := []model.Event{}
	var statuses []model.Status
	var verdicts []string

	if d.bgp.Present() {
		issues := []model.Issue{}
		events := []model.Event{}
		sec := d.bgp.report(ctx, &issues, &events)
		st := model.StatusFromIssues(issues, true)
		sec.Status = st
		sec.Verdict = bgpVerdict(&sec, issues)
		sec.Issues = model.SortIssues(issues)
		rep.BGP = sec
		statuses = append(statuses, st)
		verdicts = append(verdicts, sec.Verdict)
		for _, iss := range issues {
			cp := iss
			cp.Protocol = "bgp"
			allIssues = append(allIssues, cp)
		}
		allEvents = append(allEvents, events...)
	}

	if d.ospf.Present() {
		issues := []model.Issue{}
		events := []model.Event{}
		sec := d.ospf.report(ctx, &issues, &events)
		st := model.StatusFromIssues(issues, true)
		sec.Status = st
		sec.Verdict = ospfVerdict(&sec, issues)
		sec.Issues = model.SortIssues(issues)
		rep.OSPF = sec
		statuses = append(statuses, st)
		verdicts = append(verdicts, sec.Verdict)
		for _, iss := range issues {
			cp := iss
			cp.Protocol = "ospf"
			allIssues = append(allIssues, cp)
		}
		allEvents = append(allEvents, events...)
	}

	if d.eigrp.Present() {
		issues := []model.Issue{}
		events := []model.Event{}
		sec := d.eigrp.report(ctx, &issues, &events)
		st := model.StatusFromIssues(issues, true)
		sec.Status = st
		sec.Verdict = eigrpVerdict(&sec, issues)
		sec.Issues = model.SortIssues(issues)
		rep.EIGRP = sec
		statuses = append(statuses, st)
		verdicts = append(verdicts, sec.Verdict)
		for _, iss := range issues {
			cp := iss
			cp.Protocol = "eigrp"
			allIssues = append(allIssues, cp)
		}
		allEvents = append(allEvents, events...)
	}

	slices.SortStableFunc(allEvents, func(a, b model.Event) int {
		at, bt := 0.0, 0.0
		if a.T != nil {
			at = *a.T
		}
		if b.T != nil {
			bt = *b.T
		}
		return cmp.Compare(at, bt)
	})

	if len(statuses) > 0 {
		rep.Status = model.WorstStatus(statuses)
		rep.Verdict = strings.Join(verdicts, " ")
	} else {
		rep.Status = model.StatusNotPresent
		rep.Verdict = "No BGP, OSPF or EIGRP in this capture."
	}
	rep.Issues = model.SortIssues(allIssues)
	rep.Events = allEvents

	failover := []model.Event{}
	limit := ctx.MaxItems * 4
	for _, ev := range allEvents {
		if FailoverEvents[ev.Event] {
			failover = append(failover, ev)
			if len(failover) >= limit && ctx.MaxItems >= 0 {
				break
			}
		}
	}
	rep.FailoverTimeline = failover
	return rep
}

// errorSuffix appends sorted unique error codes when issues contain SeverityError items.
func errorSuffix(issues []model.Issue) string {
	set := make(map[string]bool)
	for _, iss := range issues {
		if iss.Severity == model.SeverityError {
			set[iss.Code] = true
		}
	}
	if len(set) == 0 {
		return ""
	}
	codes := make([]string, 0, len(set))
	for c := range set {
		codes = append(codes, c)
	}
	slices.Sort(codes)
	return "; problems: " + strings.Join(codes, ", ")
}

// bgpVerdict builds the per-protocol BGP verdict string.
func bgpVerdict(sec *BGPSection, issues []model.Issue) string {
	up := 0
	flaps := 0
	for _, s := range sec.Sessions {
		if s.State == "established" {
			up++
		}
		flaps += s.TimesDown
	}
	text := fmt.Sprintf("BGP: %d of %d session(s) established at capture end", up, len(sec.Sessions))
	if flaps > 0 {
		text += fmt.Sprintf(", %d session reset(s)", flaps)
	}
	return text + errorSuffix(issues) + "."
}

// ospfVerdict builds the per-protocol OSPF verdict string.
func ospfVerdict(sec *OSPFSection, issues []model.Issue) string {
	totalAdj, twoWay := 0, 0
	for _, link := range sec.Links {
		for _, adj := range link.Adjacencies {
			totalAdj++
			if adj.StateHint == "2-way_or_better" {
				twoWay++
			}
		}
	}
	text := fmt.Sprintf("OSPF: %d router(s), %d of %d adjacency pair(s) reached 2-Way or better", sec.Routers, twoWay, totalAdj)
	return text + errorSuffix(issues) + "."
}

// eigrpVerdict builds the per-protocol EIGRP verdict string.
func eigrpVerdict(sec *EIGRPSection, issues []model.Issue) string {
	formed := 0
	for _, link := range sec.Links {
		for _, adj := range link.Adjacencies {
			if adj.InitExchanged {
				formed++
			}
		}
	}
	text := fmt.Sprintf("EIGRP: %d speaker(s), %d adjacency(ies) formed in the capture", sec.Speakers, formed)
	return text + errorSuffix(issues) + "."
}

// optStr renders *s or "None".
func optStr(s *string) string {
	if s == nil {
		return "None"
	}
	return *s
}

// optInt renders *v or "None".
func optInt(v *int) string {
	if v == nil {
		return "None"
	}
	return fmt.Sprintf("%d", *v)
}

// strPtrEq reports whether two optional string pointers hold equal values.
func strPtrEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// sortedStringSet returns the keys of set in sorted order.
func sortedStringSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// tailFrames returns at most the last count frames from frames.
func tailFrames(frames []int, count int) []int {
	if len(frames) > count {
		return frames[len(frames)-count:]
	}
	return frames
}
