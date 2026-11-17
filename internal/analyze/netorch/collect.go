// Package netorch aggregates detector reports, timeline events, and verdicts for network_orchestrator.
package netorch

import (
	"cmp"
	"context"
	"encoding/json"
	"slices"

	"github.com/zombat/sonic/internal/analyze/audit"
	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/model"
)

func collectReport(
	ctx context.Context,
	filePath string,
	opts Options,
	names []string,
	maxItems int,
	ds detectorSet,
	capInfo model.CaptureInfo,
	families []string,
	mCtx model.Context,
	sipSeen bool,
) builtReport {
	var sec sectionOutputs
	rep := NetworkReport{
		NetworkBody: NetworkBody{
			Status:              "success",
			Schema:              ReportSchema,
			File:                filePath,
			Capture:             capInfo,
			ProtocolsPresent:    families,
			DetectorsRequested:  names,
			DetectorsRun:        []string{},
			DetectorsNotPresent: []string{},
			Verdicts:            make(map[string]string, len(names)),
		},
	}
	var statuses []model.Status
	allIssues := []model.Issue{}
	allTimeline := []model.Event{}

	for _, name := range names {
		switch name {
		case "ipsec":
			r := ds.ipsec.Report(mCtx)
			sec.ipsec = &r
			rep.IPsec = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "gre_nhrp":
			r := ds.greNHRP.Report(mCtx)
			sec.greNHRP = &r
			rep.GreNHRP = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "dmvpn_phase3":
			r := ds.dmvpn.Report(mCtx)
			sec.dmvpn = &r
			rep.DMVPNPhase3 = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "routing":
			r := ds.routing.Report(mCtx)
			sec.routing = &r
			rep.Routing = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "reachability":
			r := ds.reachability.Report(mCtx)
			sec.reachability = &r
			rep.Reachability = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "path_mtu":
			r := ds.pathMTU.Report(mCtx)
			sec.pathMTU = &r
			rep.PathMTU = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "esp_overhead":
			r := ds.espOverhead.Report(mCtx)
			sec.espOverhead = &r
			rep.ESPOverhead = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "tcp":
			r := ds.tcp.Report(mCtx)
			sec.tcp = &r
			rep.TCP = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "tls":
			r := ds.tls.Report(mCtx)
			sec.tls = &r
			rep.TLS = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "qos":
			r := ds.qos.Report(mCtx)
			sec.qos = &r
			rep.QoS = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "conversations":
			r := ds.conversations.Report(mCtx)
			sec.conversations = &r
			rep.Conversations = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "cleartext_audit":
			r := ds.cleartextAudit.Report(mCtx, filePath, capInfo, families)
			audit.AddGrpcFindings(ctx, &r, filePath, opts.DisplayFilter, opts.MaxPackets)
			sec.cleartextAudit = &r
			st := model.StatusOK
			if !r.Passed {
				st = model.StatusProblem
			} else if !r.Clean {
				st = model.StatusWarning
			}
			rep.CleartextAudit = auditSectionBytes(r, st)
			appendSectionIssuesEvents(name, r.Verdict, st, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		case "convergence":
			r, err := ds.convergence.Report(mCtx)
			if err != nil {
				return builtReport{report: errNetworkReport(err.Error())}
			}
			sec.convergence = &r
			rep.Convergence = stripEventsBytes(json.Marshal(r))
			appendSectionIssuesEvents(name, r.Verdict, r.Status, r.Issues, r.Events, &rep.DetectorsRun, &rep.DetectorsNotPresent, rep.Verdicts, &statuses, &allIssues, &allTimeline)
		}
	}

	limit := maxItems * 8
	rep.OverallStatus = model.WorstStatus(statuses)
	rep.Issues, rep.IssuesOmitted, rep.Timeline, rep.TimelineOmitted = sortAndCapAll(allIssues, allTimeline, limit)
	includeSIP := opts.IncludeSIP == nil || *opts.IncludeSIP
	sipRes := sip.EvaluateNetorchSIP(ctx, filePath, sipSeen, includeSIP)
	rep.SIP = SIPSummary{
		Present:         sipRes.Present,
		QualityAnalysis: sipRes.QualityAnalysis,
		QualityError:    sipRes.QualityError,
		MOSAnalysis:     sipRes.MOSAnalysis,
		MOSError:        sipRes.MOSError,
		Error:           sipRes.Error,
		Note:            sipRes.Note,
	}
	return builtReport{report: rep, sections: sec}
}

func auditSectionBytes(r model.AuditReport, st model.Status) json.RawMessage {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil
	}
	var obj map[string]json.RawMessage
	if uerr := json.Unmarshal(raw, &obj); uerr != nil {
		return raw
	}
	delete(obj, "events")
	delete(obj, "capture")
	delete(obj, "file")
	delete(obj, "protocols_present")
	if detRaw, merr := json.Marshal("cleartext_audit"); merr == nil {
		obj["detector"] = detRaw
	}
	if stRaw, merr := json.Marshal(st); merr == nil {
		obj["status"] = stRaw
	}
	cleaned, merr := json.Marshal(obj)
	if merr != nil {
		return raw
	}
	return cleaned
}

func stripEventsBytes(raw []byte, err error) json.RawMessage {
	if err != nil {
		return nil
	}
	var obj map[string]json.RawMessage
	if uerr := json.Unmarshal(raw, &obj); uerr != nil {
		return raw
	}
	delete(obj, "events")
	cleaned, merr := json.Marshal(obj)
	if merr != nil {
		return raw
	}
	return cleaned
}

func appendSectionIssuesEvents(
	name, verdict string,
	status model.Status,
	secIssues []model.Issue,
	secEvents []model.Event,
	run *[]string,
	notPresent *[]string,
	verdicts map[string]string,
	statuses *[]model.Status,
	allIssues *[]model.Issue,
	allTimeline *[]model.Event,
) {
	if status != model.StatusNotPresent {
		*run = append(*run, name)
	} else {
		*notPresent = append(*notPresent, name)
	}
	verdicts[name] = verdict
	if name != "conversations" {
		*statuses = append(*statuses, status)
	}
	for _, ev := range secEvents {
		ev.Detector = name
		*allTimeline = append(*allTimeline, ev)
	}
	for _, iss := range secIssues {
		if iss.Severity == model.SeverityError || iss.Severity == model.SeverityWarning {
			iss.Detector = name
			*allIssues = append(*allIssues, iss)
		}
	}
}

func sortAndCapAll(issues []model.Issue, timeline []model.Event, limit int) ([]model.Issue, int, []model.Event, int) {
	slices.SortStableFunc(timeline, func(a, b model.Event) int {
		at, bt := 0.0, 0.0
		if a.T != nil {
			at = *a.T
		}
		if b.T != nil {
			bt = *b.T
		}
		if c := cmp.Compare(at, bt); c != 0 {
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
	slices.SortStableFunc(issues, func(a, b model.Issue) int {
		return cmp.Compare(model.SeverityOrder(a.Severity), model.SeverityOrder(b.Severity))
	})
	listedIssues, issuesOmitted := model.Cap(issues, limit)
	if listedIssues == nil {
		listedIssues = []model.Issue{}
	}
	listedTL, tlOmitted := model.Cap(timeline, limit)
	if listedTL == nil {
		listedTL = []model.Event{}
	}
	return listedIssues, issuesOmitted, listedTL, tlOmitted
}
