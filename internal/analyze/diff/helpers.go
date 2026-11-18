// Package diff contains set, issue, protocol, QoS, and VoIP delta helpers for diff.go.
package diff

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/qos"
	"github.com/zombat/sonic/internal/analyze/tcphealth"
	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/model"
)

func errDiffReport(base, tgt, msg string) DiffReport {
	return DiffReport{
		Status:           "error",
		Error:            msg,
		BaselineFile:     base,
		TargetFile:       tgt,
		ProtocolsAdded:   []string{},
		ProtocolsRemoved: []string{},
		IssuesAdded:      []IssueDelta{},
		IssuesResolved:   []IssueDelta{},
		Highlights:       []string{},
	}
}

func diffStringSets(base, tgt []string) (added, removed []string) {
	bSet := make(map[string]bool, len(base))
	tSet := make(map[string]bool, len(tgt))
	for _, s := range base {
		bSet[s] = true
	}
	for _, s := range tgt {
		tSet[s] = true
	}
	added, removed = []string{}, []string{}
	for _, s := range tgt {
		if !bSet[s] && !slices.Contains(added, s) {
			added = append(added, s)
		}
	}
	for _, s := range base {
		if !tSet[s] && !slices.Contains(removed, s) {
			removed = append(removed, s)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

func diffIssues(base, tgt []model.Issue) (added, resolved []IssueDelta) {
	keyOf := func(i model.Issue) string {
		return i.Detector + "|" + i.Code + "|" + i.Severity.String()
	}
	bMap := make(map[string]model.Issue, len(base))
	tMap := make(map[string]model.Issue, len(tgt))
	for _, i := range base {
		bMap[keyOf(i)] = i
	}
	for _, i := range tgt {
		tMap[keyOf(i)] = i
	}
	added, resolved = []IssueDelta{}, []IssueDelta{}
	for k, i := range tMap {
		if _, ok := bMap[k]; !ok {
			added = append(added, IssueDelta{Detector: i.Detector, Code: i.Code, Severity: i.Severity, Message: i.Message})
		}
	}
	for k, i := range bMap {
		if _, ok := tMap[k]; !ok {
			resolved = append(resolved, IssueDelta{Detector: i.Detector, Code: i.Code, Severity: i.Severity, Message: i.Message})
		}
	}
	sortDeltas := func(s []IssueDelta) {
		slices.SortFunc(s, func(a, b IssueDelta) int {
			return strings.Compare(a.Code+a.Detector, b.Code+b.Detector)
		})
	}
	sortDeltas(added)
	sortDeltas(resolved)
	return added, resolved
}

func diffTLS(baseRaw, tgtRaw json.RawMessage) TLSDelta {
	extractTLS := func(raw json.RawMessage) (vers, ciphers, alpns []string, count int) {
		vers, ciphers, alpns = []string{}, []string{}, []string{}
		if len(raw) == 0 {
			return
		}
		var rep tlsinspect.Report
		if json.Unmarshal(raw, &rep) != nil {
			return
		}
		count = rep.Summary.Handshakes
		for _, sess := range rep.Sessions {
			if sess.ServerChose == nil {
				continue
			}
			if sess.ServerChose.Version != "" && !slices.Contains(vers, sess.ServerChose.Version) {
				vers = append(vers, sess.ServerChose.Version)
			}
			if sess.ServerChose.CipherSuite != "" && !slices.Contains(ciphers, sess.ServerChose.CipherSuite) {
				ciphers = append(ciphers, sess.ServerChose.CipherSuite)
			}
			if sess.ServerChose.ALPN != nil && *sess.ServerChose.ALPN != "" && !slices.Contains(alpns, *sess.ServerChose.ALPN) {
				alpns = append(alpns, *sess.ServerChose.ALPN)
			}
		}
		slices.Sort(vers)
		slices.Sort(ciphers)
		slices.Sort(alpns)
		return
	}
	bv, bc, ba, bn := extractTLS(baseRaw)
	tv, tc, ta, tn := extractTLS(tgtRaw)
	changed := bn != tn || !slices.Equal(bv, tv) || !slices.Equal(bc, tc) || !slices.Equal(ba, ta)
	return TLSDelta{
		BaselineVersions: bv, TargetVersions: tv,
		BaselineCiphers: bc, TargetCiphers: tc,
		BaselineALPNs: ba, TargetALPNs: ta,
		HandshakesDelta: tn - bn, Changed: changed,
	}
}

func diffTCPMSS(baseRaw, tgtRaw json.RawMessage) TCPMTUDelta {
	extractMSS := func(raw json.RawMessage) []int {
		if len(raw) == 0 {
			return []int{}
		}
		var rep tcphealth.Report
		if json.Unmarshal(raw, &rep) != nil || rep.Summary.MSSOffered == nil {
			return []int{}
		}
		out := slices.Clone(rep.Summary.MSSOffered)
		slices.Sort(out)
		return out
	}
	bm := extractMSS(baseRaw)
	tm := extractMSS(tgtRaw)
	return TCPMTUDelta{BaselineMSS: bm, TargetMSS: tm, Changed: !slices.Equal(bm, tm)}
}

func diffQoS(baseRaw, tgtRaw json.RawMessage) QoSDelta {
	extractDSCP := func(raw json.RawMessage) []string {
		out := []string{}
		if len(raw) == 0 {
			return out
		}
		var rep qos.Report
		if json.Unmarshal(raw, &rep) != nil {
			return out
		}
		for _, mf := range rep.MarkedFlows {
			for k := range mf.DSCP {
				if !slices.Contains(out, k) {
					out = append(out, k)
				}
			}
		}
		slices.Sort(out)
		return out
	}
	bd := extractDSCP(baseRaw)
	td := extractDSCP(tgtRaw)
	return QoSDelta{BaselineDSCPs: bd, TargetDSCPs: td, Changed: !slices.Equal(bd, td)}
}

func diffSIP(base, tgt netorch.SIPSummary) *SIPDiff {
	if !base.Present && !tgt.Present {
		return nil
	}
	d := &SIPDiff{Present: true}
	if base.QualityAnalysis != nil {
		d.BaselineScore = model.Round(base.QualityAnalysis.OverallScore, 2)
	}
	if tgt.QualityAnalysis != nil {
		d.TargetScore = model.Round(tgt.QualityAnalysis.OverallScore, 2)
	}
	d.ScoreDelta = model.Round(d.TargetScore-d.BaselineScore, 2)
	if base.MOSAnalysis != nil {
		d.BaselineMOS = model.Round(base.MOSAnalysis.AverageMOS, 2)
	}
	if tgt.MOSAnalysis != nil {
		d.TargetMOS = model.Round(tgt.MOSAnalysis.AverageMOS, 2)
	}
	d.MOSDelta = model.Round(d.TargetMOS-d.BaselineMOS, 2)
	if base.MediaClipping != nil {
		d.BaselineClippingMS = model.Round(base.MediaClipping.MaxDelayMS, 2)
	}
	if tgt.MediaClipping != nil {
		d.TargetClippingMS = model.Round(tgt.MediaClipping.MaxDelayMS, 2)
	}
	d.ClippingDelayDeltaMS = model.Round(d.TargetClippingMS-d.BaselineClippingMS, 2)
	if base.DTMFEvents != nil {
		d.BaselineDTMF = base.DTMFEvents.Digits
	}
	if tgt.DTMFEvents != nil {
		d.TargetDTMF = tgt.DTMFEvents.Digits
	}
	d.Changed = math.Abs(d.ScoreDelta) > 0.01 || math.Abs(d.MOSDelta) > 0.01 || math.Abs(d.ClippingDelayDeltaMS) > 0.01 || d.BaselineDTMF != d.TargetDTMF
	return d
}

func buildHighlights(
	statusDelta string, statusChanged bool,
	protoAdded, protoRemoved []string,
	issAdded, issResolved []IssueDelta,
	tlsD TLSDelta, tcpD TCPMTUDelta, qosD QoSDelta, sipD *SIPDiff,
) []string {
	var h []string
	if statusChanged {
		h = append(h, "Overall status changed: "+statusDelta)
	}
	if len(protoAdded) > 0 {
		h = append(h, "Protocols added: "+strings.Join(protoAdded, ", "))
	}
	if len(protoRemoved) > 0 {
		h = append(h, "Protocols removed: "+strings.Join(protoRemoved, ", "))
	}
	if len(issAdded) > 0 {
		codes := make([]string, 0, len(issAdded))
		for _, i := range issAdded {
			codes = append(codes, i.Code)
		}
		h = append(h, fmt.Sprintf("%d new issue(s): %s", len(issAdded), strings.Join(codes, ", ")))
	}
	if len(issResolved) > 0 {
		codes := make([]string, 0, len(issResolved))
		for _, i := range issResolved {
			codes = append(codes, i.Code)
		}
		h = append(h, fmt.Sprintf("%d issue(s) resolved: %s", len(issResolved), strings.Join(codes, ", ")))
	}
	if tlsD.Changed {
		h = append(h, fmt.Sprintf("TLS changed (versions %v -> %v, ciphers %v -> %v)", tlsD.BaselineVersions, tlsD.TargetVersions, tlsD.BaselineCiphers, tlsD.TargetCiphers))
	}
	if tcpD.Changed {
		h = append(h, fmt.Sprintf("TCP MSS changed (%v -> %v)", tcpD.BaselineMSS, tcpD.TargetMSS))
	}
	if qosD.Changed {
		h = append(h, fmt.Sprintf("QoS DSCP changed (%v -> %v)", qosD.BaselineDSCPs, qosD.TargetDSCPs))
	}
	if sipD != nil && sipD.Changed {
		h = append(h, fmt.Sprintf("VoIP delta (score %.1f -> %.1f, MOS %.2f -> %.2f)", sipD.BaselineScore, sipD.TargetScore, sipD.BaselineMOS, sipD.TargetMOS))
	}
	if h == nil {
		return []string{}
	}
	return h
}

func buildDiffVerdict(statusDelta string, added, resolved []IssueDelta, highlights []string) string {
	if len(highlights) == 0 {
		return fmt.Sprintf("No behavioral differences detected (%s).", statusDelta)
	}
	return fmt.Sprintf("Status %s: %d new issue(s), %d resolved (%d change highlight(s)).", statusDelta, len(added), len(resolved), len(highlights))
}
