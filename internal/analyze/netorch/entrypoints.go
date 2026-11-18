// Package netorch provides high-level VPN, routing, audit, convergence, and data-plane wrappers.
package netorch

import (
	"context"
	"slices"

	"github.com/zombat/sonic/internal/analyze/convergence"
	"github.com/zombat/sonic/internal/model"
)

// AnalyzeVPNCapture runs ipsec, gre_nhrp, and dmvpn_phase3 and lifts VPN verdicts to top level.
func AnalyzeVPNCapture(ctx context.Context, filePath string, opts Options) VPNReport {
	opts.Detectors = VPNDetectors
	f := false
	opts.IncludeSIP = &f
	built := analyzeInternal(ctx, filePath, opts)
	if built.report.Status != "success" {
		return VPNReport{NetworkBody: built.report.NetworkBody}
	}
	ipsecRep := built.sections.ipsec
	greRep := built.sections.greNHRP
	overlay := ""
	if greRep != nil {
		overlay = greRep.Verdict
		if greRep.Status == model.StatusNotPresent && ipsecRep != nil && ipsecRep.Summary.ESPPackets > 0 {
			overlay = "No GRE or NHRP visible: with tunnel protection, GRE and NHRP travel inside ESP. Capture on the tunnel interface to see the DMVPN overlay."
		}
	}
	diags := []IKEDiagnosis{}
	if ipsecRep != nil {
		for _, sa := range ipsecRep.IKESAs {
			d := sa.Diagnosis
			diags = append(diags, IKEDiagnosis{
				Initiator: sa.Initiator, Responder: sa.Responder,
				InitiatorSPI: sa.InitiatorSPI, Outcome: sa.Outcome, Diagnosis: d,
			})
		}
	}
	p3 := ""
	if built.sections.dmvpn != nil {
		p3 = built.sections.dmvpn.Verdict
	}
	encVerdict, verdict, negVerdict := "", "", ""
	if ipsecRep != nil {
		encVerdict, verdict, negVerdict = ipsecRep.EncryptionVerdict, ipsecRep.Verdict, ipsecRep.NegotiationVerdict
	}
	return VPNReport{
		EncryptionVerdict:  encVerdict,
		Verdict:            verdict,
		NegotiationVerdict: negVerdict,
		OverlayVerdict:     overlay,
		Phase3Verdict:      p3,
		IKEDiagnoses:       diags,
		NetworkBody:        built.report.NetworkBody,
	}
}

// AnalyzeRoutingCapture runs routing and reachability detectors with lifted failover timeline and outages.
func AnalyzeRoutingCapture(ctx context.Context, filePath string, opts Options) RoutingReport {
	opts.Detectors = RoutingDetectors
	f := false
	opts.IncludeSIP = &f
	built := analyzeInternal(ctx, filePath, opts)
	if built.report.Status != "success" {
		return RoutingReport{NetworkBody: built.report.NetworkBody}
	}
	rRep, reachRep := built.sections.routing, built.sections.reachability
	tl := []model.Event{}
	verdict := ""
	if rRep != nil {
		verdict = rRep.Verdict
		if len(rRep.FailoverTimeline) > 0 {
			tl = rRep.FailoverTimeline
		}
	}
	outages := []PingOutage{}
	rVerdict := ""
	if reachRep != nil {
		rVerdict = reachRep.Verdict
		for _, pair := range reachRep.Echo {
			for _, ow := range pair.Outages {
				outages = append(outages, PingOutage{Src: pair.Src, Dst: pair.Dst, OutageWindow: ow})
			}
		}
	}
	return RoutingReport{
		Verdict:             verdict,
		ReachabilityVerdict: rVerdict,
		FailoverTimeline:    tl,
		PingOutages:         outages,
		NetworkBody:         built.report.NetworkBody,
	}
}

// AuditCleartextCapture runs cleartext_audit (with gRPC credential enrichment) on one capture.
func AuditCleartextCapture(ctx context.Context, filePath string, opts Options) model.AuditReport {
	opts.Detectors = []string{"cleartext_audit"}
	f := false
	opts.IncludeSIP = &f
	built := analyzeInternal(ctx, filePath, opts)
	if built.report.Status != "success" {
		return model.AuditReport{Status: "error", Error: built.report.Error}
	}
	return *built.sections.cleartextAudit
}

// AnalyzeConvergenceCapture runs convergence correlation and returns ConvergenceReport.
func AnalyzeConvergenceCapture(ctx context.Context, filePath string, opts Options) ConvergenceReport {
	opts.Detectors = []string{"convergence"}
	f := false
	opts.IncludeSIP = &f
	built := analyzeInternal(ctx, filePath, opts)
	if built.report.Status != "success" {
		return ConvergenceReport{Status: "error", Error: built.report.Error}
	}
	c := built.sections.convergence
	if c == nil {
		return ConvergenceReport{Status: "error", Error: "convergence report missing"}
	}
	tl := c.Timeline
	if tl == nil {
		tl = []convergence.TimelineEntry{}
	}
	issues := c.Issues
	if issues == nil {
		issues = []model.Issue{}
	}
	cs := c.CannotShow
	if cs == nil {
		cs = []string{}
	}
	return ConvergenceReport{
		Status:           "success",
		Verdict:          c.Verdict,
		Driver:           c.Driver,
		FailedPeer:       c.FailedPeer,
		FailedPeerSource: c.FailedPeerSource,
		EventTime:        c.EventTime,
		EventT:           c.EventT,
		Measurements:     c.Measurements,
		Timeline:         tl,
		TimelineOmitted:  c.TimelineOmitted,
		TrafficShift:     c.TrafficShift,
		Issues:           issues,
		CannotShow:       cs,
		File:             built.report.File,
		Capture:          built.report.Capture,
		ProtocolsPresent: built.report.ProtocolsPresent,
	}
}

// AnalyzeDataPlaneCapture runs path_mtu, esp_overhead, tcp, tls, and qos with lifted verdicts.
func AnalyzeDataPlaneCapture(ctx context.Context, filePath string, opts Options) DataPlaneReport {
	opts.Detectors = slices.Clone(DataPlaneDetectors)
	f := false
	opts.IncludeSIP = &f
	built := analyzeInternal(ctx, filePath, opts)
	if built.report.Status != "success" {
		return DataPlaneReport{NetworkBody: built.report.NetworkBody}
	}
	v := built.report.Verdicts
	return DataPlaneReport{
		PathMTUVerdict:     v["path_mtu"],
		ESPOverheadVerdict: v["esp_overhead"],
		TCPVerdict:         v["tcp"],
		TLSVerdict:         v["tls"],
		QoSVerdict:         v["qos"],
		NetworkBody:        built.report.NetworkBody,
	}
}
