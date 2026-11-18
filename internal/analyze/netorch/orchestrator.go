// Package netorch runs selected S.O.N.I.C. detectors once over tshark records and merges their findings.
package netorch

import (
	"context"

	"github.com/zombat/sonic/internal/analyze/audit"
	"github.com/zombat/sonic/internal/analyze/convergence"
	"github.com/zombat/sonic/internal/analyze/dmvpn"
	"github.com/zombat/sonic/internal/analyze/espoverhead"
	"github.com/zombat/sonic/internal/analyze/grenhrp"
	"github.com/zombat/sonic/internal/analyze/ipsec"
	"github.com/zombat/sonic/internal/analyze/pathmtu"
	"github.com/zombat/sonic/internal/analyze/qos"
	"github.com/zombat/sonic/internal/analyze/reach"
	"github.com/zombat/sonic/internal/analyze/routing"
	"github.com/zombat/sonic/internal/analyze/tcphealth"
	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

type sectionOutputs struct {
	ipsec          *ipsec.Report
	greNHRP        *grenhrp.Report
	dmvpn          *dmvpn.Report
	routing        *routing.Report
	reachability   *reach.ReachReport
	pathMTU        *pathmtu.Report
	espOverhead    *espoverhead.Report
	tcp            *tcphealth.Report
	tls            *tlsinspect.Report
	qos            *qos.Report
	conversations  *reach.ConversationsReport
	cleartextAudit *model.AuditReport
	convergence    *convergence.Report
}

type detectorSet struct {
	ipsec          *ipsec.Detector
	greNHRP        *grenhrp.Detector
	dmvpn          *dmvpn.Detector
	routing        *routing.Detector
	reachability   *reach.ReachabilityDetector
	pathMTU        *pathmtu.PathMtuDetector
	espOverhead    *espoverhead.Detector
	tcp            *tcphealth.Detector
	tls            *tlsinspect.Detector
	qos            *qos.QosDetector
	conversations  *reach.ConversationDetector
	cleartextAudit *audit.Detector
	convergence    *convergence.Detector
}

func buildDetectors(names []string, opts Options) (detectorSet, error) {
	var ds detectorSet
	d := opts.DetectorOpts
	for _, name := range names {
		switch name {
		case "ipsec":
			ds.ipsec = ipsec.NewDetector(opts.Peers)
		case "gre_nhrp":
			ds.greNHRP = grenhrp.NewDetector()
		case "dmvpn_phase3":
			ds.dmvpn = dmvpn.NewDetector(d.DMVPNHubs)
		case "routing":
			ds.routing = routing.NewDetector(d.RoutingMSS)
		case "reachability":
			ds.reachability = reach.NewReachabilityDetector()
		case "path_mtu":
			ds.pathMTU = pathmtu.NewPathMtuDetector()
		case "esp_overhead":
			var eo espoverhead.Options
			if d.EspOverhead != nil {
				eo = *d.EspOverhead
			}
			ds.espOverhead = espoverhead.NewDetector(eo)
		case "tcp":
			ds.tcp = tcphealth.NewDetector()
		case "tls":
			ds.tls = tlsinspect.NewDetector(d.TLSBaseline)
		case "qos":
			ds.qos = qos.NewQosDetector()
		case "conversations":
			ds.conversations = reach.NewConversationDetector()
		case "cleartext_audit":
			var allow []string
			if d.CleartextAudit != nil && d.CleartextAudit.HasAllow {
				allow = d.CleartextAudit.Allow
			}
			det, err := audit.NewDetector(allow)
			if err != nil {
				return ds, err
			}
			ds.cleartextAudit = det
		case "convergence":
			var co convergence.Options
			if d.Convergence != nil {
				co = *d.Convergence
			}
			ds.convergence = convergence.NewDetector(co)
		}
	}
	return ds, nil
}

func (ds *detectorSet) feed(rec *model.Record) {
	if ds.ipsec != nil {
		ds.ipsec.Feed(rec)
	}
	if ds.greNHRP != nil {
		ds.greNHRP.Feed(rec)
	}
	if ds.dmvpn != nil {
		ds.dmvpn.Feed(rec)
	}
	if ds.routing != nil {
		ds.routing.Feed(rec)
	}
	if ds.reachability != nil {
		ds.reachability.Feed(rec)
	}
	if ds.pathMTU != nil {
		ds.pathMTU.Feed(rec)
	}
	if ds.espOverhead != nil {
		ds.espOverhead.Feed(rec)
	}
	if ds.tcp != nil {
		ds.tcp.Feed(rec)
	}
	if ds.tls != nil {
		ds.tls.Feed(rec)
	}
	if ds.qos != nil {
		ds.qos.Feed(rec)
	}
	if ds.conversations != nil {
		ds.conversations.Feed(rec)
	}
	if ds.cleartextAudit != nil {
		ds.cleartextAudit.Feed(rec)
	}
	if ds.convergence != nil {
		ds.convergence.Feed(rec)
	}
}

type builtReport struct {
	report   NetworkReport
	sections sectionOutputs
}

// AnalyzeNetworkCapture runs selected deterministic detectors in a single pass and returns NetworkReport.
func AnalyzeNetworkCapture(ctx context.Context, filePath string, opts Options) NetworkReport {
	return analyzeInternal(ctx, filePath, opts).report
}

func analyzeInternal(ctx context.Context, filePath string, opts Options) builtReport {
	names, maxItems, invalid := validateOptions(filePath, opts)
	if invalid != nil {
		return builtReport{report: *invalid}
	}

	var recordsOut model.RecordsOutput
	var err error
	useFast := len(opts.SNMPPorts) == 0 && (opts.FastPath == "always" || (opts.FastPath != "never" && extract.CanUseFastPath(names, opts.DisplayFilter)))
	if useFast {
		recordsOut, err = extract.OpenFastPathRecords(filePath, extract.FastPathOptions{
			MaxPackets: opts.MaxPackets,
			Since:      opts.Since,
			Until:      opts.Until,
		})
	} else {
		recordsOut, err = extract.OpenNetworkRecords(ctx, tshark.StreamOptions{
			FilePath:      filePath,
			DisplayFilter: opts.DisplayFilter,
			MaxPackets:    opts.MaxPackets,
			Since:         opts.Since,
			Until:         opts.Until,
			DecodeAs:      audit.SNMPDecodeAs(opts.SNMPPorts),
		})
	}
	if err != nil {
		return builtReport{report: errNetworkReport(err.Error())}
	}

	ds, err := buildDetectors(names, opts)
	if err != nil {
		return builtReport{report: errNetworkReport(err.Error())}
	}

	totalBytes := 0
	var startPtr, endPtr *float64
	sipSeen := false
	for i := range recordsOut.Records {
		rec := &recordsOut.Records[i]
		totalBytes += rec.Len
		if rec.T != 0 {
			tv := rec.T
			if startPtr == nil || tv < *startPtr {
				v := tv
				startPtr = &v
			}
			if endPtr == nil || tv > *endPtr {
				v := tv
				endPtr = &v
			}
		}
		if rec.SIP != nil && *rec.SIP {
			sipSeen = true
		}
		ds.feed(rec)
	}

	var durPtr *float64
	if startPtr != nil && endPtr != nil {
		d := model.Round(*endPtr-*startPtr, 3)
		durPtr = &d
	}
	var dfPtr *string
	if opts.DisplayFilter != "" {
		s := opts.DisplayFilter
		dfPtr = &s
	}
	missingFields := []string{}
	if len(recordsOut.MissingFields) > 0 {
		missingFields = recordsOut.MissingFields
	}
	warnings := []string{}
	if len(recordsOut.Warnings) > 0 {
		warnings = recordsOut.Warnings
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
		MissingTsharkFields: missingFields,
		Warnings:            warnings,
	}
	families := extract.DetectFamilies(recordsOut.Records)
	mCtx := model.Context{Start: startPtr, End: endPtr, MaxItems: maxItems}

	return collectReport(ctx, filePath, opts, names, maxItems, ds, capInfo, families, mCtx, sipSeen)
}
