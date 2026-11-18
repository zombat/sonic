// Package main wires deterministic network, gRPC, HTTP/RESTCONF, SNMP, AAA, ESP,
// and SIP quality CLI modes into internal/analyze and internal/report packages.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/analyze/aaainspect"
	"github.com/zombat/sonic/internal/analyze/audit"
	"github.com/zombat/sonic/internal/analyze/espdecrypt"
	"github.com/zombat/sonic/internal/analyze/grpc"
	"github.com/zombat/sonic/internal/analyze/httpinspect"
	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/analyze/snmpinspect"
	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/report"
)

func runNetwork(ctx context.Context, o cliOptions, detectors []string, stdin io.Reader, stdout, stderr io.Writer) int {
	sincePtr, untilPtr, ok := parseWindowBounds(o.sinceStr, o.untilStr, stderr)
	if !ok {
		return 2
	}
	var detOpts netorch.DetectorOptions
	if o.allowCSV != "" {
		if !slices.Contains(detectors, "cleartext_audit") {
			fmt.Fprintln(stderr, "--allow needs --detectors cleartext_audit")
			return 1
		}
		detOpts.CleartextAudit = &netorch.AuditOption{HasAllow: true, Allow: splitCSV(o.allowCSV)}
	}
	rep := netorch.AnalyzeNetworkCapture(ctx, o.file, netorch.Options{
		Detectors:     detectors,
		Peers:         splitCSV(o.peersCSV),
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
		Since:         sincePtr,
		Until:         untilPtr,
		FastPath:      o.fastPath,
		DetectorOpts:  detOpts,
	})
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	savePath := effectiveSavePath(o, ".network.md")
	var saveErr error
	if savePath != "" && !isHTMLPath(savePath) {
		saveErr = report.SaveNetworkReport(rep, savePath)
	}
	return deliverArtifacts(raw, merr, savePath, saveErr, "S.O.N.I.C. Network Analysis", o.file, report.FormatNetworkSummary(rep), o, stdin, stdout, stderr)
}

func runGRPC(ctx context.Context, o cliOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	rep := grpc.AnalyzeCapture(ctx, o.file, grpc.Options{
		KeylogFile:    o.tlsSecretsLog,
		ProtoPaths:    o.protoPaths,
		Ports:         parsePortCSV(o.grpcPorts),
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
	})
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	savePath := effectiveSavePath(o, ".grpc.md")
	var saveErr error
	if savePath != "" && !isHTMLPath(savePath) {
		saveErr = report.SaveGRPCReport(rep, savePath)
	}
	return deliverArtifacts(raw, merr, savePath, saveErr, "S.O.N.I.C. gRPC Analysis", o.file, report.FormatGRPCSummary(rep), o, stdin, stdout, stderr)
}

func runHTTP(ctx context.Context, o cliOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	rep := httpinspect.AnalyzeCapture(ctx, o.file, httpinspect.Options{
		KeylogFile:    o.tlsSecretsLog,
		Ports:         parsePortCSV(o.httpPorts),
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
	})
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	savePath := effectiveSavePath(o, ".restconf.md")
	var saveErr error
	if savePath != "" && !isHTMLPath(savePath) {
		saveErr = report.SaveHTTPReport(rep, savePath)
	}
	return deliverArtifacts(raw, merr, savePath, saveErr, "S.O.N.I.C. RESTCONF/HTTP Analysis", o.file, report.FormatHTTPSummary(rep), o, stdin, stdout, stderr)
}

func runSNMP(ctx context.Context, o cliOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	rep := snmpinspect.AnalyzeCapture(ctx, o.file, snmpinspect.Options{
		UsersFile:     o.snmpUsers,
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
	})
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	savePath := effectiveSavePath(o, ".snmp.md")
	var saveErr error
	if savePath != "" && !isHTMLPath(savePath) {
		saveErr = report.SaveSNMPReport(rep, savePath)
	}
	return deliverArtifacts(raw, merr, savePath, saveErr, "S.O.N.I.C. SNMP Analysis", o.file, report.FormatSNMPSummary(rep), o, stdin, stdout, stderr)
}

func runAAA(ctx context.Context, o cliOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	rep := aaainspect.AnalyzeCapture(ctx, o.file, aaainspect.Options{
		KeysFile:      o.aaaSecrets,
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
	})
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	savePath := effectiveSavePath(o, ".aaa.md")
	var saveErr error
	if savePath != "" && !isHTMLPath(savePath) {
		saveErr = report.SaveAAAReport(rep, savePath)
	}
	return deliverArtifacts(raw, merr, savePath, saveErr, "S.O.N.I.C. AAA Analysis", o.file, report.FormatAAASummary(rep), o, stdin, stdout, stderr)
}

func runESP(ctx context.Context, o cliOptions, detectors []string, stdin io.Reader, stdout, stderr io.Writer) int {
	rep := espdecrypt.AnalyzeCapture(ctx, o.file, espdecrypt.Options{
		SAFile:        o.espSA,
		Detectors:     detectors,
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
	})
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	savePath := effectiveSavePath(o, ".esp.md")
	var saveErr error
	if savePath != "" && !isHTMLPath(savePath) {
		saveErr = report.SaveESPReport(rep, savePath)
	}
	return deliverArtifacts(raw, merr, savePath, saveErr, "S.O.N.I.C. ESP Decryption", o.file, report.FormatESPSummary(rep), o, stdin, stdout, stderr)
}

func effectiveSavePath(o cliOptions, defaultSuffix string) string {
	if o.saveFile != "" {
		return o.saveFile
	}
	if !o.asJSON && !o.tuiMode && o.htmlPath == "" && o.file != "" {
		return o.file + defaultSuffix
	}
	return ""
}

func runQualityOnly(ctx context.Context, o cliOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	rep := sip.QuickQualityCheck(ctx, o.file)
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	var saveErr error
	if o.saveFile != "" && !isHTMLPath(o.saveFile) {
		saveErr = report.SaveQualityReport(rep, o.saveFile)
	}
	summary := fmt.Sprintf("File: %s | Quality Grade: %s (%.1f/100) | MOS: %.2f (%s)\n",
		rep.File, rep.QualityAnalysis.Grade, rep.QualityAnalysis.OverallScore,
		rep.MOSAnalysis.AverageMOS, rep.MOSAnalysis.OverallCategory)
	return deliverArtifacts(raw, merr, o.saveFile, saveErr, "S.O.N.I.C. VoIP Quality", o.file, summary, o, stdin, stdout, stderr)
}

func writeFailure(errMsg string, raw []byte, err error, asJSON bool, stdout, stderr io.Writer) int {
	if asJSON {
		_ = writeJSONBytes(stdout, stderr, raw, err)
	} else {
		fmt.Fprintln(stderr, redact.RedactText(errMsg))
	}
	return 1
}

func runAudit(ctx context.Context, o cliOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	detectors := splitCSV(o.detectorsCSV)
	if len(detectors) == 0 {
		detectors = []string{"cleartext_audit"}
	}
	if !slices.Contains(detectors, "cleartext_audit") {
		if o.allowCSV != "" {
			fmt.Fprintln(stderr, "--allow needs --detectors cleartext_audit")
			return 1
		}
		fmt.Fprintf(stderr, "unsupported stage 1 detector(s): %s\n", strings.Join(detectors, ","))
		return 1
	}
	rep, err := audit.AuditCleartextCapture(ctx, audit.AuditOptions{
		FilePath:      o.file,
		Allow:         splitCSV(o.allowCSV),
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
	})
	if err != nil {
		rep.Error = redact.RedactText(rep.Error)
		if o.asJSON {
			b, merr := json.MarshalIndent(rep, "", "  ")
			_ = writeJSONBytes(stdout, stderr, b, merr)
		} else {
			fmt.Fprintln(stderr, redact.RedactText(err.Error()))
		}
		return 1
	}
	b, merr := json.MarshalIndent(rep, "", "  ")
	return deliverArtifacts(b, merr, o.saveFile, nil, "S.O.N.I.C. Cleartext Audit", o.file, rep.Verdict+"\n", o, stdin, stdout, stderr)
}
