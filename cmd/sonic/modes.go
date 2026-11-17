// Package main wires deterministic network, gRPC, HTTP/RESTCONF, SNMP, AAA, ESP,
// and SIP quality CLI modes into internal/analyze and internal/report packages.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/zombat/sonic/internal/analyze/aaainspect"
	"github.com/zombat/sonic/internal/analyze/espdecrypt"
	"github.com/zombat/sonic/internal/analyze/grpc"
	"github.com/zombat/sonic/internal/analyze/httpinspect"
	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/sip"
	"github.com/zombat/sonic/internal/analyze/snmpinspect"
	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/report"
)

func runNetwork(ctx context.Context, o cliOptions, detectors []string, stdout, stderr io.Writer) int {
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
		DetectorOpts:  detOpts,
	})
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	var saveErr error
	if o.saveFile != "" {
		saveErr = report.SaveNetworkReport(rep, o.saveFile)
	}
	return finishReport(raw, merr, saveErr, o.saveFile != "", report.FormatNetworkSummary(rep), o.asJSON, stdout, stderr)
}

func runGRPC(ctx context.Context, o cliOptions, stdout, stderr io.Writer) int {
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
	var saveErr error
	if o.saveFile != "" {
		saveErr = report.SaveGRPCReport(rep, o.saveFile)
	}
	return finishReport(raw, merr, saveErr, o.saveFile != "", report.FormatGRPCSummary(rep), o.asJSON, stdout, stderr)
}

func runHTTP(ctx context.Context, o cliOptions, stdout, stderr io.Writer) int {
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
	var saveErr error
	if o.saveFile != "" {
		saveErr = report.SaveHTTPReport(rep, o.saveFile)
	}
	return finishReport(raw, merr, saveErr, o.saveFile != "", report.FormatHTTPSummary(rep), o.asJSON, stdout, stderr)
}

func runSNMP(ctx context.Context, o cliOptions, stdout, stderr io.Writer) int {
	rep := snmpinspect.AnalyzeCapture(ctx, o.file, snmpinspect.Options{
		UsersFile:     o.snmpUsers,
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
	})
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	var saveErr error
	if o.saveFile != "" {
		saveErr = report.SaveSNMPReport(rep, o.saveFile)
	}
	return finishReport(raw, merr, saveErr, o.saveFile != "", report.FormatSNMPSummary(rep), o.asJSON, stdout, stderr)
}

func runAAA(ctx context.Context, o cliOptions, stdout, stderr io.Writer) int {
	rep := aaainspect.AnalyzeCapture(ctx, o.file, aaainspect.Options{
		KeysFile:      o.aaaSecrets,
		DisplayFilter: o.displayFilter,
		MaxPackets:    positiveIntPtr(o.maxPackets),
	})
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	var saveErr error
	if o.saveFile != "" {
		saveErr = report.SaveAAAReport(rep, o.saveFile)
	}
	return finishReport(raw, merr, saveErr, o.saveFile != "", report.FormatAAASummary(rep), o.asJSON, stdout, stderr)
}

func runESP(ctx context.Context, o cliOptions, detectors []string, stdout, stderr io.Writer) int {
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
	var saveErr error
	if o.saveFile != "" {
		saveErr = report.SaveESPReport(rep, o.saveFile)
	}
	return finishReport(raw, merr, saveErr, o.saveFile != "", report.FormatESPSummary(rep), o.asJSON, stdout, stderr)
}

func runQualityOnly(ctx context.Context, o cliOptions, stdout, stderr io.Writer) int {
	rep := sip.QuickQualityCheck(ctx, o.file)
	raw, merr := json.MarshalIndent(rep, "", "  ")
	if rep.Status != "success" {
		return writeFailure(rep.Error, raw, merr, o.asJSON, stdout, stderr)
	}
	summary := fmt.Sprintf("File: %s | Quality Grade: %s (%.1f/100) | MOS: %.2f (%s)\n",
		rep.File, rep.QualityAnalysis.Grade, rep.QualityAnalysis.OverallScore,
		rep.MOSAnalysis.AverageMOS, rep.MOSAnalysis.OverallCategory)
	return finishReport(raw, merr, nil, false, summary, o.asJSON, stdout, stderr)
}

func finishReport(raw []byte, merr, saveErr error, wantSave bool, summary string, asJSON bool, stdout, stderr io.Writer) int {
	if wantSave && saveErr != nil {
		fmt.Fprintf(stderr, "failed to save report: %s\n", redact.RedactText(saveErr.Error()))
	}
	if asJSON {
		return writeJSONBytes(stdout, stderr, raw, merr)
	}
	fmt.Fprint(stdout, summary)
	return 0
}

func writeFailure(errMsg string, raw []byte, err error, asJSON bool, stdout, stderr io.Writer) int {
	if asJSON {
		_ = writeJSONBytes(stdout, stderr, raw, err)
	} else {
		fmt.Fprintln(stderr, redact.RedactText(errMsg))
	}
	return 1
}
