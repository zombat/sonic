// Package grpc validates capture inputs and assembles final sonic.grpc_report/1 outputs.
package grpc

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

func errReport(msg string) Report {
	return Report{Status: "error", Error: msg}
}

func validateInputs(filePath string, opts Options) ([]string, int, *Report) {
	if filePath == "" {
		r := errReport("File not found: " + filePath)
		return nil, 0, &r
	}
	info, err := os.Stat(filePath)
	if err != nil {
		r := errReport("File not found: " + filePath)
		return nil, 0, &r
	}
	if info.IsDir() {
		r := errReport("File not readable: " + filePath)
		return nil, 0, &r
	}
	if f, err := os.Open(filePath); err != nil {
		r := errReport("File not readable: " + filePath)
		return nil, 0, &r
	} else {
		_ = f.Close()
	}
	if !tshark.Available("") {
		r := errReport("gRPC analysis needs tshark (Wireshark's HTTP/2, HPACK and gRPC dissectors); install it")
		return nil, 0, &r
	}
	if opts.KeylogFile != "" {
		kInfo, kErr := os.Stat(opts.KeylogFile)
		if kErr != nil || !kInfo.Mode().IsRegular() {
			r := errReport("keylog_file is not a readable file")
			return nil, 0, &r
		}
		if kf, oErr := os.Open(opts.KeylogFile); oErr != nil {
			r := errReport("keylog_file is not a readable file")
			return nil, 0, &r
		} else {
			_ = kf.Close()
		}
	}
	if opts.MaxPackets != nil && *opts.MaxPackets <= 0 {
		r := errReport("max_packets must be a positive number")
		return nil, 0, &r
	}
	for _, p := range opts.Ports {
		if p < 1 || p > 65535 {
			r := errReport(fmt.Sprintf("Not a TCP port: %d", p))
			return nil, 0, &r
		}
	}
	protoDirs := ResolveProtoPaths(opts.ProtoPaths, opts.IgnoreDefaultProtoDir)
	for _, dir := range protoDirs {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			r := errReport("proto path is not a directory: " + dir)
			return nil, 0, &r
		}
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = 25
	}
	return protoDirs, maxItems, nil
}

func assembleGrpcReport(
	ctx context.Context,
	filePath string,
	opts Options,
	verdict string,
	startPtr, endPtr *float64,
	packets int,
	decodeAs []string,
	reasons map[int]string,
	secrets secretsInfo,
	reread []RereadRow,
	protoDirs []string,
	statusMeta, extStatus map[string]string,
	allConns, listedConns []ConnectionRow,
	connsOmitted int,
	allRPCs, listedRPCs []RPCRow,
	rpcsOmitted int,
	credentials []CredentialFinding,
	statusCounts map[string]int,
	coverage *TLSDecryptionSummary,
	issues []model.Issue,
	events []model.Event,
	maxItems int,
) Report {
	listedEvents, eventsOmitted := sortAndCapEvents(events, maxItems*8)

	decArgs := []string{}
	for _, opt := range decodeAs {
		if opt != "-d" {
			decArgs = append(decArgs, opt)
		}
	}
	decReasons := make(map[string]string, len(reasons))
	for p, r := range reasons {
		decReasons[fmt.Sprintf("tcp/%d", p)] = r
	}
	warnings := []string{}
	for _, key := range []string{"tls_error", "reread_error"} {
		if w := statusMeta[key]; w != "" {
			warnings = append(warnings, w)
		}
	}
	if pe := extStatus["parse_error"]; pe != "" {
		warnings = append(warnings, pe)
	}
	for _, r := range reread {
		flowStr := "None"
		if r.Flow != nil {
			flowStr = *r.Flow
		}
		warnings = append(warnings, fmt.Sprintf("tcp.stream %d (%s) read again without out-of-order reassembly: TShark 3.6 left it undecoded with it (a gap its retransmission did not fill)", r.TCPStream, flowStr))
	}
	warnings = append(warnings, protobufWarnings(extStatus["stderr"])...)
	var dfPtr *string
	if opts.DisplayFilter != "" {
		df := opts.DisplayFilter
		dfPtr = &df
	}
	clearCreds := 0
	for _, c := range credentials {
		if c.Cleartext {
			clearCreds++
		}
	}
	return Report{
		Status:        "success",
		Schema:        ReportSchema,
		File:          filePath,
		OverallStatus: model.StatusFromIssues(issues, len(allConns) > 0),
		Verdict:       verdict,
		Capture: CaptureInfo{
			Start:           model.ISOTime(startPtr),
			End:             model.ISOTime(endPtr),
			HTTP2Packets:    packets,
			TShark:          tshark.VersionString(ctx, ""),
			DecodeAs:        decArgs,
			DecodeAsReasons: decReasons,
			KeylogFileGiven: opts.KeylogFile != "",
			TLSSecrets: TLSSecretsSummary{
				Source:                        secrets.Source,
				KeyLogFile:                    secrets.KeyLogFile,
				PCAPNGDecryptionSecretsBlocks: secrets.PCAPNGBlocks,
				SessionsInKeyLog:              secrets.SessionsInKeyLog,
				SessionsInPCAPNG:              secrets.SessionsInPCAPNG,
			},
			RereadWithoutOutOfOrder: reread,
			ProtoPaths:              protoDirs,
			DisplayFilter:           dfPtr,
			MaxPackets:              opts.MaxPackets,
			Warnings:                warnings,
		},
		Summary: Summary{
			Connections:          len(allConns),
			RPCs:                 len(allRPCs),
			RPCStatus:            statusCounts,
			CleartextCredentials: clearCreds,
		},
		Connections:        listedConns,
		ConnectionsOmitted: connsOmitted,
		RPCs:               listedRPCs,
		RPCsOmitted:        rpcsOmitted,
		Credentials:        credentials,
		TLSDecryption:      coverage,
		Issues:             model.SortIssues(issues),
		Timeline:           listedEvents,
		TimelineOmitted:    eventsOmitted,
		Limits:             slices.Clone(Limits),
	}
}

func sortAndCapEvents(events []model.Event, limit int) ([]model.Event, int) {
	slices.SortStableFunc(events, func(a, b model.Event) int {
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
	listed, omitted := model.Cap(events, limit)
	if listed == nil {
		listed = []model.Event{}
	}
	return listed, omitted
}

func protobufWarnings(stderr string) []string {
	var out []string
	for _, ln := range strings.Split(stderr, "\n") {
		if strings.Contains(ln, "Protobuf") && (strings.Contains(ln, "failed") || strings.Contains(ln, "does not exist")) {
			s := strings.TrimSpace(ln)
			if len(s) > 300 {
				s = s[:300]
			}
			out = append(out, s)
			if len(out) >= 10 {
				break
			}
		}
	}
	return out
}

func undecodedStreams(analysis *grpcAnalysis, disc map[int]*extract.TCPConnection, wanted map[int]bool, secretsGiven bool) []int {
	var out []int
	for idx := range wanted {
		if disc[idx].IsTLS() && !secretsGiven {
			continue
		}
		c := analysis.conns[idx]
		if c == nil || c.packetsClient == 0 || c.packetsServer == 0 {
			out = append(out, idx)
		}
	}
	slices.Sort(out)
	return out
}

func mapsCloneBool(src map[string]bool) map[string]bool {
	out := make(map[string]bool, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
