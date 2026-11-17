// Package httpinspect implements HTTP/1.1, HTTP/2, and RESTCONF capture troubleshooting.
package httpinspect

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

// HTTPStatusHints maps common HTTP/RESTCONF failure status codes to troubleshooting guidance.
var HTTPStatusHints = map[int]string{
	400: "the server rejected the request as malformed (bad JSON/XML, a bad path or value)",
	401: "the server refused the credentials: check the Authorization header or the account",
	403: "the credentials were accepted but this user may not touch this resource (RESTCONF NACM, or an ACL)",
	404: "the target has no such resource (a wrong path, or a data node that is not configured)",
	405: "the method is not allowed on this resource (RESTCONF allows GET/POST/PUT/PATCH/DELETE per node)",
	409: "a conflict: the resource already exists (POST) or was changed by someone else",
	412: "a precondition failed (an If-Match/If-Unmodified-Since on a RESTCONF datastore)",
	415: "the server does not accept this Content-Type (RESTCONF wants application/yang-data+json or +xml)",
	429: "the server is rate limiting",
	500: "the server hit an internal error; read the error body and the device logs",
	501: "the server does not implement this (a RESTCONF capability or method it does not support)",
	503: "the server is unavailable or overloaded (transient); retry with backoff",
}

// Limits documents capture-vantage constraints for HTTP/RESTCONF/TLS inspection.
var Limits = []string{
	"TLS-wrapped RESTCONF/REST without a key log (or TLS secrets embedded in a pcapng) shows only the handshake: no method, path, status or body. In TLS 1.3 the certificate is encrypted too.",
	"A session's secret is matched by its ClientHello random: a session whose ClientHello is not in the capture cannot be decrypted, whatever the key log holds.",
	"A capture that begins mid-connection may leave an HTTP/2 request without its method or path (HPACK state missing) or an HTTP/1.1 body unreassembled.",
	"Only RESTCONF error documents are parsed from a body; a successful GET's configuration is never decoded (its Content-Type and size are reported).",
	"Credential values are never shown: an Authorization scheme is kept, the credential is masked, and Cookie, token and CSRF headers are flagged by name only.",
	"RESTCONF event-stream notifications (text/event-stream) are reported as a long-lived GET; their contents are not decoded.",
}

func errReport(msg string) Report {
	return Report{Status: "error", Error: msg}
}

func validateInputs(filePath string, opts Options) (map[int]bool, int, *Report) {
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
		r := errReport("RESTCONF/REST analysis needs tshark (Wireshark's HTTP, HTTP/2 and TLS dissectors); install it")
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
	extraSet := make(map[int]bool, len(opts.Ports))
	for _, p := range opts.Ports {
		if p < 1 || p > 65535 {
			r := errReport(fmt.Sprintf("Not a TCP port: %d", p))
			return nil, 0, &r
		}
		extraSet[p] = true
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = 25
	}
	return extraSet, maxItems, nil
}

// AnalyzeCapture runs RESTCONF and REST analysis over HTTP/1.1, HTTP/2, and TLS in one capture.
func AnalyzeCapture(ctx context.Context, filePath string, opts Options) Report {
	extraSet, maxItems, invalid := validateInputs(filePath, opts)
	if invalid != nil {
		return *invalid
	}

	disc, err := extract.Discover(ctx, filePath, opts.DisplayFilter, opts.MaxPackets, map[string]string{}, opts.Ports)
	if err != nil {
		return errReport(err.Error())
	}
	secrets := secretsView(filePath, opts.KeylogFile)
	secretsGiven := secrets.Source != nil
	decodeAs, reasons := extract.PlanHTTPDecodeAs(disc, opts.Ports)

	wanted := make(map[int]bool)
	anyTLS := false
	for idx, conn := range disc {
		if conn.IsTLS() {
			anyTLS = true
		}
		if carriesHTTP(conn, extraSet) {
			wanted[idx] = true
		}
	}

	secretValues := make(map[string]bool)
	var messages []extract.HTTPMessage
	http1, h1Secrets, err := extract.HTTP1Messages(ctx, filePath, decodeAs, opts.KeylogFile, opts.DisplayFilter, opts.MaxPackets, true)
	if err != nil {
		return errReport(err.Error())
	}
	for s := range h1Secrets {
		secretValues[s] = true
	}
	for _, m := range http1 {
		if wanted[m.TCPStream] {
			messages = append(messages, m)
		}
	}

	http2Packets := 0
	warnings := []string{}
	http2, h2Secrets, h2Pkts, h2Status, h2Err := extract.HTTP2Messages(ctx, filePath, decodeAs, wanted, opts.KeylogFile, opts.DisplayFilter, opts.MaxPackets, true)
	if h2Err != nil {
		warnings = append(warnings, h2Err.Error())
	} else {
		http2Packets = h2Pkts
		for s := range h2Secrets {
			secretValues[s] = true
		}
		messages = append(messages, http2...)
		if pe := h2Status["parse_error"]; pe != "" {
			warnings = append(warnings, pe)
		}
	}

	startPtr, endPtr := captureTimeBounds(messages, disc)
	var coverage *TLSDecryptionSummary
	if anyTLS {
		cov := decryptionCoverage(ctx, disc, filePath, decodeAs, opts.KeylogFile, secrets, opts.DisplayFilter, opts.MaxPackets, maxItems)
		coverage = &cov
	}

	requests, connRows, issues := buildHTTP(disc, messages, secretsGiven, coverage)
	appendFallbackTLSConns(wanted, disc, secretsGiven, &connRows, &issues)
	appendTLSDecryptIssues(coverage, secrets, secretsGiven, &issues)

	credentials := credentialsSummary(requests)
	verdict := httpVerdict(connRows, requests, credentials, secretsGiven)
	listedReqs, reqsOmitted := model.Cap(requests, maxItems*4)
	if listedReqs == nil {
		listedReqs = []RequestRow{}
	}

	rep := assembleReport(filePath, opts, verdict, startPtr, endPtr, len(messages), http2Packets,
		tshark.VersionString(ctx, ""), decodeAs, reasons, secrets, warnings,
		connRows, listedReqs, requests, reqsOmitted, credentials, coverage, issues)

	var scrubList []string
	for v := range secretValues {
		if len(v) >= 4 {
			scrubList = append(scrubList, v)
		}
	}
	slices.SortFunc(scrubList, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	if len(scrubList) > 0 {
		scrubReport(&rep, scrubList)
	}
	return rep
}

func assembleReport(
	filePath string,
	opts Options,
	verdict string,
	startPtr, endPtr *float64,
	msgCount, h2Pkts int,
	tsharkVer *string,
	decodeAs []string,
	reasons map[int]string,
	secrets secretsInfo,
	warnings []string,
	connRows []ConnectionRow,
	listedReqs, allReqs []RequestRow,
	reqsOmitted int,
	credentials []CredentialRow,
	coverage *TLSDecryptionSummary,
	issues []model.Issue,
) Report {
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
	var dfPtr *string
	if opts.DisplayFilter != "" {
		df := opts.DisplayFilter
		dfPtr = &df
	}
	restconfReqs, restconfErrs, clearCreds := 0, 0, 0
	for _, r := range allReqs {
		if r.Restconf {
			restconfReqs++
		}
		if len(r.RestconfErrors) > 0 {
			restconfErrs++
		}
	}
	for _, c := range credentials {
		if c.Cleartext {
			clearCreds++
		}
	}
	return Report{
		Status:        "success",
		Schema:        ReportSchema,
		File:          filePath,
		OverallStatus: model.StatusFromIssues(issues, len(connRows) > 0),
		Verdict:       verdict,
		Capture: CaptureInfo{
			Start:           model.ISOTime(startPtr),
			End:             model.ISOTime(endPtr),
			HTTPMessages:    msgCount,
			HTTP2Packets:    h2Pkts,
			TShark:          tsharkVer,
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
			DisplayFilter: dfPtr,
			MaxPackets:    opts.MaxPackets,
			Warnings:      warnings,
		},
		Summary: Summary{
			Connections:          len(connRows),
			Requests:             len(allReqs),
			RestconfRequests:     restconfReqs,
			StatusCounts:         statusCounts(allReqs),
			RestconfErrors:       restconfErrs,
			CleartextCredentials: clearCreds,
		},
		Connections:     connRows,
		Requests:        listedReqs,
		RequestsOmitted: reqsOmitted,
		Credentials:     credentials,
		TLSDecryption:   coverage,
		Issues:          model.SortIssues(issues),
		Limits:          slices.Clone(Limits),
	}
}
