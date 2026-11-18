// Package grpc emits per-RPC issues, metadata credential findings, and top-level verdicts.
package grpc

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

func appendConnectionDiagnostics(
	conn *connTrack,
	reportConn *ConnectionRow,
	connRPCs []RPCRow,
	tlsInfo *TLSView,
	ctx model.Context,
	secretsSource string,
	statusCounts map[string]int,
	statusOrder *[]string,
	credentials *[]CredentialFinding,
	issues *[]model.Issue,
	events *[]model.Event,
) {
	flow := reportConn.Flow
	svcStr := "None"
	if reportConn.Service != nil {
		svcStr = *reportConn.Service
	}
	label := fmt.Sprintf("%s (%s)", flow, svcStr)

	for _, rpc := range connRPCs {
		key := rpc.Outcome
		if rpc.GrpcStatusName != nil {
			key = *rpc.GrpcStatusName
		}
		reportConn.RPCStatus[key]++
		if statusCounts[key] == 0 {
			*statusOrder = append(*statusOrder, key)
		}
		statusCounts[key]++

		var frames []int
		if f := rpc.Frames["request"]; f != 0 {
			frames = append(frames, f)
		}
		if f := rpc.Frames["trailers"]; f != 0 {
			frames = append(frames, f)
		}
		if frames == nil {
			frames = []int{}
		}
		methodStr := "None"
		methodVal := ""
		if rpc.Method != nil {
			methodStr = *rpc.Method
			methodVal = *rpc.Method
		}

		if rpc.Outcome == "error" {
			codeName := "None"
			if rpc.GrpcStatusName != nil {
				codeName = *rpc.GrpcStatusName
			}
			sev := model.SeverityError
			if rpc.GrpcStatus != nil && (*rpc.GrpcStatus == 1 || *rpc.GrpcStatus == 5 || *rpc.GrpcStatus == 6) {
				sev = model.SeverityWarning
			}
			iss := model.MakeIssue(sev, "GRPC_"+codeName, fmt.Sprintf("%s: %s", label, rpc.Diagnosis), frames)
			iss.Method = methodVal
			iss.GrpcStatus = rpc.GrpcStatus
			*issues = append(*issues, iss)
		} else if rpc.Outcome == "incomplete" && rpc.Method != nil && *rpc.Method != "" {
			sev := model.SeverityWarning
			if strings.Contains(rpc.Diagnosis, "long-lived stream") {
				sev = model.SeverityInfo
			}
			iss := model.MakeIssue(sev, "GRPC_NO_STATUS", fmt.Sprintf("%s: %s", label, rpc.Diagnosis), frames)
			iss.Method = methodVal
			*issues = append(*issues, iss)
		}
		if rpc.Decoded != nil && rpc.Decoded.Response != nil && rpc.Decoded.Response.SubscribeSum != nil &&
			len(rpc.Decoded.Response.SubscribeSum.Errors) > 0 && rpc.Outcome == "ok" {
			iss := model.MakeIssue(model.SeverityWarning, "GNMI_INBAND_ERROR", fmt.Sprintf("%s: %s", label, rpc.Diagnosis), frames)
			iss.Method = methodVal
			*issues = append(*issues, iss)
		}
		if rpc.StateChanging {
			tAbs := 0.0
			if ctx.Start != nil {
				rpcRel := 0.0
				if rpc.T != nil {
					rpcRel = *rpc.T
				}
				tAbs = *ctx.Start + rpcRel
			}
			var rf *int
			if f := rpc.Frames["request"]; f != 0 {
				rf = &f
			}
			*events = append(*events, model.MakeEvent(ctx, tAbs, "grpc", "state_changing_rpc",
				fmt.Sprintf("%s on %s: %s", methodStr, flow, key), rf))
		}
		for _, pair := range []struct {
			kind string
			sum  FramerSummary
		}{{"request", rpc.Request}, {"response", rpc.Response}} {
			if pair.sum.Largest != nil && *pair.sum.Largest > grpcDefaultMaxRecv {
				iss := model.MakeIssue(model.SeverityWarning, "GRPC_MESSAGE_OVER_DEFAULT_LIMIT",
					fmt.Sprintf("%s: %s %s message of %d bytes exceeds the common 4 MiB default receive limit (grpc-go, grpc-java, C core); the receiver fails it with RESOURCE_EXHAUSTED unless its limit was raised",
						label, methodStr, pair.kind, *pair.sum.Largest), frames)
				iss.Method = methodVal
				*issues = append(*issues, iss)
			}
		}
		if rpc.T != nil && ctx.Start != nil {
			tAbs := *ctx.Start + *rpc.T
			var rf *int
			if f := rpc.Frames["request"]; f != 0 {
				rf = &f
			}
			*events = append(*events, model.MakeEvent(ctx, tAbs, "grpc", "rpc",
				fmt.Sprintf("%s %s", methodStr, key), rf))
		}
	}

	if reportConn.Transport == "cleartext" && len(conn.rpcs) > 0 {
		frame := conn.magicFrame
		if frame == nil {
			frame = conn.firstFrame
		}
		frames := []int{}
		if frame != nil {
			frames = []int{*frame}
		}
		*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "GRPC_CLEARTEXT",
			fmt.Sprintf("%s: %s over cleartext HTTP/2 (h2c): every request, response and metadata value crosses the network readable", label, reportConn.Protocol),
			frames))
	}

	type credEntry struct {
		key   string
		track *credTrack
	}
	var credItems []credEntry
	for k, tr := range conn.credentials {
		credItems = append(credItems, credEntry{key: k, track: tr})
	}
	slices.SortStableFunc(credItems, func(a, b credEntry) int {
		if c := cmp.Compare(a.track.firstFrame, b.track.firstFrame); c != 0 {
			return c
		}
		return cmp.Compare(a.track.order, b.track.order)
	})
	for _, ce := range credItems {
		clear := reportConn.Transport == "cleartext"
		*credentials = append(*credentials, CredentialFinding{
			Flow: flow, Service: reportConn.Service, Key: ce.key, Cleartext: clear,
			Transport: reportConn.Transport, Requests: ce.track.requests,
			FirstFrame: ce.track.firstFrame, Frames: nonNilInts(ce.track.frames), Value: "masked",
		})
		if clear {
			iss := model.MakeIssue(model.SeverityError, "CLEARTEXT_CREDENTIAL",
				fmt.Sprintf("%s: gRPC metadata key '%s' sent in cleartext in %d request(s) (value masked): anyone on the path can read it; use TLS", label, ce.key, ce.track.requests),
				nonNilInts(ce.track.frames))
			iss.Key = ce.key
			iss.Flow = flow
			*issues = append(*issues, iss)
		} else {
			iss := model.MakeIssue(model.SeverityInfo, "CREDENTIAL_IN_METADATA",
				fmt.Sprintf("%s: gRPC metadata key '%s' in %d request(s), protected by TLS on the wire (seen because %s decrypted it; value masked)", label, ce.key, ce.track.requests, secretsSource),
				nonNilInts(ce.track.frames))
			iss.Key = ce.key
			iss.Flow = flow
			*issues = append(*issues, iss)
		}
	}

	appendHTTP2Issues(conn, reportConn, label, ctx, issues, events)
	appendTLSConnIssues(conn.disc, tlsInfo, label, issues)
}

func grpcVerdict(connections []ConnectionRow, rpcs []RPCRow, credentials []CredentialFinding, statusCounts map[string]int, statusOrder []string, secretsSource string, secretsGiven bool) string {
	if len(connections) == 0 {
		return "No gRPC or HTTP/2 found: no HTTP/2 preface, no TLS offering h2, and nothing on a well-known gRPC port."
	}
	var clearConns, tlsConns []ConnectionRow
	for _, c := range connections {
		if c.Transport == "cleartext" && c.RPCs > 0 {
			clearConns = append(clearConns, c)
		} else if strings.HasPrefix(c.Transport, "tls") {
			tlsConns = append(tlsConns, c)
		}
	}
	var parts []string
	if len(clearConns) > 0 {
		proto := "HTTP/2"
		svcs := make(map[string]bool)
		for _, c := range clearConns {
			if c.Protocol == "grpc" {
				proto = "gRPC"
			}
			if c.Service != nil {
				svcs[*c.Service] = true
			}
		}
		parts = append(parts, fmt.Sprintf("%d cleartext %s connection(s) (%s)", len(clearConns), proto, strings.Join(slices.Sorted(maps.Keys(svcs)), ", ")))
	}
	if len(tlsConns) > 0 {
		dec := 0
		svcs := make(map[string]bool)
		for _, c := range tlsConns {
			if c.TLS != nil && c.TLS.Decrypted {
				dec++
			}
			if c.Service != nil {
				svcs[*c.Service] = true
			}
		}
		tail := ": without a key log only the handshake is visible, so whether they carry gRPC cannot be seen"
		if dec > 0 {
			tail = " with " + secretsSource
		} else if secretsGiven {
			tail = fmt.Sprintf(": %s decrypted none of them, so whether they carry gRPC cannot be seen (see tls_decryption)", secretsSource)
		}
		parts = append(parts, fmt.Sprintf("%d TLS connection(s) on a gRPC port or offering ALPN h2 (%s), %d decrypted%s",
			len(tlsConns), strings.Join(slices.Sorted(maps.Keys(svcs)), ", "), dec, tail))
	}
	verdict := strings.Join(parts, "; ")
	if verdict == "" {
		verdict = fmt.Sprintf("%d connection(s)", len(connections))
	}
	if len(rpcs) > 0 {
		type sc struct {
			k string
			n int
		}
		var pairs []sc
		for _, k := range statusOrder {
			pairs = append(pairs, sc{k: k, n: statusCounts[k]})
		}
		slices.SortStableFunc(pairs, func(a, b sc) int { return cmp.Compare(b.n, a.n) })
		stParts := make([]string, len(pairs))
		for i, p := range pairs {
			stParts[i] = fmt.Sprintf("%d %s", p.n, p.k)
		}
		verdict += fmt.Sprintf(". %d RPC(s): %s", len(rpcs), strings.Join(stParts, ", "))
	}
	if len(credentials) > 0 {
		clearSet := make(map[string]bool)
		for _, c := range credentials {
			if c.Cleartext {
				clearSet[c.Key] = true
			}
		}
		if len(clearSet) > 0 {
			verdict += ". Credentials in cleartext metadata: " + strings.Join(slices.Sorted(maps.Keys(clearSet)), ", ") + " (values masked)"
		}
	}
	return verdict + "."
}
