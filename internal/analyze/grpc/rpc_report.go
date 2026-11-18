// Package grpc builds per-RPC diagnostic summaries and gNMI/gNOI decoded views.
package grpc

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

func (a *grpcAnalysis) rpcReport(conn *connTrack, rpc *rpcTrack, ctx model.Context) RPCRow {
	method := rpc.method()
	var servicePtr, rpcNamePtr *string
	if method != nil && strings.Count(*method, "/") >= 2 {
		parts := strings.SplitN(strings.Trim(*method, "/"), "/", 2)
		if len(parts) == 2 {
			servicePtr, rpcNamePtr = &parts[0], &parts[1]
		}
	}
	httpStatusPtr := rpc.header(":status", "response")
	if httpStatusPtr == nil {
		httpStatusPtr = rpc.header(":status", "trailers")
	}
	var httpStatusInt *int
	if httpStatusPtr != nil && isASCIIDigits(*httpStatusPtr) {
		if v, err := strconv.Atoi(*httpStatusPtr); err == nil {
			httpStatusInt = &v
		}
	}
	grpcStatusRaw := rpc.header("grpc-status", "trailers")
	var grpcStatus *int
	if grpcStatusRaw != nil && isASCIIDigits(*grpcStatusRaw) {
		if v, err := strconv.Atoi(*grpcStatusRaw); err == nil {
			grpcStatus = &v
		}
	}
	mapped := false
	if grpcStatus == nil && httpStatusInt != nil && *httpStatusInt != 200 {
		code := HTTPToGrpc[*httpStatusInt]
		if code == 0 {
			code = 2
		}
		grpcStatus = &code
		mapped = true
	}

	timeout := parseTimeout(rpc.header("grpc-timeout", "request"))
	reqSum := rpc.clientFramer.summary()
	respSum := rpc.serverFramer.summary()

	var timing TimingInfo
	if rpc.tRequest != nil && rpc.tFirstResponse != nil {
		v := model.Round((*rpc.tFirstResponse-*rpc.tRequest)*1000, 3)
		timing.ToFirstResponseMS = &v
	}
	if rpc.tRequest != nil && rpc.tEnd != nil {
		v := model.Round((*rpc.tEnd-*rpc.tRequest)*1000, 3)
		timing.ToEndMS = &v
	}
	resetAfterEnd := rpc.reset != nil && grpcStatus != nil && rpc.serverEndedBeforeReset
	outcome := "incomplete"
	if rpc.reset != nil && !resetAfterEnd {
		outcome = "reset"
	} else if grpcStatus != nil {
		if *grpcStatus == 0 {
			outcome = "ok"
		} else {
			outcome = "error"
		}
	}

	metaMap := make(map[string]bool)
	for _, h := range rpc.requestHeaders {
		low := strings.ToLower(h.Name)
		if !strings.HasPrefix(h.Name, ":") && !ReservedHeaders[low] {
			metaMap[low] = true
		}
	}
	metaKeys := slices.Sorted(maps.Keys(metaMap))
	if metaKeys == nil {
		metaKeys = []string{}
	}

	var statusNamePtr *string
	if grpcStatus != nil {
		name, ok := GrpcStatus[*grpcStatus]
		if !ok {
			name = fmt.Sprintf("code %d", *grpcStatus)
		}
		statusNamePtr = &name
	}

	var resetCopy *ResetInfo
	if rpc.reset != nil {
		rc := *rpc.reset
		resetCopy = &rc
	}
	framesCopy := make(map[string]int, len(rpc.frames))
	for k, v := range rpc.frames {
		framesCopy[k] = v
	}

	stateChanging := method != nil && StateChanging[strings.Trim(*method, "/")]
	var headersDecPtr *bool
	if rpc.decodeFailed {
		f := false
		headersDecPtr = &f
	}

	row := RPCRow{
		Flow:               endpointStr(conn.client) + " -> " + endpointStr(conn.server),
		StreamID:           rpc.streamID,
		Method:             method,
		Family:             serviceFamily(method),
		Service:            servicePtr,
		RPC:                rpcNamePtr,
		Authority:          rpc.header(":authority", "request"),
		ContentType:        rpc.header("content-type", "request"),
		UserAgent:          rpc.header("user-agent", "request"),
		GrpcTimeoutS:       timeout,
		GrpcEncoding:       rpc.header("grpc-encoding", "request"),
		MetadataKeys:       metaKeys,
		Request:            reqSum,
		Response:           respSum,
		HTTPStatus:         httpStatusInt,
		GrpcStatus:         grpcStatus,
		GrpcStatusName:     statusNamePtr,
		GrpcStatusFromHTTP: mapped,
		GrpcMessage:        rpc.header("grpc-message", "trailers"),
		TrailersOnly:       len(rpc.trailers) > 0 && rpc.headerBlocksServer == 1 && respSum.Messages == 0,
		Outcome:            outcome,
		Reset:              resetCopy,
		ResetAfterEnd:      resetAfterEnd,
		Timing:             timing,
		T:                  ctx.Rel(rpc.tRequest),
		Frames:             framesCopy,
		StateChanging:      stateChanging,
		WiresharkProtobuf:  rpc.protobuf,
		HeadersDecoded:     headersDecPtr,
	}
	if decoded := a.decodeRPC(rpc, method); decoded != nil {
		row.Decoded = decoded
	}
	row.Diagnosis = a.diagnose(conn, rpc, &row, timeout)
	return row
}

func (a *grpcAnalysis) decodeRPC(rpc *rpcTrack, method *string) *DecodedBlock {
	fam := serviceFamily(method)
	if fam == nil || (*fam != "gNMI" && *fam != "gNOI" && *fam != "gRPC health") {
		return nil
	}
	var errorsList []string
	var requests []*DecodedRequest
	polls := 0
	for _, msg := range rpc.clientFramer.messages {
		if !msg.hasPartial || len(msg.partial) < msg.size {
			continue
		}
		dec, err := DecodeRequest(*method, msg.partial)
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("request at frame %d: %s", msg.frame, err.Error()))
			continue
		}
		requests = append(requests, dec)
		if dec.Poll {
			polls++
		}
	}

	var responses []*DecodedResponse
	for _, msg := range rpc.serverFramer.messages {
		if !msg.hasPartial || len(msg.partial) < msg.size {
			continue
		}
		tv := msg.t
		dec, err := DecodeResponse(*method, msg.partial, &tv)
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("response at frame %d: %s", msg.frame, err.Error()))
			continue
		}
		responses = append(responses, dec)
	}

	out := &DecodedBlock{Polls: polls}
	hasContent := polls > 0
	for _, r := range requests {
		if !r.Empty() {
			if out.Request == nil || !r.Poll {
				if !r.Poll {
					out.Request = r
					break
				}
				out.Request = r
			}
			hasContent = true
		}
	}
	if out.Request != nil {
		hasContent = true
	}

	_, rpcName := splitMethod(*method)
	if len(responses) > 0 && *fam == "gNMI" && rpcName == "Subscribe" {
		summary := &SubscribeResponseSummary{Messages: len(responses)}
		for _, r := range responses {
			if r.SubscribeMsg == nil {
				continue
			}
			if r.SubscribeMsg.Notification != nil && *r.SubscribeMsg.Notification {
				summary.Notifications++
				if r.SubscribeMsg.Updates != nil {
					summary.Updates += *r.SubscribeMsg.Updates
				}
				if r.SubscribeMsg.Deletes != nil {
					summary.Deletes += *r.SubscribeMsg.Deletes
				}
			}
			if r.SubscribeMsg.SyncResponse != nil && *r.SubscribeMsg.SyncResponse {
				summary.SyncResponse = true
			}
			if r.SubscribeMsg.Error != nil && len(summary.Errors) < 5 {
				summary.Errors = append(summary.Errors, *r.SubscribeMsg.Error)
			}
		}
		out.Response = &DecodedResponse{SubscribeSum: summary}
		hasContent = true
	} else {
		for _, r := range responses {
			if !r.Empty() {
				out.Response = r
				hasContent = true
				break
			}
		}
	}
	if rpc.serverFramer.count > len(responses) {
		out.ResponsesNotDecoded = rpc.serverFramer.count - len(responses)
		hasContent = true
	}
	if len(errorsList) > 0 {
		if len(errorsList) > 5 {
			errorsList = errorsList[:5]
		}
		out.DecodeErrors = errorsList
		hasContent = true
	}
	if *fam == "gNMI" && rpcName == "Capabilities" && out.Response != nil {
		rpc.conn.capabilities = out.Response
	}
	if !hasContent {
		return nil
	}
	return out
}
