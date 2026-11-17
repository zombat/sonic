// Package httpinspect pairs HTTP requests with responses per TCP stream.
package httpinspect

import (
	"cmp"
	"fmt"
	"maps"
	"slices"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

func makePairRecord(req, resp *extract.HTTPMessage, flow, service, transport string) RequestRow {
	srcMsg := req
	if srcMsg == nil {
		srcMsg = resp
	}

	var method, path, host, reqCT, respCT, phrase, location, httpVer *string
	var streamID, status, reqFrame, respFrame *int
	var timingMS, tVal *float64
	var reqBodyLen, respBodyLen int
	var body []byte
	creds := []extract.HTTPCredentialFlag{}

	if srcMsg != nil {
		v := srcMsg.HTTPVersion
		httpVer = &v
		streamID = srcMsg.StreamID
		tv := srcMsg.T
		tVal = &tv
	}
	if req != nil {
		method = req.Method
		path = req.URI
		host = req.Host
		reqCT = req.ContentType
		reqBodyLen = req.BodyLen
		if req.Frame != 0 {
			f := req.Frame
			reqFrame = &f
		}
		if len(req.Credentials) > 0 {
			creds = append(creds, req.Credentials...)
		}
		if req.HasAuth {
			creds = append(creds, extract.HTTPCredentialFlag{
				Header: "Authorization",
				Kind:   "authorization",
				Scheme: req.AuthScheme,
				Value:  "masked",
			})
		}
		if req.HasCookie {
			creds = append(creds, extract.HTTPCredentialFlag{
				Header: "Cookie",
				Kind:   "cookie",
				Value:  "masked",
			})
		}
	}
	if resp != nil {
		status = resp.Status
		phrase = resp.Phrase
		respCT = resp.ContentType
		respBodyLen = resp.BodyLen
		body = resp.Body
		location = resp.Location
		if resp.Frame != 0 {
			f := resp.Frame
			respFrame = &f
		}
		if resp.TimeSinceRequest != nil {
			ms := model.Round(*resp.TimeSinceRequest*1000, 3)
			timingMS = &ms
		}
	}

	errs := []map[string]string{}
	if resp != nil && status != nil && *status >= 400 {
		ct := ""
		if respCT != nil {
			ct = *respCT
		}
		errs = ParseRestconfErrors(body, ct)
	}
	pathStr, rct, sct := "", "", ""
	if path != nil {
		pathStr = *path
	}
	if reqCT != nil {
		rct = *reqCT
	}
	if respCT != nil {
		sct = *respCT
	}
	restconf := extract.IsRestconf(pathStr, rct, sct) || len(errs) > 0

	return RequestRow{
		Flow:                flow,
		Service:             service,
		Transport:           transport,
		HTTPVersion:         httpVer,
		StreamID:            streamID,
		Method:              method,
		Path:                path,
		Host:                host,
		Status:              status,
		Phrase:              phrase,
		RequestContentType:  reqCT,
		ResponseContentType: respCT,
		RequestBodyBytes:    reqBodyLen,
		ResponseBodyBytes:   respBodyLen,
		TimingMS:            timingMS,
		Location:            location,
		Restconf:            restconf,
		RestconfErrors:      errs,
		Credentials:         creds,
		Frames:              FramesRef{Request: reqFrame, Response: respFrame},
		T:                   tVal,
		Outcome:             httpOutcome(resp),
	}
}

func pairStream(msgs []*extract.HTTPMessage, flow, service, transport string) []RequestRow {
	var requests, responses []*extract.HTTPMessage
	byFrame := make(map[int]*extract.HTTPMessage)
	byStreamID := make(map[int]*extract.HTTPMessage)

	for _, m := range msgs {
		if m.IsRequest {
			requests = append(requests, m)
			if m.Frame != 0 {
				byFrame[m.Frame] = m
			}
			if m.StreamID != nil {
				byStreamID[*m.StreamID] = m
			}
		} else {
			responses = append(responses, m)
		}
	}

	used := make(map[*extract.HTTPMessage]bool, len(requests))
	records := make([]RequestRow, 0, len(requests)+len(responses))
	for _, resp := range responses {
		var req *extract.HTTPMessage
		if resp.StreamID != nil {
			req = byStreamID[*resp.StreamID]
		}
		if req == nil && resp.RequestFrame != nil {
			req = byFrame[*resp.RequestFrame]
		}
		if req != nil {
			used[req] = true
		}
		records = append(records, makePairRecord(req, resp, flow, service, transport))
	}
	for _, req := range requests {
		if !used[req] {
			records = append(records, makePairRecord(req, nil, flow, service, transport))
		}
	}
	sortFrame := func(r RequestRow) int {
		if r.Frames.Request != nil && *r.Frames.Request != 0 {
			return *r.Frames.Request
		}
		if r.Frames.Response != nil && *r.Frames.Response != 0 {
			return *r.Frames.Response
		}
		return 0
	}
	slices.SortStableFunc(records, func(a, b RequestRow) int {
		return cmp.Compare(sortFrame(a), sortFrame(b))
	})
	return records
}

func buildHTTP(
	disc map[int]*extract.TCPConnection,
	messages []extract.HTTPMessage,
	secretsGiven bool,
	coverage *TLSDecryptionSummary,
) ([]RequestRow, []ConnectionRow, []model.Issue) {
	covByStream := make(map[int]TLSSessionRow)
	if coverage != nil {
		for _, row := range coverage.Sessions {
			covByStream[row.TCPStream] = row
		}
	}

	byStream := make(map[int][]*extract.HTTPMessage)
	for i := range messages {
		m := &messages[i]
		byStream[m.TCPStream] = append(byStream[m.TCPStream], m)
	}
	streamIDs := slices.Sorted(maps.Keys(byStream))

	requests := []RequestRow{}
	connRows := []ConnectionRow{}
	issues := []model.Issue{}
	for _, idx := range streamIDs {
		conn := disc[idx]
		if conn == nil {
			continue
		}
		cov, hasCov := covByStream[idx]
		decrypted := (hasCov && cov.Decrypted) || !conn.IsTLS()
		transport := transportLabel(conn, decrypted, secretsGiven)
		flow := connectionFlow(conn)
		service := fmt.Sprintf("tcp/%d", conn.ServicePort())

		paired := pairStream(byStream[idx], flow, service, transport)
		verSet := make(map[string]bool)
		restconfHere := false
		for _, rec := range paired {
			if rec.HTTPVersion != nil {
				verSet[*rec.HTTPVersion] = true
			}
			if rec.Restconf {
				restconfHere = true
			}
			requests = append(requests, rec)
			appendRequestIssues(rec, fmt.Sprintf("%s (%s)", flow, service), &issues)
		}

		versions := slices.Sorted(maps.Keys(verSet))
		if versions == nil {
			versions = []string{}
		}
		alpn := []string{}
		if len(conn.ALPN) > 0 {
			alpn = slices.Clone(conn.ALPN)
		}
		var svcName *string
		if name := extract.HTTPPorts[conn.ServicePort()]; name != "" {
			svcName = &name
		}
		var decPtr *bool
		if conn.IsTLS() {
			d := decrypted
			decPtr = &d
		}
		rc := restconfHere
		connRows = append(connRows, ConnectionRow{
			Flow:         flow,
			Service:      service,
			ServiceName:  svcName,
			Transport:    transport,
			HTTPVersions: versions,
			Requests:     len(paired),
			Restconf:     &rc,
			SNI:          conn.SNI,
			ALPNOffered:  alpn,
			Decrypted:    decPtr,
		})
	}
	return requests, connRows, issues
}
