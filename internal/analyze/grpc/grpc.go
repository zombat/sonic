// Package grpc orchestrates HTTP/2, gNMI/gNOI, TLS, and credential analysis on captures.
package grpc

import (
	"cmp"
	"context"
	"slices"

	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

// AnalyzeCapture runs HTTP/2, gNMI/gNOI, TLS, and credential analysis on one capture file.
func AnalyzeCapture(ctx context.Context, filePath string, opts Options) Report {
	protoDirs, maxItems, invalid := validateInputs(filePath, opts)
	if invalid != nil {
		return *invalid
	}
	includeTLS := true
	if opts.IncludeTLS != nil {
		includeTLS = *opts.IncludeTLS
	}

	statusMeta := make(map[string]string)
	disc, err := extract.Discover(ctx, filePath, opts.DisplayFilter, opts.MaxPackets, statusMeta, opts.Ports)
	if err != nil {
		return errReport(err.Error())
	}
	secrets := secretsView(filePath, opts.KeylogFile)
	secretsGiven := secrets.Source != nil
	decodeAs, reasons := extract.PlanDecodeAs(disc, opts.Ports)

	ext, err := extract.IterHTTP2Packets(ctx, filePath, decodeAs, opts.KeylogFile, protoDirs, opts.DisplayFilter, opts.MaxPackets, true)
	if err != nil {
		return errReport(err.Error())
	}
	secSrc := "the key log"
	if secrets.Source != nil {
		secSrc = *secrets.Source
	}
	analysis := newGrpcAnalysis(disc, secSrc)
	wanted := make(map[int]bool)
	anyTLS := false
	for idx, conn := range disc {
		if conn.IsTLS() {
			anyTLS = true
		}
		if conn.CarriesHTTP2(opts.Ports...) {
			wanted[idx] = true
		}
	}
	for i := range ext.Packets {
		if wanted[ext.Packets[i].TCPStream] {
			analysis.feed(&ext.Packets[i])
		}
	}

	secretVals := mapsCloneBool(ext.SecretValues)
	identVals := mapsCloneBool(ext.IdentityValues)
	reread := rereadStuckStreams(ctx, filePath, opts, decodeAs, protoDirs, disc, analysis, wanted, secretsGiven, secretVals, identVals, statusMeta)
	rules := buildScrubRules(secretVals, identVals)

	startPtr, endPtr := analysis.start, analysis.end
	for _, c := range disc {
		if startPtr == nil || c.FirstT < *startPtr {
			v := c.FirstT
			startPtr = &v
		}
		if endPtr == nil || c.LastT > *endPtr {
			v := c.LastT
			endPtr = &v
		}
	}
	mCtx := model.Context{Start: startPtr, End: endPtr, MaxItems: maxItems}

	tlsSessionsMap, tlsState := probeTLSDetails(ctx, filePath, opts, decodeAs, disc, includeTLS, anyTLS, secretsGiven, statusMeta)
	certificates := make(map[int][]byte)
	for idx, st := range tlsState {
		if st != nil && len(st.Certificate) > 0 {
			certificates[idx] = st.Certificate
		}
	}
	var coverage *TLSDecryptionSummary
	if includeTLS {
		cov := decryptionCoverage(disc, tlsState, secrets, analysis, tlsSessionsMap, maxItems)
		coverage = &cov
	}
	covByStream := make(map[int]TLSSessionRow)
	if coverage != nil {
		for _, r := range coverage.Sessions {
			covByStream[r.TCPStream] = r
		}
	}

	for idx, dconn := range disc {
		if wanted[idx] && analysis.conns[idx] == nil {
			conn := newConnTrack(idx, dconn)
			ff, ft, lt := dconn.FirstFrame, dconn.FirstT, dconn.LastT
			conn.firstFrame, conn.firstT, conn.lastT = &ff, &ft, &lt
			analysis.conns[idx] = conn
		}
	}
	sortedConns := make([]*connTrack, 0, len(analysis.conns))
	for _, c := range analysis.conns {
		sortedConns = append(sortedConns, c)
	}
	slices.SortStableFunc(sortedConns, func(a, b *connTrack) int {
		af, bf := 0, 0
		if a.firstFrame != nil {
			af = *a.firstFrame
		}
		if b.firstFrame != nil {
			bf = *b.firstFrame
		}
		return cmp.Compare(af, bf)
	})

	issues, events := []model.Issue{}, []model.Event{}
	connections := make([]ConnectionRow, 0, len(sortedConns))
	rpcs, credentials := []RPCRow{}, []CredentialFinding{}
	statusCounts := make(map[string]int)
	var statusOrder []string

	for _, conn := range sortedConns {
		dconn := conn.disc
		var tViewPtr *TLSView
		if dconn != nil && dconn.IsTLS() {
			cli, srv := dconn.Client, dconn.Server
			var sessPtr *tlsinspect.Session
			if s, ok := tlsSessionsMap[tlsFlowKey{client: endpointStr(cli), server: endpointStr(srv)}]; ok {
				sessPtr = &s
			}
			var covPtr *TLSSessionRow
			if cr, ok := covByStream[conn.index]; ok {
				covPtr = &cr
			}
			ft := dconn.FirstT
			tv := tlsView(dconn, sessPtr, conn.tlsSeen && len(conn.rpcs) > 0, secretsGiven, certificates[conn.index], &ft, covPtr)
			tViewPtr = &tv
		}
		reportConn := analysis.connectionReport(conn, mCtx, tViewPtr)
		rpcList := make([]*rpcTrack, 0, len(conn.rpcs))
		for _, r := range conn.rpcs {
			rpcList = append(rpcList, r)
		}
		slices.SortFunc(rpcList, func(a, b *rpcTrack) int { return cmp.Compare(a.streamID, b.streamID) })
		connRPCs := make([]RPCRow, 0, len(rpcList))
		for _, r := range rpcList {
			connRPCs = append(connRPCs, analysis.rpcReport(conn, r, mCtx))
		}
		appendConnectionDiagnostics(conn, &reportConn, connRPCs, tViewPtr, mCtx, analysis.secretsSource, statusCounts, &statusOrder, &credentials, &issues, &events)
		connections = append(connections, reportConn)
		rpcs = append(rpcs, connRPCs...)
	}

	verdict := grpcVerdict(connections, rpcs, credentials, statusCounts, statusOrder, analysis.secretsSource, secretsGiven)
	appendCaptureTLSAlerts(coverage, secrets, secretsGiven, disc, reread, &issues)

	listedRPCs, rpcsOmitted := model.Cap(rpcs, maxItems*4)
	if listedRPCs == nil {
		listedRPCs = []RPCRow{}
	}
	listedConns, connsOmitted := model.Cap(connections, maxItems)
	if listedConns == nil {
		listedConns = []ConnectionRow{}
	}
	rep := assembleGrpcReport(ctx, filePath, opts, verdict, startPtr, endPtr, analysis.packets,
		decodeAs, reasons, secrets, reread, protoDirs, statusMeta, ext.Status,
		connections, listedConns, connsOmitted, rpcs, listedRPCs, rpcsOmitted,
		credentials, statusCounts, coverage, issues, events, maxItems)
	scrubReport(&rep, rules)
	return rep
}
