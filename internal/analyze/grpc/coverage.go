// Package grpc builds per-session TLS decryption coverage rows and failure verdicts.
package grpc

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

func decryptionCoverage(
	disc map[int]*extract.TCPConnection,
	tlsState map[int]*extract.TLSDecryptionInfo,
	secrets secretsInfo,
	analysis *grpcAnalysis,
	tlsSessionsMap map[tlsFlowKey]tlsinspect.Session,
	maxItems int,
) TLSDecryptionSummary {
	type indexed struct {
		idx  int
		conn *extract.TCPConnection
	}
	var conns []indexed
	for idx, c := range disc {
		if c.IsTLS() {
			conns = append(conns, indexed{idx: idx, conn: c})
		}
	}
	slices.SortStableFunc(conns, func(a, b indexed) int {
		if c := cmp.Compare(a.conn.FirstFrame, b.conn.FirstFrame); c != 0 {
			return c
		}
		return cmp.Compare(a.idx, b.idx)
	})

	rows := make([]TLSSessionRow, 0, len(conns))
	done := 0
	var notDec []string
	for _, ic := range conns {
		row := buildCoverageRow(ic.idx, ic.conn, tlsState[ic.idx], secrets, analysis, tlsSessionsMap)
		if row.Decrypted {
			done++
		} else {
			notDec = append(notDec, row.Flow)
		}
		rows = append(rows, row)
	}

	var verdict string
	switch {
	case len(rows) == 0:
		verdict = "No TLS session in this capture."
	case secrets.Source == nil:
		verdict = fmt.Sprintf("0 of %d TLS session(s) decrypted: no key log given, and the capture carries no TLS secrets.", len(rows))
	default:
		verdict = fmt.Sprintf("%d of %d TLS session(s) decrypted with %s.", done, len(rows), *secrets.Source)
		if done < len(rows) {
			verdict = strings.TrimSuffix(verdict, ".") + "; not decrypted: " + strings.Join(notDec, ", ") + "."
		}
	}
	listed, omitted := model.Cap(rows, maxItems)
	if listed == nil {
		listed = []TLSSessionRow{}
	}
	return TLSDecryptionSummary{
		Verdict:         verdict,
		Decrypted:       done,
		Total:           len(rows),
		SecretsSource:   secrets.Source,
		Sessions:        listed,
		SessionsOmitted: omitted,
	}
}

func buildCoverageRow(
	idx int,
	dconn *extract.TCPConnection,
	state *extract.TLSDecryptionInfo,
	secrets secretsInfo,
	analysis *grpcAnalysis,
	tlsSessionsMap map[tlsFlowKey]tlsinspect.Session,
) TLSSessionRow {
	cli, srv := dconn.A, dconn.B
	if dconn.Client != nil {
		cli = *dconn.Client
	}
	if dconn.Server != nil {
		srv = *dconn.Server
	}
	conn := analysis.conns[idx]
	hasHTTP2 := conn != nil && conn.tlsSeen && (conn.packetsClient+conn.packetsServer+conn.packetsUnknown) > 0
	inside := []string{}
	if state != nil && len(state.ApplicationData) > 0 {
		inside = slices.Clone(state.ApplicationData)
	} else if hasHTTP2 {
		inside = []string{"http2"}
	}
	hsDec := state != nil && state.Handshake
	decrypted := hsDec || len(inside) > 0

	var randPtr *string
	chFrame := dconn.TLSClientHello
	if state != nil {
		randPtr = state.ClientRandom
		if state.ClientHelloFrame != nil {
			chFrame = state.ClientHelloFrame
		}
	}
	var found *randomSecretInfo
	if randPtr != nil {
		if info, ok := secrets.ByRandom[*randPtr]; ok {
			found = &info
		}
	}
	sess, hasSess := tlsSessionsMap[tlsFlowKey{client: endpointStr(&cli), server: endpointStr(&srv)}]
	var verPtr *string
	verStr := ""
	if hasSess && sess.ServerChose != nil {
		v := sess.ServerChose.Version
		verPtr = &v
		verStr = v
	}
	var missing []string
	if found != nil {
		missing = extract.MissingLabels(found.labels, verStr)
	}

	reasonPtr := coverageFailureReason(secrets.Source, decrypted, inside, missing, randPtr, dconn.TLSClientHello, found)
	secretIn, labels := []string{}, []string{}
	if found != nil {
		for s := range found.sources {
			secretIn = append(secretIn, s)
		}
		slices.Sort(secretIn)
		for l := range found.labels {
			labels = append(labels, l)
		}
		slices.Sort(labels)
	}
	return TLSSessionRow{
		Flow:               endpointStr(&cli) + " -> " + endpointStr(&srv),
		Service:            fmt.Sprintf("tcp/%d", dconn.ServicePort()),
		TCPStream:          idx,
		ClientHelloFrame:   chFrame,
		Version:            verPtr,
		Decrypted:          decrypted,
		HandshakeDecrypted: hsDec,
		ApplicationData:    inside,
		SecretIn:           secretIn,
		Labels:             labels,
		Reason:             reasonPtr,
	}
}

func coverageFailureReason(
	source *string,
	decrypted bool,
	inside, missing []string,
	randPtr *string,
	clientHello *int,
	found *randomSecretInfo,
) *string {
	var msg string
	switch {
	case source == nil:
		msg = "no key log given, and the capture carries no TLS secrets"
	case decrypted && len(missing) > 0 && len(inside) == 0:
		msg = fmt.Sprintf("only the handshake was decrypted: the TLS secrets lack %s for this session, so its application data stays encrypted", strings.Join(missing, ", "))
	case decrypted:
		return nil
	case randPtr == nil && clientHello == nil:
		msg = "no ClientHello in the capture (the session began before it), so no secret can be matched to it"
	case randPtr == nil:
		msg = "its ClientHello could not be reassembled from the capture, so no secret can be matched to it"
	case found == nil:
		verb := "holds"
		if strings.Contains(*source, " and ") {
			verb = "hold"
		}
		msg = fmt.Sprintf("%s %s no secret for this session (no line with its ClientHello random): the key log is from another session or another client", *source, verb)
	default:
		extra := ""
		if len(missing) > 0 {
			extra = " but lack " + strings.Join(missing, ", ")
		}
		msg = "the secrets name this session's ClientHello random" + extra + ", and tshark did not decrypt it"
	}
	return &msg
}
