// Package httpinspect computes per-session TLS decryption coverage and reasons for failures.
package httpinspect

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

// decryptionCoverage evaluates TLS decryption outcomes and failure reasons for every TLS stream.
func decryptionCoverage(
	ctx context.Context,
	disc map[int]*extract.TCPConnection,
	filePath string,
	decodeAs []string,
	keylogFile string,
	secrets secretsInfo,
	displayFilter string,
	maxPackets *int,
	maxItems int,
) TLSDecryptionSummary {
	tlsState := probeTLSState(ctx, disc, filePath, decodeAs, keylogFile, secrets, displayFilter, maxPackets)

	type indexedConn struct {
		idx  int
		conn *extract.TCPConnection
	}
	conns := make([]indexedConn, 0, len(disc))
	for idx, c := range disc {
		if c.IsTLS() {
			conns = append(conns, indexedConn{idx: idx, conn: c})
		}
	}
	slices.SortStableFunc(conns, func(a, b indexedConn) int {
		if c := cmp.Compare(a.conn.FirstFrame, b.conn.FirstFrame); c != 0 {
			return c
		}
		return cmp.Compare(a.idx, b.idx)
	})

	rows := make([]TLSSessionRow, 0, len(conns))
	done := 0
	var notDecFlows []string
	for _, ic := range conns {
		row := buildTLSSessionRow(ic.idx, ic.conn, tlsState[ic.idx], secrets)
		if row.Decrypted {
			done++
		} else {
			notDecFlows = append(notDecFlows, row.Flow)
		}
		rows = append(rows, row)
	}

	verdict := tlsCoverageVerdict(rows, done, notDecFlows, secrets.Source)
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

func probeTLSState(
	ctx context.Context,
	disc map[int]*extract.TCPConnection,
	filePath string,
	decodeAs []string,
	keylogFile string,
	secrets secretsInfo,
	displayFilter string,
	maxPackets *int,
) map[int]*extract.TLSDecryptionInfo {
	tlsState := make(map[int]*extract.TLSDecryptionInfo)
	if secrets.Source == nil {
		return tlsState
	}
	st, err := extract.TLSDecryption(ctx, filePath, decodeAs, keylogFile, displayFilter, maxPackets, true)
	if err != nil || st == nil {
		return tlsState
	}
	tlsState = st
	var retry []int
	for idx, c := range disc {
		if !c.IsTLS() {
			continue
		}
		info := tlsState[idx]
		if info == nil || (!info.Handshake && len(info.ApplicationData) == 0) {
			retry = append(retry, idx)
		}
	}
	if len(retry) > 0 {
		slices.Sort(retry)
		parts := make([]string, len(retry))
		for i, idx := range retry {
			parts[i] = strconv.Itoa(idx)
		}
		flt := "tcp.stream in {" + strings.Join(parts, " ") + "}"
		if displayFilter != "" {
			flt = fmt.Sprintf("(%s) && %s", displayFilter, flt)
		}
		if second, err2 := extract.TLSDecryption(ctx, filePath, decodeAs, keylogFile, flt, maxPackets, false); err2 == nil {
			for _, idx := range retry {
				mergeTLSDecryption(tlsState, idx, second[idx])
			}
		}
	}
	return tlsState
}

func buildTLSSessionRow(idx int, dconn *extract.TCPConnection, state *extract.TLSDecryptionInfo, secrets secretsInfo) TLSSessionRow {
	inside := []string{}
	var random *string
	chFrame := dconn.TLSClientHello
	decrypted := false
	if state != nil {
		if len(state.ApplicationData) > 0 {
			inside = slices.Clone(state.ApplicationData)
		}
		decrypted = state.Handshake || len(inside) > 0
		random = state.ClientRandom
		if state.ClientHelloFrame != nil {
			chFrame = state.ClientHelloFrame
		}
	}

	var found *randomSecretInfo
	if random != nil {
		if info, ok := secrets.ByRandom[*random]; ok {
			found = &info
		}
	}
	var reason *string
	if secrets.Source == nil {
		s := "no key log given, and the capture carries no TLS secrets"
		reason = &s
	} else if !decrypted {
		reason = tlsFailureReason(random, dconn.TLSClientHello, found, *secrets.Source)
	}

	secretIn := []string{}
	labels := []string{}
	if found != nil {
		for src := range found.sources {
			secretIn = append(secretIn, src)
		}
		slices.Sort(secretIn)
		for lbl := range found.labels {
			labels = append(labels, lbl)
		}
		slices.Sort(labels)
	}

	return TLSSessionRow{
		Flow:             connectionFlow(dconn),
		Service:          fmt.Sprintf("tcp/%d", dconn.ServicePort()),
		TCPStream:        idx,
		ClientHelloFrame: chFrame,
		Decrypted:        decrypted,
		ApplicationData:  inside,
		SecretIn:         secretIn,
		Labels:           labels,
		Reason:           reason,
	}
}

func tlsCoverageVerdict(rows []TLSSessionRow, done int, notDecFlows []string, source *string) string {
	switch {
	case len(rows) == 0:
		return "No TLS session in this capture."
	case source == nil:
		return fmt.Sprintf("0 of %d TLS session(s) decrypted: no key log given, and the capture carries no secrets.", len(rows))
	default:
		verdict := fmt.Sprintf("%d of %d TLS session(s) decrypted with %s.", done, len(rows), *source)
		if done < len(rows) {
			verdict = strings.TrimSuffix(verdict, ".") + "; not decrypted: " + strings.Join(notDecFlows, ", ") + "."
		}
		return verdict
	}
}

func mergeTLSDecryption(dst map[int]*extract.TLSDecryptionInfo, idx int, other *extract.TLSDecryptionInfo) {
	if other == nil {
		return
	}
	first := dst[idx]
	if first == nil {
		dst[idx] = other
		return
	}
	first.Handshake = first.Handshake || other.Handshake
	seen := make(map[string]bool, len(first.ApplicationData)+len(other.ApplicationData))
	for _, s := range first.ApplicationData {
		seen[s] = true
	}
	for _, s := range other.ApplicationData {
		seen[s] = true
	}
	merged := make([]string, 0, len(seen))
	for s := range seen {
		merged = append(merged, s)
	}
	slices.Sort(merged)
	first.ApplicationData = merged
	if first.ClientRandom == nil {
		first.ClientRandom = other.ClientRandom
	}
}

func tlsFailureReason(random *string, clientHello *int, found *randomSecretInfo, source string) *string {
	var msg string
	switch {
	case random == nil && clientHello == nil:
		msg = "no ClientHello in the capture (the session began before it), so no secret can be matched to it"
	case random == nil:
		msg = "its ClientHello could not be reassembled from the capture, so no secret can be matched to it"
	case found == nil:
		msg = fmt.Sprintf("%s hold no secret for this session (no line with its ClientHello random): the key log is from another session or client", source)
	default:
		missing := extract.MissingLabels(found.labels, "")
		extra := ""
		if len(missing) > 0 {
			extra = " but lack " + strings.Join(missing, ", ")
		}
		msg = "the secrets name this session's ClientHello random" + extra + ", and tshark did not decrypt it"
	}
	return &msg
}
