// Package grpc inspects TLS handshakes, certificates, and secret sources for gRPC streams.
package grpc

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

type tlsFlowKey struct {
	client string
	server string
}

type randomSecretInfo struct {
	labels  map[string]bool
	sources map[string]bool
}

type secretsInfo struct {
	KeyLogFile       bool
	PCAPNGBlocks     int
	ByRandom         map[string]randomSecretInfo
	Source           *string
	SessionsInKeyLog int
	SessionsInPCAPNG int
}

func secretsView(filePath, keylogFile string) secretsInfo {
	var keyLog map[string]map[string]bool
	if keylogFile != "" {
		if kl, err := extract.KeyLogLabels(keylogFile); err == nil {
			keyLog = kl
		}
	}
	blocks := 0
	var pcapLabels map[string]map[string]bool
	if res, err := extract.PCAPNGSecrets(filePath); err == nil && res != nil {
		blocks = res.Blocks
		pcapLabels = res.Labels
	}

	byRandom := make(map[string]randomSecretInfo)
	merge := func(source string, table map[string]map[string]bool) {
		for randHex, labels := range table {
			entry, ok := byRandom[randHex]
			if !ok {
				entry = randomSecretInfo{labels: make(map[string]bool), sources: make(map[string]bool)}
			}
			for lbl := range labels {
				entry.labels[lbl] = true
			}
			entry.sources[source] = true
			byRandom[randHex] = entry
		}
	}
	merge("key log", keyLog)
	merge("pcapng", pcapLabels)

	var names []string
	if keylogFile != "" {
		names = append(names, "the key log")
	}
	if blocks > 0 {
		names = append(names, "the secrets in the pcapng")
	}
	var srcPtr *string
	if len(names) > 0 {
		s := strings.Join(names, " and ")
		srcPtr = &s
	}
	return secretsInfo{
		KeyLogFile:       keylogFile != "",
		PCAPNGBlocks:     blocks,
		ByRandom:         byRandom,
		Source:           srcPtr,
		SessionsInKeyLog: len(keyLog),
		SessionsInPCAPNG: len(pcapLabels),
	}
}

func streamFilter(indexes []int, displayFilter string) string {
	sorted := slices.Clone(indexes)
	slices.Sort(sorted)
	parts := make([]string, len(sorted))
	for i, idx := range sorted {
		parts[i] = strconv.Itoa(idx)
	}
	flt := "tcp.stream in {" + strings.Join(parts, ", ") + "}"
	if displayFilter != "" {
		return fmt.Sprintf("(%s) && %s", displayFilter, flt)
	}
	return flt
}

func tlsSessions(
	ctx context.Context,
	filePath string,
	conns map[int]*extract.TCPConnection,
	displayFilter string,
	maxPackets *int,
) (map[tlsFlowKey]tlsinspect.Session, error) {
	var wanted []int
	for _, c := range conns {
		if !c.IsTLS() {
			continue
		}
		port := c.ServicePort()
		if slices.Contains(c.ALPN, "h2") || extract.GrpcPorts[port] != "" {
			wanted = append(wanted, c.Index)
		}
	}
	if len(wanted) == 0 {
		return map[tlsFlowKey]tlsinspect.Session{}, nil
	}
	out, err := extract.OpenNetworkRecords(ctx, tshark.StreamOptions{
		FilePath:      filePath,
		DisplayFilter: streamFilter(wanted, displayFilter),
		MaxPackets:    maxPackets,
	})
	if err != nil {
		return nil, err
	}
	det := tlsinspect.NewDetector(nil)
	var startPtr, endPtr *float64
	for i := range out.Records {
		rec := &out.Records[i]
		if rec.T != 0 {
			if startPtr == nil || rec.T < *startPtr {
				v := rec.T
				startPtr = &v
			}
			if endPtr == nil || rec.T > *endPtr {
				v := rec.T
				endPtr = &v
			}
		}
		det.Feed(rec)
	}
	rep := det.Report(model.Context{Start: startPtr, End: endPtr, MaxItems: 500})
	sessions := make(map[tlsFlowKey]tlsinspect.Session, len(rep.Sessions))
	for _, s := range rep.Sessions {
		sessions[tlsFlowKey{client: s.Client, server: s.Server}] = s
	}
	return sessions, nil
}

func tlsView(
	dconn *extract.TCPConnection,
	session *tlsinspect.Session,
	decrypted, keylogGiven bool,
	decryptedDER []byte,
	captureTime *float64,
	coverage *TLSSessionRow,
) TLSView {
	alpn := []string{}
	if len(dconn.ALPN) > 0 {
		alpn = slices.Clone(dconn.ALPN)
	}
	view := TLSView{
		SNI:         dconn.SNI,
		ALPNOffered: alpn,
		Decrypted:   decrypted,
		Hints:       []tlsinspect.HintRecord{},
	}
	if session != nil {
		view.hasSession = true
		alerts := []tlsinspect.AlertRecord{}
		if len(session.Alerts) > 0 {
			alerts = slices.Clone(session.Alerts)
		}
		hrr := session.HelloRetryRequest
		certCopy := session.Certificate
		view.Certificate = &certCopy
		view.Alerts = alerts
		view.HelloRetryRequest = &hrr
		if session.ServerChose != nil {
			v := session.ServerChose.Version
			cs := session.ServerChose.CipherSuite
			view.Version = &v
			view.CipherSuite = &cs
			view.ALPNChosen = session.ServerChose.ALPN
		}
		if len(decryptedDER) > 0 && !certCopy.Visible {
			body := make([]byte, 6+len(decryptedDER))
			total := len(decryptedDER) + 3
			dlen := len(decryptedDER)
			body[0], body[1], body[2] = byte(total>>16), byte(total>>8), byte(total)
			body[3], body[4], body[5] = byte(dlen>>16), byte(dlen>>8), byte(dlen)
			copy(body[6:], decryptedDER)
			ct := 0.0
			if captureTime != nil {
				ct = *captureTime
			}
			parsed := tlsinspect.ParseCertificate(body, ct)
			t := true
			parsed.DecryptedWithKeyLog = &t
			view.Certificate = &parsed
			srv := dconn.B
			if dconn.Server != nil {
				srv = *dconn.Server
			}
			ver := ""
			if view.Version != nil {
				ver = *view.Version
			}
			view.Hints = append(view.Hints, tlsinspect.SessionHints(srv.IP, dconn.SNI, ver, parsed)...)
		} else {
			view.Hints = append(view.Hints, session.Hints...)
		}
		if session.ServerChose == nil && session.ClientOffered != nil && len(session.Alerts) == 0 {
			view.Hints = append(view.Hints, tlsinspect.HintRecord{
				Code:     "TLS_NO_SERVER_HELLO",
				Severity: "warning",
				Text:     "ClientHello with no ServerHello: if this is a plaintext (insecure) gRPC port the client should not use TLS there; otherwise the server's TLS is not enabled or not answering",
			})
		}
	}
	if !decrypted {
		if keylogGiven {
			why := "the TLS secrets hold no keys for this session (or the session began before the capture)"
			if coverage != nil && coverage.Reason != nil && *coverage.Reason != "" {
				why = *coverage.Reason
			}
			view.Hints = append(view.Hints, tlsinspect.HintRecord{
				Code:     "GRPC_TLS_NOT_DECRYPTED",
				Severity: "info",
				Text:     why + ": the RPCs stay encrypted",
			})
		} else {
			view.Hints = append(view.Hints, tlsinspect.HintRecord{
				Code:     "GRPC_TLS_NOT_DECRYPTED",
				Severity: "info",
				Text:     "the RPCs are encrypted; have the client write a TLS key log while capturing (gnmic --log-tls-secret, SSLKEYLOGFILE for Python and curl, tls.Config.KeyLogWriter in Go) and pass the file as keylog_file to decode them",
			})
		}
	}
	return view
}

func mergeTLSState(first, second *extract.TLSDecryptionInfo) *extract.TLSDecryptionInfo {
	if first == nil {
		return second
	}
	if second == nil {
		return first
	}
	randHex := first.ClientRandom
	if randHex == nil {
		randHex = second.ClientRandom
	}
	chFrame := first.ClientHelloFrame
	if chFrame == nil {
		chFrame = second.ClientHelloFrame
	}
	cert := first.Certificate
	if len(cert) == 0 {
		cert = second.Certificate
	}
	seen := make(map[string]bool, len(first.ApplicationData)+len(second.ApplicationData))
	for _, s := range first.ApplicationData {
		seen[s] = true
	}
	for _, s := range second.ApplicationData {
		seen[s] = true
	}
	mergedApp := make([]string, 0, len(seen))
	for s := range seen {
		mergedApp = append(mergedApp, s)
	}
	slices.Sort(mergedApp)
	return &extract.TLSDecryptionInfo{
		ClientRandom:     randHex,
		ClientHelloFrame: chFrame,
		Handshake:        first.Handshake || second.Handshake,
		ApplicationData:  mergedApp,
		Certificate:      cert,
	}
}
