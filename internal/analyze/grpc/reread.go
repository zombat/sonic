// Package grpc handles HTTP/2 out-of-order reread recovery and TLS state probing helpers.
package grpc

import (
	"context"
	"fmt"

	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

func rereadStuckStreams(
	ctx context.Context,
	filePath string,
	opts Options,
	decodeAs, protoDirs []string,
	disc map[int]*extract.TCPConnection,
	analysis *grpcAnalysis,
	wanted map[int]bool,
	secretsGiven bool,
	secretVals, identVals map[string]bool,
	statusMeta map[string]string,
) []RereadRow {
	reread := []RereadRow{}
	stuck := undecodedStreams(analysis, disc, wanted, secretsGiven)
	if len(stuck) == 0 {
		return reread
	}
	again, rErr := extract.IterHTTP2Packets(ctx, filePath, decodeAs, opts.KeylogFile, protoDirs,
		streamFilter(stuck, opts.DisplayFilter), opts.MaxPackets, false)
	if rErr != nil {
		statusMeta["reread_error"] = rErr.Error()
		return reread
	}
	if again == nil {
		return reread
	}
	second := newGrpcAnalysis(disc, analysis.secretsSource)
	stuckSet := make(map[int]bool, len(stuck))
	for _, idx := range stuck {
		stuckSet[idx] = true
	}
	for i := range again.Packets {
		if stuckSet[again.Packets[i].TCPStream] {
			second.feed(&again.Packets[i])
		}
	}
	for s := range again.SecretValues {
		secretVals[s] = true
	}
	for s := range again.IdentityValues {
		identVals[s] = true
	}
	for _, idx := range stuck {
		before, after := 0, 0
		if old := analysis.conns[idx]; old != nil {
			before = old.packetsClient + old.packetsServer + old.packetsUnknown
		}
		if nw := second.conns[idx]; nw != nil {
			after = nw.packetsClient + nw.packetsServer + nw.packetsUnknown
			if after > before {
				analysis.conns[idx] = nw
				analysis.packets += after - before
				reread = append(reread, RereadRow{
					TCPStream: idx, HTTP2PacketsBefore: before, HTTP2PacketsAfter: after,
				})
			}
		}
	}
	if second.start != nil && (analysis.start == nil || *second.start < *analysis.start) {
		v := *second.start
		analysis.start = &v
	}
	if second.end != nil && (analysis.end == nil || *second.end > *analysis.end) {
		v := *second.end
		analysis.end = &v
	}
	return reread
}

func probeTLSDetails(
	ctx context.Context,
	filePath string,
	opts Options,
	decodeAs []string,
	disc map[int]*extract.TCPConnection,
	includeTLS, anyTLS, secretsGiven bool,
	statusMeta map[string]string,
) (map[tlsFlowKey]tlsinspect.Session, map[int]*extract.TLSDecryptionInfo) {
	sessions := make(map[tlsFlowKey]tlsinspect.Session)
	state := make(map[int]*extract.TLSDecryptionInfo)
	if !includeTLS || !anyTLS {
		return sessions, state
	}
	if ts, err := tlsSessions(ctx, filePath, disc, opts.DisplayFilter, opts.MaxPackets); err != nil {
		statusMeta["tls_error"] = fmt.Sprintf("%T: %s", err, err)
	} else {
		sessions = ts
	}
	if secretsGiven {
		st, err := extract.TLSDecryption(ctx, filePath, decodeAs, opts.KeylogFile, opts.DisplayFilter, opts.MaxPackets, true)
		if err != nil {
			statusMeta["tls_error"] = fmt.Sprintf("%T: %s", err, err)
		} else if st != nil {
			state = st
			var retry []int
			for idx, c := range disc {
				if c.IsTLS() {
					inf := state[idx]
					if inf == nil || (!inf.Handshake && len(inf.ApplicationData) == 0) {
						retry = append(retry, idx)
					}
				}
			}
			if len(retry) > 0 {
				if st2, err2 := extract.TLSDecryption(ctx, filePath, decodeAs, opts.KeylogFile, streamFilter(retry, opts.DisplayFilter), opts.MaxPackets, false); err2 == nil {
					for _, idx := range retry {
						state[idx] = mergeTLSState(state[idx], st2[idx])
					}
				}
			}
		}
	}
	return sessions, state
}

func appendCaptureTLSAlerts(
	coverage *TLSDecryptionSummary,
	secrets secretsInfo,
	secretsGiven bool,
	disc map[int]*extract.TCPConnection,
	reread []RereadRow,
	issues *[]model.Issue,
) {
	if coverage != nil && secretsGiven {
		for _, row := range coverage.Sessions {
			if row.Decrypted {
				continue
			}
			frames := []int{}
			if row.ClientHelloFrame != nil {
				frames = []int{*row.ClientHelloFrame}
			}
			reason := ""
			if row.Reason != nil {
				reason = *row.Reason
			}
			*issues = append(*issues, model.MakeIssue(model.SeverityWarning, "TLS_SESSION_NOT_DECRYPTED",
				fmt.Sprintf("%s (%s): not decrypted: %s", row.Flow, row.Service, reason), frames))
		}
	}
	if secrets.PCAPNGBlocks > 0 {
		*issues = append(*issues, model.MakeIssue(model.SeverityInfo, "TLS_SECRETS_IN_CAPTURE",
			fmt.Sprintf("the capture carries TLS secrets in %d Decryption Secrets Block(s) (%d session(s)), used to decrypt it with no separate key log: anyone with this file can read the sessions they cover",
				secrets.PCAPNGBlocks, secrets.SessionsInPCAPNG), []int{}))
	}
	for i := range reread {
		if dc := disc[reread[i].TCPStream]; dc != nil {
			cli, srv := dc.A, dc.B
			if dc.Client != nil {
				cli = *dc.Client
			}
			if dc.Server != nil {
				srv = *dc.Server
			}
			f := endpointStr(&cli) + " -> " + endpointStr(&srv)
			reread[i].Flow = &f
		}
	}
}
