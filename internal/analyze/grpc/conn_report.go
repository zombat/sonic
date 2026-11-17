// Package grpc assembles per-connection HTTP/2 and gRPC telemetry rows.
package grpc

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
)

func (a *grpcAnalysis) connectionReport(conn *connTrack, ctx model.Context, tlsInfo *TLSView) ConnectionRow {
	disc := conn.disc
	var port *int
	if disc != nil {
		p := disc.ServicePort()
		port = &p
	} else if conn.server != nil {
		p := conn.server.Port
		port = &p
	}

	svcSet := make(map[string]bool)
	isGrpc := false
	for _, r := range conn.rpcs {
		if m := r.method(); m != nil && *m != "" {
			trimmed := strings.Trim(*m, "/")
			if strings.Contains(trimmed, "/") {
				svcSet[strings.SplitN(trimmed, "/", 2)[0]] = true
			}
		}
		if ct := r.header("content-type", "request"); ct != nil && strings.HasPrefix(*ct, "application/grpc") {
			isGrpc = true
		}
	}
	services := slices.Sorted(maps.Keys(svcSet))
	if services == nil {
		services = []string{}
	}

	transport := "cleartext"
	if conn.tlsSeen {
		transport = fmt.Sprintf("tls (decrypted with %s)", a.secretsSource)
	} else if disc != nil && disc.IsTLS() {
		transport = "tls"
	}

	var detectedPtr *string
	if disc != nil {
		var d string
		if disc.PrefaceFrame != nil {
			d = "preface"
		} else if disc.IsTLS() && slices.Contains(disc.ALPN, "h2") {
			d = "alpn h2"
		} else if port != nil && extract.GrpcPorts[*port] != "" {
			d = "grpc port"
		}
		if d != "" {
			detectedPtr = &d
		}
	}

	pingReport := make(map[string]PingStats)
	for _, pair := range []struct {
		side  string
		stats pingTrack
	}{
		{"client", conn.pingsClient},
		{"server", conn.pingsServer},
	} {
		st := pair.stats
		if st.sent == 0 {
			continue
		}
		var gaps []float64
		for i := 1; i < len(st.times); i++ {
			gaps = append(gaps, model.Round(st.times[i]-st.times[i-1], 3))
		}
		var rttMed, intMin, intMed *float64
		if len(st.rttMS) > 0 {
			s := slices.Clone(st.rttMS)
			slices.Sort(s)
			v := s[len(s)/2]
			rttMed = &v
		}
		if len(gaps) > 0 {
			minG := slices.Min(gaps)
			intMin = &minG
			sg := slices.Clone(gaps)
			slices.Sort(sg)
			medG := sg[len(sg)/2]
			intMed = &medG
		}
		pingReport[pair.side] = PingStats{
			Sent:            st.sent,
			Acked:           st.acked,
			RTTMSMedian:     rttMed,
			IntervalSMin:    intMin,
			IntervalSMedian: intMed,
			FirstFrame:      st.firstFrame,
		}
	}

	stalls := make([]StallRow, 0, len(conn.stalls))
	for _, st := range conn.stalls {
		endVal := st.t
		if st.reopenedT != nil {
			endVal = *st.reopenedT
		} else if st.endedT != nil && *st.endedT != 0 {
			endVal = *st.endedT
		} else if a.end != nil && *a.end != 0 {
			endVal = *a.end
		}
		stalls = append(stalls, StallRow{
			Sender:        st.sender,
			StreamID:      st.streamID,
			Method:        st.method,
			Window:        st.window,
			Frame:         st.frame,
			T:             ctx.Rel(&st.t),
			DurationS:     model.Round(endVal-st.t, 3),
			ReopenedFrame: st.reopenedFrame,
			Resolved:      st.reopenedT != nil,
			EndedBy:       st.endedBy,
			DataWaiting:   st.dataWaiting,
		})
	}

	var durationPtr *float64
	if conn.firstT != nil && conn.lastT != nil {
		d := model.Round(*conn.lastT-*conn.firstT, 3)
		durationPtr = &d
	}

	var svcStr, svcNamePtr *string
	if port != nil && *port != 0 {
		s := fmt.Sprintf("tcp/%d", *port)
		svcStr = &s
		if name := extract.GrpcPorts[*port]; name != "" {
			svcNamePtr = &name
		}
	}

	knownBy := conn.serverKnownBy
	if knownBy == "" {
		knownBy = "headers"
	}

	protocol := "unknown"
	switch {
	case isGrpc:
		protocol = "grpc"
	case len(conn.rpcs) > 0 || len(conn.framesByType) > 0:
		protocol = "http2"
	case disc != nil && slices.Contains(disc.ALPN, "h2"):
		protocol = "tls, h2 offered"
	case disc != nil && disc.IsTLS():
		protocol = "tls"
	}

	goaways := make([]GoawayRow, len(conn.goaways))
	copy(goaways, conn.goaways)
	rsts := make([]ResetInfo, len(conn.rstStreams))
	copy(rsts, conn.rstStreams)
	resets := []TCPResetRow{}
	if disc != nil {
		for _, r := range disc.Resets {
			resets = append(resets, TCPResetRow{
				Frame: r.Frame,
				From:  endpointPtr(&r.From),
			})
		}
	}
	osFrames := conn.oversizeFrames
	if osFrames == nil {
		osFrames = []OversizeFrameRow{}
	}
	osHeaders := conn.oversizeHeaders
	if osHeaders == nil {
		osHeaders = []OversizeHeaderRow{}
	}

	credKeys := slices.Sorted(maps.Keys(conn.credentials))
	if credKeys == nil {
		credKeys = []string{}
	}
	metaKeys := slices.Sorted(maps.Keys(conn.metadataKeys))
	if metaKeys == nil {
		metaKeys = []string{}
	}

	return ConnectionRow{
		Flow:                     endpointStr(conn.client) + " -> " + endpointStr(conn.server),
		Client:                   endpointPtr(conn.client),
		Server:                   endpointPtr(conn.server),
		Service:                  svcStr,
		ServiceName:              svcNamePtr,
		ServerKnownBy:            knownBy,
		Transport:                transport,
		DetectedBy:               detectedPtr,
		Protocol:                 protocol,
		Services:                 services,
		FirstFrame:               conn.firstFrame,
		T:                        ctx.Rel(conn.firstT),
		DurationS:                durationPtr,
		RPCs:                     len(conn.rpcs),
		RPCStatus:                make(map[string]int),
		FramesByType:             conn.framesByType,
		Settings:                 map[string]map[string]*int{"client": conn.settingsClient, "server": conn.settingsServer},
		MaxConcurrentStreamsUsed: conn.maxOpen,
		Pings:                    pingReport,
		Goaways:                  goaways,
		RstStreams:               rsts,
		FlowControl:              FlowControlInfo{Followed: conn.trackFlow, Stalls: stalls},
		OversizeFrames:           osFrames,
		OversizeHeaderLists:      osHeaders,
		TCPResets:                resets,
		CredentialKeys:           credKeys,
		MetadataKeys:             metaKeys,
		Capabilities:             conn.capabilities,
		TLS:                      tlsInfo,
	}
}
