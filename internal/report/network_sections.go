// Package report renders individual detector subsections for network_orchestrator Markdown
// reports (IPsec/VPN, GRE/NHRP, BGP/OSPF/EIGRP, reachability, timeline, and conversations).
package report

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/analyze/grenhrp"
	"github.com/zombat/sonic/internal/analyze/ipsec"
	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/analyze/reach"
	"github.com/zombat/sonic/internal/analyze/routing"
	"github.com/zombat/sonic/internal/model"
)

func appendNetworkIPsecMarkdown(sb *strings.Builder, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var sec ipsec.Report
	if json.Unmarshal(raw, &sec) != nil || sec.Status == model.StatusNotPresent {
		return
	}
	sb.WriteString("## IPsec / VPN\n\n")
	fmt.Fprintf(sb, "Encryption verdict: **%s**. %s.\n\n", sec.EncryptionVerdict, sec.NegotiationVerdict)
	pairRows := make([][]string, 0, len(sec.PeerPairs))
	for _, p := range sec.PeerPairs {
		b, _ := json.Marshal(p.ProtectedPackets)
		pairRows = append(pairRows, []string{strings.Join(p.Endpoints, " <-> "), p.Verdict, string(b), strconv.Itoa(p.CleartextPackets)})
	}
	sb.WriteString(MarkdownTable([]string{"endpoints", "verdict", "protected", "cleartext"}, pairRows))
	saRows := make([][]string, 0, len(sec.IKESAs))
	for _, s := range sec.IKESAs {
		saRows = append(saRows, []string{
			strconv.Itoa(s.IKEVersion), DerefStr(s.Initiator, ""), DerefStr(s.Responder, ""),
			s.Outcome, s.Detail, strconv.Itoa(s.Retransmissions), strconv.Itoa(s.Rekeys),
		})
	}
	sb.WriteString(MarkdownTable([]string{"version", "initiator", "responder", "outcome", "detail", "retransmissions", "rekeys"}, saRows))
	espRows := make([][]string, 0, len(sec.ESPFlows))
	for _, f := range sec.ESPFlows {
		espRows = append(espRows, []string{
			f.Src, f.Dst, f.SPI, YesNo(f.UDPEncapsulated), strconv.Itoa(f.Packets),
			strconv.Itoa(f.MissingSequenceNumbers), strconv.Itoa(f.DuplicateSequenceNumbers),
		})
	}
	sb.WriteString(MarkdownTable([]string{"src", "dst", "spi", "udp_encapsulated", "packets", "missing_sequence_numbers", "duplicate_sequence_numbers"}, espRows))
	fmt.Fprintf(sb, "NAT traversal: %s\n\n", sec.NATTraversal.Verdict)
}

func appendNetworkGREMarkdown(sb *strings.Builder, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var sec grenhrp.Report
	if json.Unmarshal(raw, &sec) != nil || sec.Status == model.StatusNotPresent {
		return
	}
	sb.WriteString("## GRE / NHRP (DMVPN)\n\n")
	fmt.Fprintf(sb, "DMVPN phase hint: %s\n\n", sec.DMVPNPhaseHint)
	regRows := make([][]string, 0, len(sec.Registrations))
	for _, r := range sec.Registrations {
		regRows = append(regRows, []string{r.SpokeNBMA, DerefStr(r.SpokeTunnelIP, ""), r.HubNBMA, DerefStr(r.HubTunnelIP, ""), r.Result})
	}
	sb.WriteString(MarkdownTable([]string{"spoke_nbma", "spoke_tunnel_ip", "hub_nbma", "hub_tunnel_ip", "result"}, regRows))
	tunRows := make([][]string, 0, len(sec.Tunnels))
	for _, t := range sec.Tunnels {
		keysB, _ := json.Marshal(t.GREKeys)
		inB, _ := json.Marshal(t.InnerProtocols)
		tunRows = append(tunRows, []string{t.Src, t.Dst, strconv.Itoa(t.Packets), string(keysB), string(inB)})
	}
	sb.WriteString(MarkdownTable([]string{"src", "dst", "packets", "keys", "inner"}, tunRows))
}

func appendNetworkRoutingMarkdown(sb *strings.Builder, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var sec routing.Report
	if json.Unmarshal(raw, &sec) != nil || sec.Status == model.StatusNotPresent {
		return
	}
	sb.WriteString("## Routing protocols\n\n")
	if sec.BGP.Present {
		sb.WriteString("### BGP\n\n")
		rows := make([][]string, 0, len(sec.BGP.Sessions))
		for _, s := range sec.BGP.Sessions {
			rows = append(rows, []string{strings.Join(s.Peers, " <-> "), s.State, YesNo(s.IBGP), DerefInt(s.NegotiatedHoldTime, ""), strconv.Itoa(s.TimesEstablished), strconv.Itoa(s.TimesDown)})
		}
		sb.WriteString(MarkdownTable([]string{"peers", "state", "ibgp", "hold", "established", "down"}, rows))
	}
	if sec.OSPF.Present {
		sb.WriteString("### OSPF\n\n")
		for _, link := range sec.OSPF.Links {
			fmt.Fprintf(sb, "Link %s (DR %s)\n\n", DerefStr(link.Network, ""), DerefStr(link.DR, ""))
			rows := make([][]string, 0, len(link.Routers))
			for _, r := range link.Routers {
				rows = append(rows, []string{r.RouterID, r.Address, DerefStr(r.Area, ""), DerefInt(r.HelloInterval, ""), DerefInt(r.DeadInterval, ""), DerefStr(r.NetworkMask, ""), strings.Join(r.NeighborsListed, ", ")})
			}
			sb.WriteString(MarkdownTable([]string{"router_id", "address", "area", "hello_interval", "dead_interval", "network_mask", "neighbors_listed"}, rows))
		}
	}
	if sec.EIGRP.Present {
		sb.WriteString("### EIGRP\n\n")
		for _, link := range sec.EIGRP.Links {
			rows := make([][]string, 0, len(link.Speakers))
			for _, s := range link.Speakers {
				kb, _ := json.Marshal(s.KValues)
				rows = append(rows, []string{s.Address, DerefInt(s.AS, ""), string(kb), DerefInt(s.HoldTime, ""), strconv.Itoa(s.Hellos), strconv.Itoa(s.Goodbyes)})
			}
			sb.WriteString(MarkdownTable([]string{"address", "as", "k_values", "hold_time", "hellos", "goodbyes"}, rows))
		}
	}
}

func appendNetworkReachTimelineConvMarkdown(sb *strings.Builder, rep netorch.NetworkReport) {
	if len(rep.Reachability) > 0 {
		var rSec reach.ReachReport
		if json.Unmarshal(rep.Reachability, &rSec) == nil && rSec.Status != model.StatusNotPresent {
			sb.WriteString("## Reachability\n\n")
			rows := make([][]string, 0, len(rSec.Echo))
			for _, p := range rSec.Echo {
				rttAvg := ""
				if p.RTTMs != nil {
					rttAvg = fmt.Sprintf("%v", p.RTTMs.Avg)
				}
				rows = append(rows, []string{p.Src, p.Dst, strconv.Itoa(p.Sent), strconv.Itoa(p.Answered), fmt.Sprintf("%v", p.LossPercent), rttAvg, strconv.Itoa(len(p.Outages))})
			}
			sb.WriteString(MarkdownTable([]string{"src", "dst", "sent", "answered", "loss_percent", "rtt_avg_ms", "outages"}, rows))
		}
	}
	if len(rep.Timeline) > 0 {
		sb.WriteString("## Timeline\n\n")
		rows := make([][]string, 0, len(rep.Timeline))
		for _, ev := range rep.Timeline {
			rows = append(rows, []string{fmt.Sprintf("%v", ev.T), ev.Protocol, ev.Event, ev.Detail, DerefInt(ev.Frame, "")})
		}
		sb.WriteString(MarkdownTable([]string{"t (s)", "protocol", "event", "detail", "frame"}, rows))
	}
	if len(rep.Conversations) > 0 {
		var cSec reach.ConversationsReport
		if json.Unmarshal(rep.Conversations, &cSec) == nil && cSec.Status != model.StatusNotPresent {
			sb.WriteString("## Conversations\n\n")
			pRows := make([][]string, 0, len(cSec.Protocols))
			for _, p := range cSec.Protocols {
				pRows = append(pRows, []string{p.Protocol, DerefStr(p.Service, ""), strconv.Itoa(p.Packets), strconv.Itoa(p.Bytes)})
			}
			sb.WriteString(MarkdownTable([]string{"protocol", "service", "packets", "bytes"}, pRows))
			tRows := make([][]string, 0, len(cSec.TopConversations))
			for _, c := range cSec.TopConversations {
				tRows = append(tRows, []string{c.A, c.B, strconv.Itoa(c.Packets), strconv.Itoa(c.Bytes)})
			}
			sb.WriteString(MarkdownTable([]string{"a", "b", "packets", "bytes"}, tRows))
		}
	}
}
