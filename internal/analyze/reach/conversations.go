// Package reach implements ConversationDetector for packet, byte, protocol,
// address-pair, and top-talker summaries.
package reach

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// ConversationsReport is the JSON output emitted by ConversationDetector.
type ConversationsReport struct {
	Detector                string              `json:"detector"`
	Status                  model.Status        `json:"status"`
	Verdict                 string              `json:"verdict"`
	Totals                  ConversationTotals  `json:"totals"`
	Protocols               []ProtocolStat      `json:"protocols"`
	ProtocolsOmitted        int                 `json:"protocols_omitted"`
	TopConversations        []ConversationEntry `json:"top_conversations"`
	TopConversationsOmitted int                 `json:"top_conversations_omitted"`
	TopTalkers              []TalkerEntry       `json:"top_talkers"`
	TopTalkersOmitted       int                 `json:"top_talkers_omitted"`
	Issues                  []model.Issue       `json:"issues"`
	Events                  []model.Event       `json:"events"`
}

// ConversationTotals captures overall packet/byte/host counts for the capture.
type ConversationTotals struct {
	Packets      int      `json:"packets"`
	Bytes        int      `json:"bytes"`
	DurationS    *float64 `json:"duration_s"`
	AddressPairs int      `json:"address_pairs"`
	HostsSending int      `json:"hosts_sending"`
}

// ProtocolStat summarizes traffic for one protocol label.
type ProtocolStat struct {
	Protocol string  `json:"protocol"`
	Service  *string `json:"service"`
	Packets  int     `json:"packets"`
	Bytes    int     `json:"bytes"`
}

// DirTraffic captures directional packet and byte counts.
type DirTraffic struct {
	Packets int `json:"packets"`
	Bytes   int `json:"bytes"`
}

// ConversationEntry summarizes bidirectional traffic for one address pair.
type ConversationEntry struct {
	A         string         `json:"a"`
	B         string         `json:"b"`
	Packets   int            `json:"packets"`
	Bytes     int            `json:"bytes"`
	AToB      DirTraffic     `json:"a_to_b"`
	BToA      DirTraffic     `json:"b_to_a"`
	Protocols map[string]int `json:"protocols"`
}

// TalkerEntry summarizes outbound traffic sent by one source IP address.
type TalkerEntry struct {
	Address     string `json:"address"`
	PacketsSent int    `json:"packets_sent"`
	BytesSent   int    `json:"bytes_sent"`
}

type convTrack struct {
	a, b       string
	packets    int
	bytes      int
	aToB       DirTraffic
	bToA       DirTraffic
	protoOrder []string
	protocols  map[string]int
}

type talkerTrack struct {
	addr    string
	packets int
	bytes   int
}

// ConversationDetector aggregates overall protocol mix, top conversations, and top talkers.
type ConversationDetector struct {
	packets       int
	bytes         int
	protocols     map[string][2]int
	conversations map[[2]string]*convTrack
	convOrder     [][2]string
	talkers       map[string]*talkerTrack
	talkerOrder   []string
}

// NewConversationDetector returns an initialized ConversationDetector.
func NewConversationDetector() *ConversationDetector {
	return &ConversationDetector{
		protocols:     make(map[string][2]int),
		conversations: make(map[[2]string]*convTrack),
		talkers:       make(map[string]*talkerTrack),
	}
}

// Name returns the canonical detector name "conversations".
func (d *ConversationDetector) Name() string { return "conversations" }

// Present reports whether any packets were fed.
func (d *ConversationDetector) Present() bool { return d.packets > 0 }

// Feed records one packet's protocol label, size, pair, and sender stats.
func (d *ConversationDetector) Feed(rec *model.Record) {
	d.packets++
	d.bytes += rec.Len
	label := model.ProtocolLabel(rec)
	st := d.protocols[label]
	st[0]++
	st[1] += rec.Len
	d.protocols[label] = st

	if rec.IP == nil {
		return
	}
	src, dst := rec.IP.Src, rec.IP.Dst
	key := model.PairKey(src, dst)
	conv, ok := d.conversations[key]
	if !ok {
		conv = &convTrack{a: key[0], b: key[1], protocols: make(map[string]int)}
		d.conversations[key] = conv
		d.convOrder = append(d.convOrder, key)
	}
	conv.packets++
	conv.bytes += rec.Len
	if src == key[0] {
		conv.aToB.Packets++
		conv.aToB.Bytes += rec.Len
	} else {
		conv.bToA.Packets++
		conv.bToA.Bytes += rec.Len
	}
	if _, seen := conv.protocols[label]; !seen {
		conv.protoOrder = append(conv.protoOrder, label)
	}
	conv.protocols[label]++

	tk, ok := d.talkers[src]
	if !ok {
		tk = &talkerTrack{addr: src}
		d.talkers[src] = tk
		d.talkerOrder = append(d.talkerOrder, src)
	}
	tk.packets++
	tk.bytes += rec.Len
}

// Report finalizes protocol mix, conversations, and talker rankings.
func (d *ConversationDetector) Report(ctx model.Context) ConversationsReport {
	protoList := make([]ProtocolStat, 0, len(d.protocols))
	for label, counts := range d.protocols {
		var svcPtr *string
		if svc, ok := model.LabelService(label); ok {
			s := svc
			svcPtr = &s
		}
		protoList = append(protoList, ProtocolStat{
			Protocol: label, Service: svcPtr, Packets: counts[0], Bytes: counts[1],
		})
	}
	slices.SortStableFunc(protoList, func(a, b ProtocolStat) int {
		if a.Bytes != b.Bytes {
			return b.Bytes - a.Bytes
		}
		return strings.Compare(a.Protocol, b.Protocol)
	})

	convTracks := make([]*convTrack, 0, len(d.convOrder))
	for _, k := range d.convOrder {
		convTracks = append(convTracks, d.conversations[k])
	}
	slices.SortStableFunc(convTracks, func(a, b *convTrack) int {
		return b.bytes - a.bytes
	})
	convList := make([]ConversationEntry, 0, len(convTracks))
	for _, c := range convTracks {
		topProtos := topNProtocols(c.protoOrder, c.protocols, 5)
		convList = append(convList, ConversationEntry{
			A: c.a, B: c.b, Packets: c.packets, Bytes: c.bytes,
			AToB: c.aToB, BToA: c.bToA, Protocols: topProtos,
		})
	}

	talkerTracks := make([]*talkerTrack, 0, len(d.talkerOrder))
	for _, addr := range d.talkerOrder {
		talkerTracks = append(talkerTracks, d.talkers[addr])
	}
	slices.SortStableFunc(talkerTracks, func(a, b *talkerTrack) int {
		return b.bytes - a.bytes
	})
	talkerList := make([]TalkerEntry, 0, len(talkerTracks))
	for _, t := range talkerTracks {
		talkerList = append(talkerList, TalkerEntry{
			Address: t.addr, PacketsSent: t.packets, BytesSent: t.bytes,
		})
	}

	var durPtr *float64
	durText := "None"
	if ctx.Start != nil && ctx.End != nil {
		dv := model.Round(*ctx.End-*ctx.Start, 3)
		durPtr = &dv
		durText = model.FormatPyFloat(dv)
	}
	verdict := "Empty capture."
	status := model.StatusNotPresent
	if d.packets > 0 {
		status = model.StatusOK
		top := ""
		if len(protoList) > 0 {
			top = protoList[0].Protocol
		}
		verdict = fmt.Sprintf("%d packets, %d bytes over %s s; %d address pair(s); most bytes: %s",
			d.packets, d.bytes, durText, len(convList), top)
	}

	convsCap, convsOm := model.Cap(convList, ctx.MaxItems)
	talkersCap, talkersOm := model.Cap(talkerList, ctx.MaxItems)
	protoLimit := ctx.MaxItems * 2
	if ctx.MaxItems < 0 {
		protoLimit = -1
	}
	protosCap, protosOm := model.Cap(protoList, protoLimit)

	return ConversationsReport{
		Detector: d.Name(), Status: status, Verdict: verdict,
		Totals: ConversationTotals{
			Packets: d.packets, Bytes: d.bytes, DurationS: durPtr,
			AddressPairs: len(convList), HostsSending: len(talkerList),
		},
		Protocols: protosCap, ProtocolsOmitted: protosOm,
		TopConversations: convsCap, TopConversationsOmitted: convsOm,
		TopTalkers: talkersCap, TopTalkersOmitted: talkersOm,
		Issues: []model.Issue{}, Events: []model.Event{},
	}
}

func topNProtocols(order []string, counts map[string]int, limit int) map[string]int {
	keys := slices.Clone(order)
	slices.SortStableFunc(keys, func(a, b string) int {
		return counts[b] - counts[a]
	})
	out := make(map[string]int, min(len(keys), limit))
	for i := 0; i < len(keys) && i < limit; i++ {
		out[keys[i]] = counts[keys[i]]
	}
	return out
}
