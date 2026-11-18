// Package model defines the normalized packet record types, detector report
// structures, and shared transport/status helpers used across S.O.N.I.C.
package model

// RecordsOutput matches the normalized packet extraction payload emitted by
// both Python and Go backends and compared against golden JSON fixtures.
type RecordsOutput struct {
	Backend       string   `json:"backend"`
	MissingFields []string `json:"missing_fields"`
	Warnings      []string `json:"warnings"`
	Records       []Record `json:"records"`
}

// Record holds the normalized decoded fields for a single captured frame.
type Record struct {
	N            int          `json:"n"`
	T            float64      `json:"t"`
	Len          int          `json:"len"`
	EthType      *int         `json:"eth_type,omitempty"`
	LLC          string       `json:"llc,omitempty"`
	IP           *IPHeader    `json:"ip,omitempty"`
	TCP          *TCPHeader   `json:"tcp,omitempty"`
	UDP          *UDPHeader   `json:"udp,omitempty"`
	Inner        *InnerPacket `json:"inner,omitempty"`
	GRE          *GREHeader   `json:"gre,omitempty"`
	IKE          *IKEHeader   `json:"ike,omitempty"`
	ESP          *ESPHeader   `json:"esp,omitempty"`
	NATKeepalive *bool        `json:"nat_keepalive,omitempty"`
	NHRP         *NHRPPacket  `json:"nhrp,omitempty"`
	BGP          []BGPMessage `json:"bgp,omitempty"`
	BGPNLRI      *int         `json:"bgp_nlri,omitempty"`
	BGPWithdrawn *int         `json:"bgp_withdrawn,omitempty"`
	OSPF         *OSPFPacket  `json:"ospf,omitempty"`
	EIGRP        *EIGRPPacket `json:"eigrp,omitempty"`
	ICMP         *ICMPPacket  `json:"icmp,omitempty"`
	ARP          *ARPPacket   `json:"arp,omitempty"`
	SIP          *bool        `json:"sip,omitempty"`
	DP           *DataPlane   `json:"dp,omitempty"`
}

// IPHeader captures the outer IPv4 or IPv6 header fields.
type IPHeader struct {
	V     int    `json:"v"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto *int   `json:"proto"`
	TTL   *int   `json:"ttl"`
}

// TCPHeader captures outer or inner TCP header metadata for a frame.
type TCPHeader struct {
	Sport *int `json:"sport"`
	Dport *int `json:"dport"`
	Flags int  `json:"flags"`
	Len   int  `json:"len"`
	MSS   *int `json:"mss,omitempty"`
	// Svc records the listening service port inferred across a TCP stream.
	Svc *int `json:"svc,omitempty"`
}

// UDPHeader captures outer or inner UDP port and length fields.
type UDPHeader struct {
	Sport *int `json:"sport"`
	Dport *int `json:"dport"`
	Len   int  `json:"len"`
}

// InnerPacket represents the IPv4 packet encapsulated inside a GRE tunnel.
type InnerPacket struct {
	Src          string       `json:"src"`
	Dst          string       `json:"dst"`
	Proto        *int         `json:"proto"`
	TCP          *TCPHeader   `json:"tcp,omitempty"`
	UDP          *UDPHeader   `json:"udp,omitempty"`
	IKE          *IKEHeader   `json:"ike,omitempty"`
	ESP          *ESPHeader   `json:"esp,omitempty"`
	NATKeepalive *bool        `json:"nat_keepalive,omitempty"`
	BGP          []BGPMessage `json:"bgp,omitempty"`
	BGPNLRI      *int         `json:"bgp_nlri,omitempty"`
	BGPWithdrawn *int         `json:"bgp_withdrawn,omitempty"`
	OSPF         *OSPFPacket  `json:"ospf,omitempty"`
	EIGRP        *EIGRPPacket `json:"eigrp,omitempty"`
}

// IKEHeader holds decoded IKEv1/IKEv2 header, payload, and SA proposal data.
type IKEHeader struct {
	Version        int           `json:"version"`
	ISPI           *string       `json:"ispi"`
	RSPI           *string       `json:"rspi"`
	Exch           *int          `json:"exch"`
	Flags          int           `json:"flags"`
	MsgID          uint32        `json:"msgid"`
	Length         uint32        `json:"length"`
	Notify         []int         `json:"notify"`
	Encrypted      bool          `json:"encrypted"`
	NATT           bool          `json:"natt"`
	Payloads       []int         `json:"payloads"`
	Proposals      []IKEProposal `json:"proposals"`
	KEGroup        *int          `json:"ke_group"`
	NATDSrc        []string      `json:"natd_src"`
	NATDDst        []string      `json:"natd_dst"`
	InvalidKEGroup *int          `json:"invalid_ke_group"`
	InvalidSPIs    []string      `json:"invalid_spis"`
}

// IKEProposal represents one cryptographic proposal inside an IKE SA payload.
type IKEProposal struct {
	Num        int            `json:"num"`
	Protocol   int            `json:"protocol"`
	SPI        *string        `json:"spi"`
	Transforms []IKETransform `json:"transforms"`
}

// IKETransform represents one algorithm transform inside an IKE proposal.
type IKETransform struct {
	Type      int  `json:"type"`
	ID        int  `json:"id"`
	KeyLength *int `json:"key_length"`
}

// ESPHeader captures IPsec ESP SPI, sequence number, and NAT-T UDP wrapping.
type ESPHeader struct {
	SPI uint32 `json:"spi"`
	Seq uint32 `json:"seq"`
	UDP bool   `json:"udp"`
}

// GREHeader captures GRE optional key and encapsulated Ethertype protocol.
type GREHeader struct {
	Key   *uint32 `json:"key"`
	Ptype *int    `json:"ptype"`
}

// NHRPPacket captures NHRP registration, resolution, purge, and error fields.
type NHRPPacket struct {
	Op          *int    `json:"op"`
	SrcNBMA     *string `json:"src_nbma"`
	SrcProto    *string `json:"src_proto"`
	DstProto    *string `json:"dst_proto"`
	ReqID       *uint32 `json:"reqid"`
	Code        *int    `json:"code"`
	ErrCode     *int    `json:"err_code"`
	ClientNBMA  *string `json:"client_nbma"`
	ClientProto *string `json:"client_proto"`
	Prefix      *int    `json:"prefix"`
	OrigSrc     *string `json:"orig_src"`
	OrigDst     *string `json:"orig_dst"`
}

// BGPMessage represents one decoded BGP message inside a TCP segment.
type BGPMessage struct {
	Type  int     `json:"type"`
	Len   *int    `json:"len"`
	MyAS  *int    `json:"myas"`
	Hold  *int    `json:"hold"`
	BGPID *string `json:"bgp_id"`
	AS4   *uint32 `json:"as4"`
	Major *int    `json:"major"`
	Minor *int    `json:"minor"`
	// Caps is nil for non-OPEN messages (serializes as JSON null) and non-nil for OPEN.
	Caps []int `json:"caps"`
}

// OSPFPacket captures OSPF header, Hello, and DBD fields.
type OSPFPacket struct {
	Type      *int     `json:"type"`
	RID       *string  `json:"rid"`
	Area      *string  `json:"area"`
	Auth      *int     `json:"auth"`
	Mask      *string  `json:"mask"`
	Hello     *int     `json:"hello"`
	Dead      *int     `json:"dead"`
	Prio      *int     `json:"prio"`
	DR        *string  `json:"dr"`
	BDR       *string  `json:"bdr"`
	Neighbors []string `json:"neighbors"`
	Options   *int     `json:"options"`
	MTU       *int     `json:"mtu"`
	DBDFlags  *int     `json:"dbd_flags"`
	DDSeq     *uint32  `json:"dd_seq"`
}

// EIGRPPacket captures EIGRP header, TLV list, K-values, and hold time fields.
type EIGRPPacket struct {
	Opcode *int   `json:"opcode"`
	AS     *int   `json:"as"`
	Flags  uint32 `json:"flags"`
	Seq    uint32 `json:"seq"`
	Ack    uint32 `json:"ack"`
	TLVs   []int  `json:"tlvs"`
	// K is nil when fewer than 5 K-values were decoded (serializes as JSON null).
	K    []int `json:"k"`
	Hold *int  `json:"hold"`
}

// ICMPPacket captures ICMPv4 or ICMPv6 fields including embedded errors.
type ICMPPacket struct {
	V6       bool      `json:"v6"`
	Type     *int      `json:"type"`
	Code     *int      `json:"code"`
	ID       *int      `json:"id"`
	Seq      *int      `json:"seq"`
	Src      *string   `json:"src"`
	Dst      *string   `json:"dst"`
	Tunneled bool      `json:"tunneled"`
	Orig     *ICMPOrig `json:"orig"`
}

// ICMPOrig holds the inner IP header summary embedded in an ICMP error message.
type ICMPOrig struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto *int   `json:"proto"`
	Dport *int   `json:"dport"`
}

// ARPPacket captures ARP opcode, protocol addresses, and sender MAC address.
type ARPPacket struct {
	Op  *int    `json:"op"`
	SPA *string `json:"spa"`
	TPA *string `json:"tpa"`
	SHA *string `json:"sha"`
}

// DataPlane captures IP/TCP/ICMP MTU, QoS, fragmentation, and payload head data.
type DataPlane struct {
	HL    int      `json:"hl"`
	TL    int      `json:"tl"`
	ID    *int     `json:"id"`
	DF    *int     `json:"df"`
	MF    *int     `json:"mf"`
	Off   int      `json:"off"`
	DSCP  int      `json:"dscp"`
	ECN   int      `json:"ecn"`
	Inner *DPInner `json:"inner,omitempty"`
	TCP   *DPTCP   `json:"tcp,omitempty"`
	PL    string   `json:"pl,omitempty"`
	PH    string   `json:"ph,omitempty"`
	ICMP  *DPICMP  `json:"icmp,omitempty"`
}

// DPInner captures the data-plane view of an IPv4 packet inside GRE.
type DPInner struct {
	TL   int  `json:"tl"`
	ID   *int `json:"id"`
	DF   int  `json:"df"`
	DSCP int  `json:"dscp"`
	ECN  int  `json:"ecn"`
}

// DPTCP captures TCP sequence/window/option details used by data-plane detectors.
type DPTCP struct {
	Seq  uint32 `json:"seq"`
	Ack  uint32 `json:"ack"`
	Win  int    `json:"win"`
	HL   int    `json:"hl"`
	MSS  *int   `json:"mss"`
	WS   *int   `json:"ws"`
	SACK bool   `json:"sack"`
	TS   bool   `json:"ts"`
}

// DPICMP captures ICMP fragmentation-needed MTU and original IP header fields.
type DPICMP struct {
	MTU     *int `json:"mtu"`
	OrigID  *int `json:"orig_id"`
	OrigLen *int `json:"orig_len"`
	OrigDF  *int `json:"orig_df"`
}
