// Package extract decodes HTTP/2 frames and allowlisted protobuf fields from PDML trees.
package extract

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// MaxDataKeep caps HTTP/2 DATA payload retention per frame at 64 KiB.
const MaxDataKeep = 65536

// FrameTypes maps RFC 9113 HTTP/2 frame type bytes to canonical names.
var FrameTypes = map[int]string{
	0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS",
	5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION",
}

// SettingsNames maps HTTP/2 SETTINGS parameter IDs to names.
var SettingsNames = map[int]string{
	1: "header_table_size", 2: "enable_push", 3: "max_concurrent_streams",
	4: "initial_window_size", 5: "max_frame_size", 6: "max_header_list_size",
	8: "enable_connect_protocol",
}

// ProtobufShownFields enumerates gNMI/gNOI field names safe to display in diagnostic reports.
var ProtobufShownFields = map[string]bool{
	"pbf.gnmi.GetRequest.encoding": true, "pbf.gnmi.GetRequest.type": true,
	"pbf.gnmi.SubscriptionList.mode": true, "pbf.gnmi.SubscriptionList.encoding": true,
	"pbf.gnmi.SubscriptionList.updates_only": true, "pbf.gnmi.Subscription.mode": true,
	"pbf.gnmi.Subscription.sample_interval": true, "pbf.gnmi.CapabilityResponse.gNMI_version": true,
	"pbf.gnmi.CapabilityResponse.supported_encodings": true, "pbf.gnmi.SubscribeResponse.sync_response": true,
	"pbf.gnmi.PathElem.name": true, "pbf.gnmi.Path.origin": true, "pbf.gnmi.Error.code": true,
	"pbf.gnmi.Error.message": true, "pbf.gnmi.UpdateResult.op": true, "pbf.gnoi.system.TimeResponse.time": true,
}

var (
	pbMessageRe = regexp.MustCompile(`\(Message: ([\w.]+)\)`)
	pbHeadRe    = regexp.MustCompile(`^Protocol Buffers: ([^,]+),(request|response)`)
)

// packetFromPDML converts one PDML <packet> into an HTTP2Packet, or nil if no HTTP/2 or protobuf layer is present.
func packetFromPDML(pkt *pdmlPacket, ext *HTTP2Extraction) *HTTP2Packet {
	out := &HTTP2Packet{}
	hasStream := false
	for i := range pkt.Protos {
		p := &pkt.Protos[i]
		switch p.Name {
		case "geninfo":
			if s := pdmlShow(p.Fields, "num"); s != nil {
				out.N, _ = parseFieldInt(*s)
			}
			if f := pdmlFirst(p.Fields, "timestamp"); f != nil && f.Value != nil {
				out.T, _ = strconv.ParseFloat(*f.Value, 64)
			}
		case "ip", "ipv6":
			if out.Src == "" {
				out.Src = strDeref(pdmlShow(p.Fields, p.Name+".src"))
				out.Dst = strDeref(pdmlShow(p.Fields, p.Name+".dst"))
			}
		case "tcp":
			if !hasStream {
				if s := pdmlShow(p.Fields, "tcp.stream"); s != nil {
					if idx, ok := parseFieldInt(*s); ok {
						out.TCPStream = idx
						hasStream = true
					}
				}
				if s := pdmlShow(p.Fields, "tcp.srcport"); s != nil {
					if v, ok := parseFieldInt(*s); ok {
						out.Sport = &v
					}
				}
				if s := pdmlShow(p.Fields, "tcp.dstport"); s != nil {
					if v, ok := parseFieldInt(*s); ok {
						out.Dport = &v
					}
				}
			}
		case "tls":
			out.TLS = true
		case "http2":
			for j := range p.Fields {
				ch := &p.Fields[j]
				if ch.Name == "http2.magic" {
					out.Frames = append(out.Frames, HTTP2Frame{Type: "MAGIC"})
				} else if ch.Name == "http2.stream" {
					if fr := frameFromPDML(ch, ext); fr != nil {
						out.Frames = append(out.Frames, *fr)
					}
				}
			}
		case "protobuf":
			out.Protobuf = append(out.Protobuf, protobufFromPDML(p))
		}
	}
	if !hasStream || (len(out.Frames) == 0 && len(out.Protobuf) == 0) {
		return nil
	}
	return out
}

// frameFromPDML extracts one HTTP/2 frame (HEADERS, DATA, SETTINGS, RST_STREAM, GOAWAY, PING, WINDOW_UPDATE).
func frameFromPDML(streamField *pdmlField, ext *HTTP2Extraction) *HTTP2Frame {
	tStr := pdmlShow(streamField.Fields, "http2.type")
	if tStr == nil {
		if pdmlFirst(streamField.Fields, "http2.magic") != nil {
			return &HTTP2Frame{Type: "MAGIC"}
		}
		return nil
	}
	ftype, ok := parseFieldInt(*tStr)
	if !ok {
		return nil
	}
	typeName := FrameTypes[ftype]
	if typeName == "" {
		typeName = fmt.Sprintf("TYPE_%d", ftype)
	}
	sid, _ := parseFieldInt(strDeref(pdmlShow(streamField.Fields, "http2.streamid")))
	flen, _ := parseFieldInt(strDeref(pdmlShow(streamField.Fields, "http2.length")))
	flags, _ := parseFieldInt(strDeref(pdmlShow(streamField.Fields, "http2.flags")))

	fr := &HTTP2Frame{Type: typeName, TypeCode: ftype, StreamID: sid, Length: flen, Flags: flags}
	if ftype == 0 || ftype == 1 {
		fr.EndStream = (flags & 0x01) != 0
	}
	if ftype == 1 || ftype == 9 {
		fr.EndHeaders = (flags & 0x04) != 0
		parsePDMLHeaderBlock(streamField, fr, ext)
	}
	if ftype == 4 || ftype == 6 {
		fr.Ack = (flags & 0x01) != 0
	}
	switch ftype {
	case 0:
		if f := pdmlFirst(streamField.Fields, "http2.data.data"); f != nil && f.Value != nil {
			rawHex := *f.Value
			fr.DataLen = len(rawHex) / 2
			if len(rawHex) > MaxDataKeep*2 {
				rawHex = rawHex[:MaxDataKeep*2]
			}
			if decoded, err := hex.DecodeString(rawHex); err == nil {
				fr.Data = decoded
			}
		}
	case 3:
		if v, ok := parseFieldInt(strDeref(pdmlShow(streamField.Fields, "http2.rst_stream.error"))); ok {
			fr.ErrorCode = &v
		}
	case 4:
		settings := make(map[string]*int)
		for i := range streamField.Fields {
			item := &streamField.Fields[i]
			if item.Name != "http2.settings" {
				continue
			}
			pid, ok := parseFieldInt(strDeref(pdmlShow(item.Fields, "http2.settings.id")))
			if !ok {
				continue
			}
			var valPtr *int
			for k := range item.Fields {
				ch := &item.Fields[k]
				if ch.Name != "http2.settings.id" && ch.Show != nil {
					if v, ok := parseFieldInt(*ch.Show); ok {
						valPtr = &v
					}
				}
			}
			sName := SettingsNames[pid]
			if sName == "" {
				sName = fmt.Sprintf("id_%d", pid)
			}
			settings[sName] = valPtr
		}
		fr.Settings = settings
	case 6:
		name := "http2.ping"
		if fr.Ack {
			name = "http2.pong"
		}
		if p := pdmlFirst(streamField.Fields, name); p != nil {
			if p.Value != nil && *p.Value != "" {
				fr.Opaque = *p.Value
			} else if p.Show != nil {
				fr.Opaque = *p.Show
			}
		}
	case 7:
		if v, ok := parseFieldInt(strDeref(pdmlShow(streamField.Fields, "http2.goaway.last_stream_id"))); ok {
			fr.LastStreamID = &v
		}
		if v, ok := parseFieldInt(strDeref(pdmlShow(streamField.Fields, "http2.goaway.error"))); ok {
			fr.ErrorCode = &v
		}
		if d := pdmlFirst(streamField.Fields, "http2.goaway.addata"); d != nil && d.Value != nil && *d.Value != "" {
			if rawBytes, err := hex.DecodeString(*d.Value); err == nil {
				var sb strings.Builder
				for _, r := range string(rawBytes) {
					if unicode.IsPrint(r) {
						sb.WriteRune(r)
						if sb.Len() >= 200 {
							break
						}
					}
				}
				s := sb.String()
				fr.DebugData = &s
			}
		}
	case 8:
		fr.Increment, _ = parseFieldInt(strDeref(pdmlShow(streamField.Fields, "http2.window_update.window_size_increment")))
	}
	return fr
}

// parsePDMLHeaderBlock decodes HPACK header pairs, applies SHOWN_HEADERS allowlisting,
// and records credential secrets in ext for downstream scrubbing.
func parsePDMLHeaderBlock(streamField *pdmlField, fr *HTTP2Frame, ext *HTTP2Extraction) {
	unresolved := false
	hasHeadersField := false
	hasCount := pdmlShow(streamField.Fields, "http2.header.count") != nil

	for i := range streamField.Fields {
		ch := &streamField.Fields[i]
		if ch.Name == "http2.headers" {
			hasHeadersField = true
		}
		if ch.Name != "http2.header" {
			continue
		}
		namePtr := pdmlShow(ch.Fields, "http2.header.name")
		if namePtr == nil {
			continue
		}
		name := *namePtr
		if name == "<unknown>" {
			unresolved = true
			continue
		}
		val := strDeref(pdmlShow(ch.Fields, "http2.header.value"))
		fr.HeaderListSize += len(name) + len(val) + 32
		kind := HeaderKind(name)
		if kind == "shown" {
			if strings.EqualFold(name, "grpc-message") {
				if u, err := url.PathUnescape(val); err == nil {
					val = u
				}
			}
			v := val
			fr.Headers = append(fr.Headers, HTTP2Header{Name: name, Value: &v})
		} else {
			if kind == "credential" && len(val) >= MinScrubLength {
				if IdentityNameRe.MatchString(name) {
					ext.IdentityValues[val] = true
				} else {
					ext.SecretValues[val] = true
					if sp := strings.IndexByte(val, ' '); sp >= 0 {
						ext.SecretValues[val[sp+1:]] = true
					}
				}
			}
			fr.Headers = append(fr.Headers, HTTP2Header{Name: name, Value: nil, Masked: true, Credential: kind == "credential"})
		}
	}
	fr.DecodeFailed = unresolved || (hasHeadersField && len(fr.Headers) == 0 && !hasCount)
}

// protobufFromPDML extracts message type, gRPC path/direction, and allowlisted gNMI/gNOI fields.
func protobufFromPDML(p *pdmlProto) ProtobufMsg {
	var msg ProtobufMsg
	if m := pbMessageRe.FindStringSubmatch(p.Showname); len(m) > 1 {
		msg.MessageType = &m[1]
	}
	if m := pbHeadRe.FindStringSubmatch(p.Showname); len(m) > 2 {
		msg.Path = &m[1]
		msg.Direction = &m[2]
	}
	var walk func(fields []pdmlField)
	walk = func(fields []pdmlField) {
		for i := range fields {
			f := &fields[i]
			if ProtobufShownFields[f.Name] && len(msg.Fields) < 64 {
				val := strDeref(f.Show)
				if idx := strings.Index(f.Showname, ": "); idx >= 0 {
					val = f.Showname[idx+2:]
				}
				msg.Fields = append(msg.Fields, ProtobufField{Field: strings.TrimPrefix(f.Name, "pbf."), Value: val})
			}
			walk(f.Fields)
		}
	}
	walk(p.Fields)
	return msg
}
