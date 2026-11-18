package extract

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/model"
)

func buildMinimalPCAPNGSeed() []byte {
	var buf bytes.Buffer
	appendBlock := func(blockType uint32, body []byte) {
		pad := (4 - (len(body) % 4)) % 4
		total := uint32(12 + len(body) + pad)
		_ = binary.Write(&buf, binary.LittleEndian, blockType)
		_ = binary.Write(&buf, binary.LittleEndian, total)
		buf.Write(body)
		for range pad {
			buf.WriteByte(0)
		}
		_ = binary.Write(&buf, binary.LittleEndian, total)
	}
	var shb bytes.Buffer
	_ = binary.Write(&shb, binary.LittleEndian, uint32(0x1a2b3c4d))
	_ = binary.Write(&shb, binary.LittleEndian, uint16(1))
	_ = binary.Write(&shb, binary.LittleEndian, uint16(0))
	_ = binary.Write(&shb, binary.LittleEndian, int64(-1))
	appendBlock(0x0a0d0d0a, shb.Bytes())

	var idb bytes.Buffer
	_ = binary.Write(&idb, binary.LittleEndian, uint16(1))
	_ = binary.Write(&idb, binary.LittleEndian, uint16(0))
	_ = binary.Write(&idb, binary.LittleEndian, uint32(65535))
	appendBlock(0x00000001, idb.Bytes())

	var epb bytes.Buffer
	_ = binary.Write(&epb, binary.LittleEndian, uint32(0))
	_ = binary.Write(&epb, binary.LittleEndian, uint32(0))
	_ = binary.Write(&epb, binary.LittleEndian, uint32(1000))
	_ = binary.Write(&epb, binary.LittleEndian, uint32(14))
	_ = binary.Write(&epb, binary.LittleEndian, uint32(14))
	epb.Write(make([]byte, 14))
	appendBlock(0x00000006, epb.Bytes())
	return buf.Bytes()
}

func FuzzFastPathPCAP(f *testing.F) {
	for _, stem := range []string{"dp_tcp_health.pcap", "dp_qos_rtp.pcap", "ipsec_ikev2_esp.pcap"} {
		if raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", stem)); err == nil {
			f.Add(raw)
		}
	}
	f.Add(buildMinimalPCAPNGSeed())
	// Truncated/oversized length header to ensure bounded allocation without panic.
	badHdr := []byte{
		0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
		1, 0, 0, 0, 2, 0, 0, 0, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 1, 2, 3,
	}
	f.Add(badHdr)

	f.Fuzz(func(t *testing.T, data []byte) {
		capPkts := 64
		out := model.RecordsOutput{}
		_ = readFastPathReader(bytes.NewReader(data), FastPathOptions{MaxPackets: &capPkts}, &out)
	})
}

func FuzzDecodeFastPacket(f *testing.F) {
	f.Add(uint32(1), make([]byte, 64))
	f.Add(uint32(101), []byte{0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0, 80, 1, 187, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0, 0, 0, 0, 0})
	f.Add(uint32(113), make([]byte, 32))
	f.Add(uint32(276), make([]byte, 36))
	f.Add(uint32(0), []byte{2, 0, 0, 0, 0x45, 0, 0, 20})

	linkTypes := []uint32{0, 1, 101, 113, 276}
	f.Fuzz(func(t *testing.T, ltIdx uint32, frame []byte) {
		lt := linkTypes[int(ltIdx)%len(linkTypes)]
		_ = decodeFastFrame(1, 1700000000.0, len(frame), frame, lt)
	})
}

func FuzzParseSIPAndSDP(f *testing.F) {
	f.Add("crypto:1 AES_CM_128_HMAC_SHA1_80 inline:SuperSecretKey123|2^20|1:4", "42000", "RTP/AVP", "call-1@example.com", "101", "1")
	f.Add("key-mgmt:mikey AQAFgM0XflABAAAAAAAAAAAA", "8000", "UDP/TLS/RTP/SAVPF", "call-2", "105", "0")
	f.Add("fmtp:101 0-15", "5060", "RTP/AVP", "", "bad", "")

	f.Fuzz(func(t *testing.T, mediaAttr, portStr, proto, callID, eventID, endOfEvent string) {
		if len(mediaAttr) > 0 && strings.Contains(mediaAttr, "inline:") && !strings.Contains(mediaAttr, SIPCredentialMask) {
			masked := maskSDPMediaAttr(mediaAttr)
			if strings.Contains(masked, "SuperSecretKey123") {
				t.Fatalf("SRTP inline secret leaked in maskSDPMediaAttr: %q", masked)
			}
		}
		layers := map[string][]string{
			"sip.Call-ID":           {callID},
			"sip.Method":            {"INVITE"},
			"sdp.media.port":        {portStr},
			"sdp.media.proto":       {proto},
			"sdp.media_attr":        {mediaAttr},
			"rtpevent.event_id":     {eventID},
			"rtpevent.end_of_event": {endOfEvent},
		}
		_, _ = parseSIPPacketRow(layers, 1, "10.0.0.1", "10.0.0.2", "5060", "5060", 1.5, true)
		_, _ = parseRTPEventRow(layers, 1, 1.5, "10.0.0.1", "10.0.0.2", "42000", "42000", "0x1")
		specs := collectDynamicRTPDecodeSpecs([]map[string][]string{layers})
		if len(specs) > maxDynamicRTPDecodePorts {
			t.Fatalf("exceeded maxDynamicRTPDecodePorts: %d", len(specs))
		}
	})
}
