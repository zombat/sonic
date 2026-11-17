// Package extract provides a pure-Go libpcap fallback for extracting masked raw SIP
// UDP payloads when tshark is unavailable.
package extract

import (
	"encoding/binary"
	"os"
	"strings"
)

var sipStartLines = []string{
	"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS",
	"NOTIFY", "SUBSCRIBE", "PRACK", "UPDATE", "REFER", "INFO", "SIP/2.0",
}

// readSIPRawPCAP extracts masked UDP SIP message blocks from a libpcap file as a fallback.
func readSIPRawPCAP(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	if len(data) < 24 {
		return "", nil
	}
	var order binary.ByteOrder
	switch binary.LittleEndian.Uint32(data[0:4]) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.BigEndian
	default:
		return "", nil
	}
	linkType := order.Uint32(data[20:24])
	pos := 24
	var msgs []string
	for pos+16 <= len(data) {
		inclLen := int(order.Uint32(data[pos+8 : pos+12]))
		pos += 16
		if inclLen < 0 || pos+inclLen > len(data) {
			break
		}
		frame := data[pos : pos+inclLen]
		pos += inclLen
		payload := extractUDPFromFrame(frame, linkType)
		if len(payload) == 0 {
			continue
		}
		text := string(payload)
		lines := strings.SplitN(text, "\n", 2)
		if len(lines) == 0 {
			continue
		}
		first := strings.TrimSpace(lines[0])
		isSIP := false
		for _, pfx := range sipStartLines {
			if strings.HasPrefix(first, pfx) {
				isSIP = true
				break
			}
		}
		if isSIP {
			msgs = append(msgs, MaskSIPText(text))
		}
	}
	if len(msgs) == 0 {
		return "", nil
	}
	return strings.Join(msgs, "\n---PACKET---\n"), nil
}

// extractUDPFromFrame returns UDP payload bytes from Ethernet or Raw-IP captured frames.
func extractUDPFromFrame(frame []byte, linkType uint32) []byte {
	var l3 []byte
	switch linkType {
	case 1:
		if len(frame) < 14 {
			return nil
		}
		et := binary.BigEndian.Uint16(frame[12:14])
		off := 14
		if et == 0x8100 && len(frame) >= 18 {
			et = binary.BigEndian.Uint16(frame[16:18])
			off = 18
		}
		if et != 0x0800 {
			return nil
		}
		l3 = frame[off:]
	case 101:
		l3 = frame
	default:
		return nil
	}
	if len(l3) < 20 || (l3[0]>>4) != 4 || l3[9] != 17 {
		return nil
	}
	ihl := int(l3[0]&0x0f) * 4
	if ihl < 20 || len(l3) < ihl+8 {
		return nil
	}
	return l3[ihl+8:]
}
