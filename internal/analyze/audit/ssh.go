// Package audit implements SSH_MSG_KEXINIT parsing and RFC 4253 cipher negotiation.
package audit

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/model"
)

var (
	sshNameListKeys = []string{
		"kex", "host_key", "cipher_client_to_server", "cipher_server_to_client",
		"mac_client_to_server", "mac_server_to_client",
		"compression_client_to_server", "compression_server_to_client",
	}
	sshAEAD = map[string]bool{
		"chacha20-poly1305@openssh.com": true,
		"aes128-gcm@openssh.com":        true,
		"aes256-gcm@openssh.com":        true,
		"aes128-gcm":                    true,
		"aes256-gcm":                    true,
		"aead_aes_128_gcm":              true,
		"aead_aes_256_gcm":              true,
	}
	sshStrong = map[string]bool{
		"chacha20-poly1305@openssh.com": true,
		"aes128-gcm@openssh.com":        true,
		"aes256-gcm@openssh.com":        true,
		"aes128-gcm":                    true,
		"aes256-gcm":                    true,
		"aead_aes_128_gcm":              true,
		"aead_aes_256_gcm":              true,
		"aes128-ctr":                    true,
		"aes192-ctr":                    true,
		"aes256-ctr":                    true,
	}
	sshStateRank = map[tlsinspect.EncState]int{
		tlsinspect.StateEncrypted:  0,
		tlsinspect.StateNotStarted: 0,
		tlsinspect.StateWeak:       1,
		tlsinspect.StateUnverified: 2,
		tlsinspect.StateCleartext:  3,
	}
)

// ParseKexInit decodes the 8 name-lists of an SSH_MSG_KEXINIT payload (RFC 4253 7.1),
// returning nil when the payload is truncated or has the wrong message type.
func ParseKexInit(payload []byte) map[string][]string {
	if len(payload) < 17 || payload[0] != 20 {
		return nil
	}
	out := make(map[string][]string, len(sshNameListKeys))
	pos := 17
	for _, field := range sshNameListKeys {
		if pos+4 > len(payload) {
			return nil
		}
		length := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
		if length < 0 || pos+4+length > len(payload) {
			return nil
		}
		raw := decodeASCIIReplace(payload[pos+4 : pos+4+length])
		var list []string
		for _, item := range strings.Split(raw, ",") {
			if item != "" {
				list = append(list, item)
			}
		}
		out[field] = list
		pos += 4 + length
	}
	return out
}

// SSHChoose returns the first algorithm on client's list also offered by server.
func SSHChoose(client, server []string) *string {
	offered := make(map[string]bool, len(server))
	for _, s := range server {
		offered[s] = true
	}
	for _, c := range client {
		if offered[c] {
			chosen := c
			return &chosen
		}
	}
	return nil
}

// SSHCipher classifies one negotiated SSH cipher name into a state and explanation.
func SSHCipher(name *string) (tlsinspect.EncState, string) {
	if name == nil {
		return tlsinspect.StateUnverified, "the two KEXINITs offer no cipher in common, so the key exchange cannot complete"
	}
	low := strings.ToLower(*name)
	if low == "none" {
		return tlsinspect.StateCleartext, "the cipher none: SSH packets cross the link unencrypted"
	}
	if strings.HasPrefix(low, "arcfour") {
		return tlsinspect.StateWeak, *name + " is RC4, which RFC 8758 forbids"
	}
	if strings.Contains(low, "-cbc") || low == "des" || low == "3des" {
		return tlsinspect.StateWeak, *name + " is a CBC mode, open to plaintext recovery (CVE-2008-5161)"
	}
	if sshStrong[low] {
		return tlsinspect.StateEncrypted, ""
	}
	for _, weak64 := range []string{"3des", "blowfish", "cast128", "idea", "des"} {
		if strings.HasPrefix(low, weak64) {
			return tlsinspect.StateWeak, *name + " has a 64-bit block (Sweet32)"
		}
	}
	return tlsinspect.StateUnverified, fmt.Sprintf("the cipher %s is not one S.O.N.I.C. knows", *name)
}

func evaluateSSHEncryption(session *tcpSession, client, server endpointAddr) (*model.SessionEncryption, []endpointAddr) {
	mine := session.dirs[client]
	theirs := session.dirs[server]
	var ckex, skex map[string][]string
	if mine != nil {
		ckex = mine.kexinit
	}
	if theirs != nil {
		skex = theirs.kexinit
	}
	if ckex == nil || skex == nil {
		var missing []string
		if ckex == nil {
			missing = append(missing, "client's")
		}
		if skex == nil {
			missing = append(missing, "server's")
		}
		reason := fmt.Sprintf("the %s KEXINIT is not in the capture, so the cipher cannot be read", strings.Join(missing, " and "))
		return &model.SessionEncryption{
			State:             tlsinspect.StateUnverified.String(),
			HandshakeCaptured: false,
			Reason:            &reason,
		}, nil
	}

	overall := tlsinspect.StateEncrypted
	var whys [][2]string
	var readable []endpointAddr
	out := &model.SessionEncryption{
		State:             overall.String(),
		HandshakeCaptured: true,
		KexInitFrames: &model.KexInitFrames{
			Client: mine.kexinitFrame,
			Server: theirs.kexinitFrame,
		},
	}

	dirs := []struct {
		key    string
		label  string
		sender endpointAddr
	}{
		{"client_to_server", "client to server", client},
		{"server_to_client", "server to client", server},
	}
	for _, d := range dirs {
		cipher := SSHChoose(ckex["cipher_"+d.key], skex["cipher_"+d.key])
		state, why := SSHCipher(cipher)
		aead := cipher != nil && sshAEAD[strings.ToLower(*cipher)]
		var mac *string
		if !aead {
			mac = SSHChoose(ckex["mac_"+d.key], skex["mac_"+d.key])
		}
		if state == tlsinspect.StateEncrypted && !aead && mac != nil && strings.ToLower(*mac) == "none" {
			state = tlsinspect.StateWeak
			why = fmt.Sprintf("%s with the MAC none: encrypted, but not integrity-protected", *cipher)
		}

		macVal := mac
		if aead {
			implicit := "implicit (AEAD cipher)"
			macVal = &implicit
		}
		if d.key == "client_to_server" {
			out.CipherClientToServe = cipher
			out.MACClientToServer = macVal
		} else {
			out.CipherServerToClien = cipher
			out.MACServerToClient = macVal
		}

		if state == tlsinspect.StateCleartext {
			readable = append(readable, d.sender)
		}
		if why != "" {
			whys = append(whys, [2]string{d.label, why})
		}
		if sshStateRank[state] > sshStateRank[overall] {
			overall = state
		}
	}

	out.State = overall.String()
	if len(whys) == 2 && whys[0][1] == whys[1][1] {
		r := whys[0][1]
		out.Reason = &r
	} else if len(whys) > 0 {
		parts := make([]string, 0, len(whys))
		for _, w := range whys {
			parts = append(parts, fmt.Sprintf("%s: %s", w[0], w[1]))
		}
		r := strings.Join(parts, "; ")
		out.Reason = &r
	}
	return out, readable
}

func decodeASCIIReplace(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		if c < 0x80 {
			sb.WriteByte(c)
		} else {
			sb.WriteRune('\ufffd')
		}
	}
	return sb.String()
}
