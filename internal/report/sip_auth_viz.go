// Package report renders SIP authentication realm trees and ASCII/Mermaid registration
// sequence diagrams matching utils/reporting.py.
package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

// FormatRealmServerMapping formats an ASCII tree mapping SIP servers to realms, algorithms, and QoP posture.
func FormatRealmServerMapping(auth *extract.AuthInfo) string {
	if auth == nil {
		return "   No authentication data available"
	}
	if len(auth.SIPServers) == 0 {
		return "   No SIP servers with authentication detected"
	}
	ips := make([]string, 0, len(auth.SIPServers))
	for ip := range auth.SIPServers {
		ips = append(ips, ip)
	}
	slices.Sort(ips)

	var lines []string
	for _, serverIP := range ips {
		info := auth.SIPServers[serverIP]
		role := "SIP Server"
		switch {
		case info.ProxyChallenges > info.ServerChallenges:
			role = "SIP Proxy"
		case info.ServerChallenges > 0:
			role = "SIP Registrar/Server"
		}
		lines = append(lines, fmt.Sprintf("   📡 Server: %s (%s)", serverIP, role))
		if len(info.Realms) > 0 {
			for i, realm := range info.Realms {
				isLast := i == len(info.Realms)-1
				prefix := "   ├─"
				subPrefix := "   │  "
				if isLast {
					prefix = "   └─"
					subPrefix = "      "
				}
				lines = append(lines, fmt.Sprintf("%s Realm: %q", prefix, realm))

				var matched []extract.AuthChallenge
				for _, ch := range auth.AuthChallenges {
					if ch.Realm == realm && (ch.FromIP == serverIP || ch.ToIP == serverIP) {
						matched = append(matched, ch)
					}
				}
				if len(matched) > 0 {
					algoStatus, qopInd, withQoP := summarizeRealmChallenges(matched)
					lines = append(lines, fmt.Sprintf("%s   Challenges: %d", subPrefix, len(matched)))
					lines = append(lines, fmt.Sprintf("%s   Algorithm: %s", subPrefix, algoStatus))
					lines = append(lines, fmt.Sprintf("%s   QoP: %s %d/%d with qop", subPrefix, qopInd, withQoP, len(matched)))
				}
			}
		} else {
			lines = append(lines, fmt.Sprintf("   └─ Challenges: %d (realm unknown)", info.ChallengeCount))
		}
		lines = append(lines, "")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

func summarizeRealmChallenges(matched []extract.AuthChallenge) (algoStatus, qopInd string, withQoP int) {
	algos := make(map[string]bool)
	hasWeak, hasStrong := false, false
	for _, ch := range matched {
		if a := strings.ToUpper(ch.Algorithm); a != "" {
			algos[a] = true
			if a == "MD5" {
				hasWeak = true
			} else if a == "SHA-256" || a == "SHA-512" {
				hasStrong = true
			}
		}
		if ch.QoP != "" {
			withQoP++
		}
	}
	switch {
	case hasWeak && hasStrong:
		algoStatus = "⚠️ Mixed (MD5 + SHA-256)"
	case hasWeak:
		algoStatus = "⚠️ Weak (MD5)"
	case hasStrong:
		algoStatus = "✅ Strong (SHA-256+)"
	case len(algos) > 0:
		names := make([]string, 0, len(algos))
		for a := range algos {
			names = append(names, a)
		}
		slices.Sort(names)
		algoStatus = strings.Join(names, ", ")
	default:
		algoStatus = "Unknown"
	}
	switch {
	case withQoP == len(matched):
		qopInd = "✅"
	case withQoP == 0:
		qopInd = "❌"
	default:
		qopInd = "⚠️"
	}
	return algoStatus, qopInd, withQoP
}

// GenerateAuthSequenceASCII generates an ASCII art sequence diagram for one REGISTER lifecycle.
func GenerateAuthSequenceASCII(attempt extract.RegisterAttempt, challenges []extract.AuthChallenge) string {
	if len(attempt.Packets) == 0 {
		return "   No packet sequence available"
	}
	lines := []string{
		fmt.Sprintf("   %-20s %s", "Client", "Server"),
		"      │                    │",
	}
	for _, pkt := range attempt.Packets {
		switch pkt.Type {
		case "request":
			label := "REGISTER"
			if pkt.HasAuth {
				label = "REGISTER (with Auth)"
			}
			lines = append(lines, fmt.Sprintf("      │  %-17s │  [Packet #%d]", label, pkt.PacketNum))
			lines = append(lines, "      │ ──────────────────> │")
		case "challenge":
			label := pkt.StatusCode + " Challenge"
			lines = append(lines, fmt.Sprintf("      │      %-12s │  [Packet #%d]", label, pkt.PacketNum))
			lines = append(lines, "      │ <────────────────── │")
			if ch, ok := findAuthChallenge(challenges, pkt.PacketNum); ok && ch.Realm != "" {
				realm := ch.Realm
				if len(realm) > 15 {
					realm = realm[:15]
				}
				algo := defaultWhenEmpty(ch.Algorithm, "MD5")
				lines = append(lines, fmt.Sprintf("      │   realm=%q", realm))
				lines = append(lines, "      │   algorithm="+algo)
			}
		case "response":
			label := pkt.StatusCode + " OK"
			lines = append(lines, fmt.Sprintf("      │      %-12s │  [Packet #%d]", label, pkt.PacketNum))
			lines = append(lines, "      │ <────────────────── │")
		}
		lines = append(lines, "      │                    │")
	}
	return strings.Join(lines, "\n")
}

// GenerateMermaidAuthSequence renders a fenced Mermaid sequenceDiagram for one REGISTER flow.
func GenerateMermaidAuthSequence(attempt extract.RegisterAttempt, challenges []extract.AuthChallenge) string {
	if len(attempt.Packets) == 0 {
		return ""
	}
	cid := attempt.CallID
	if cid == "" {
		cid = "unknown"
	}
	if len(cid) > 20 {
		cid = cid[:20]
	}
	lines := []string{
		"```mermaid",
		"sequenceDiagram",
		"    participant Client",
		"    participant Server",
		"    Note over Client,Server: Call-ID: " + cid,
	}
	for _, pkt := range attempt.Packets {
		switch pkt.Type {
		case "request":
			if pkt.HasAuth {
				lines = append(lines, "    Client->>Server: REGISTER (with Authorization)")
			} else {
				lines = append(lines, "    Client->>Server: REGISTER")
			}
			lines = append(lines, fmt.Sprintf("    Note right of Client: Packet #%d", pkt.PacketNum))
		case "challenge":
			lines = append(lines, fmt.Sprintf("    Server->>Client: %s Challenge", pkt.StatusCode))
			if ch, ok := findAuthChallenge(challenges, pkt.PacketNum); ok {
				algo := defaultWhenEmpty(ch.Algorithm, "MD5")
				qop := defaultWhenEmpty(ch.QoP, "none")
				lines = append(lines, fmt.Sprintf("    Note left of Server: realm=%q<br/>algorithm=%s<br/>qop=%s", ch.Realm, algo, qop))
			} else {
				lines = append(lines, fmt.Sprintf("    Note left of Server: Packet #%d", pkt.PacketNum))
			}
		case "response":
			lines = append(lines, fmt.Sprintf("    Server->>Client: %s OK", pkt.StatusCode))
			lines = append(lines, fmt.Sprintf("    Note left of Server: Packet #%d", pkt.PacketNum))
		}
	}
	if attempt.Success {
		lines = append(lines, "    Note over Client,Server: ✅ Registration Successful")
	} else {
		lines = append(lines, "    Note over Client,Server: ❌ Registration Failed")
	}
	lines = append(lines, "```")
	return strings.Join(lines, "\n")
}

func findAuthChallenge(challenges []extract.AuthChallenge, pktNum int) (extract.AuthChallenge, bool) {
	for _, ch := range challenges {
		if ch.PacketNum == pktNum {
			return ch, true
		}
	}
	return extract.AuthChallenge{}, false
}
