// Package extract tracks SIP REGISTER lifecycles and detects authentication anomalies.
package extract

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RegisterPacketEvent represents a request, 401/407 challenge, or 200 OK response in a REGISTER attempt.
type RegisterPacketEvent struct {
	Type       string `json:"type"`
	PacketNum  int    `json:"packet_num"`
	Timestamp  string `json:"timestamp"`
	FromIP     string `json:"from_ip"`
	ToIP       string `json:"to_ip"`
	FromAddr   string `json:"from_addr"`
	ToAddr     string `json:"to_addr"`
	RequestURI string `json:"request_uri"`
	HasAuth    bool   `json:"has_auth"`
	Expires    string `json:"expires"`
	Contact    string `json:"contact"`
	StatusCode string `json:"status_code"`
	Realm      string `json:"realm"`
	Nonce      string `json:"nonce"`
}

// MarshalJSON emits exact per-type fields matching extractors/auth_info.py:extract_register_attempts.
func (e RegisterPacketEvent) MarshalJSON() ([]byte, error) {
	switch e.Type {
	case "challenge":
		type challengeEvent struct {
			PacketNum  int    `json:"packet_num"`
			Timestamp  string `json:"timestamp"`
			Type       string `json:"type"`
			StatusCode string `json:"status_code"`
			FromIP     string `json:"from_ip"`
			ToIP       string `json:"to_ip"`
			Realm      string `json:"realm"`
			Nonce      string `json:"nonce"`
		}
		return json.Marshal(challengeEvent{
			PacketNum: e.PacketNum, Timestamp: e.Timestamp, Type: e.Type, StatusCode: e.StatusCode,
			FromIP: e.FromIP, ToIP: e.ToIP, Realm: e.Realm, Nonce: e.Nonce,
		})
	case "response":
		type responseEvent struct {
			PacketNum  int    `json:"packet_num"`
			Timestamp  string `json:"timestamp"`
			Type       string `json:"type"`
			StatusCode string `json:"status_code"`
			FromIP     string `json:"from_ip"`
			ToIP       string `json:"to_ip"`
			Expires    string `json:"expires"`
		}
		return json.Marshal(responseEvent{
			PacketNum: e.PacketNum, Timestamp: e.Timestamp, Type: e.Type, StatusCode: e.StatusCode,
			FromIP: e.FromIP, ToIP: e.ToIP, Expires: e.Expires,
		})
	default:
		type requestEvent struct {
			PacketNum  int    `json:"packet_num"`
			Timestamp  string `json:"timestamp"`
			Type       string `json:"type"`
			FromIP     string `json:"from_ip"`
			ToIP       string `json:"to_ip"`
			FromAddr   string `json:"from_addr"`
			ToAddr     string `json:"to_addr"`
			RequestURI string `json:"request_uri"`
			HasAuth    bool   `json:"has_auth"`
			Expires    string `json:"expires"`
			Contact    string `json:"contact"`
		}
		return json.Marshal(requestEvent{
			PacketNum: e.PacketNum, Timestamp: e.Timestamp, Type: e.Type, FromIP: e.FromIP, ToIP: e.ToIP,
			FromAddr: e.FromAddr, ToAddr: e.ToAddr, RequestURI: e.RequestURI, HasAuth: e.HasAuth,
			Expires: e.Expires, Contact: e.Contact,
		})
	}
}

// RegisterAttempt groups all REGISTER requests, challenges, and 200 responses sharing one Call-ID.
type RegisterAttempt struct {
	CallID        string                `json:"call_id"`
	Packets       []RegisterPacketEvent `json:"packets"`
	Success       bool                  `json:"success"`
	Authenticated bool                  `json:"authenticated"`
	Count         int                   `json:"count"`
}

// ExtractRegisterAttempts groups REGISTER transactions by Call-ID matching extractors/auth_info.py.
func ExtractRegisterAttempts(packets []SIPPacket) []RegisterAttempt {
	byCall := make(map[string][]RegisterPacketEvent)
	order := []string{}

	add := func(cid string, ev RegisterPacketEvent) {
		if _, exists := byCall[cid]; !exists {
			order = append(order, cid)
		}
		byCall[cid] = append(byCall[cid], ev)
	}

	for _, pkt := range packets {
		cid := pkt.CallID
		if cid == "" {
			cid = "Unknown"
		}
		switch {
		case pkt.Method == "REGISTER":
			add(cid, RegisterPacketEvent{
				Type: "request", PacketNum: pkt.PacketNum, Timestamp: pkt.Time,
				FromIP: pkt.SrcIP, ToIP: pkt.DstIP, FromAddr: pkt.FromAddr, ToAddr: pkt.ToAddr,
				RequestURI: pkt.RequestURI, HasAuth: pkt.Authorization != "" || pkt.ProxyAuthorization != "",
				Expires: pkt.Expires, Contact: pkt.Contact,
			})
		case pkt.Method == "" && (pkt.StatusCode == "401" || pkt.StatusCode == "407") && strings.Contains(pkt.CSeqMethod, "REGISTER"):
			hdr := pkt.WWWAuthenticate
			if hdr == "" {
				hdr = pkt.ProxyAuthenticate
			}
			nonce := firstGroup(authNonceRe, hdr)
			if nonce != "" {
				if len(nonce) > 16 {
					nonce = nonce[:16] + "..."
				} else {
					nonce += "..."
				}
			}
			add(cid, RegisterPacketEvent{
				Type: "challenge", PacketNum: pkt.PacketNum, Timestamp: pkt.Time,
				StatusCode: pkt.StatusCode, FromIP: pkt.SrcIP, ToIP: pkt.DstIP,
				Realm: firstGroup(authRealmRe, hdr), Nonce: nonce,
			})
		case pkt.StatusCode == "200" && strings.Contains(pkt.CSeqMethod, "REGISTER"):
			add(cid, RegisterPacketEvent{
				Type: "response", PacketNum: pkt.PacketNum, Timestamp: pkt.Time,
				StatusCode: "200", FromIP: pkt.SrcIP, ToIP: pkt.DstIP, Expires: pkt.Expires,
			})
		}
	}

	attempts := []RegisterAttempt{}
	for _, cid := range order {
		evts := byCall[cid]
		if len(evts) == 0 {
			continue
		}
		success, authed, reqCount := false, false, 0
		for _, ev := range evts {
			if ev.StatusCode == "200" {
				success = true
			}
			if ev.Type == "request" {
				reqCount++
				if ev.HasAuth {
					authed = true
				}
			}
		}
		attempts = append(attempts, RegisterAttempt{
			CallID: cid, Packets: evts, Success: success, Authenticated: authed, Count: reqCount,
		})
	}
	return attempts
}

// DetectAuthAnomalies returns human-readable security findings matching extractors/auth_info.py.
func DetectAuthAnomalies(challenges []AuthChallenge, attempts []RegisterAttempt, responses []AuthResponse) []string {
	anomalies := []string{}
	if len(challenges) > 3 {
		anomalies = append(anomalies, fmt.Sprintf("⚠️ Excessive authentication challenges detected (%d). May indicate credential issues or replay attacks.", len(challenges)))
	}
	failedCount := 0
	for _, a := range attempts {
		if !a.Success {
			failedCount++
		}
	}
	if failedCount > 0 {
		anomalies = append(anomalies, fmt.Sprintf("⚠️ %d REGISTER attempt(s) failed. May indicate registration service issues or credential problems.", failedCount))
	}
	weakCount, noQoPCount, proxy407, staleCount := 0, 0, 0, 0
	for _, c := range challenges {
		up := strings.ToUpper(c.Algorithm)
		if up == "" || up == "MD5" {
			weakCount++
		}
		if c.QoP == "" {
			noQoPCount++
		}
		if c.StatusCode == "407" {
			proxy407++
		}
		if c.Stale {
			staleCount++
		}
	}
	if weakCount > 0 {
		anomalies = append(anomalies, fmt.Sprintf("🔓 Weak authentication algorithm (MD5) detected in %d challenge(s). Consider upgrading to SHA-256.", weakCount))
	}
	if noQoPCount > 0 && float64(noQoPCount) > float64(len(challenges))/2.0 {
		anomalies = append(anomalies, fmt.Sprintf("🔓 Quality-of-Protection (qop) missing in %d challenge(s). Security is reduced without auth-int or replay protection.", noQoPCount))
	}
	if proxy407 > 2 {
		anomalies = append(anomalies, fmt.Sprintf("⚠️ Cascading proxy challenges detected (%d 407 responses). May indicate proxy chain configuration issues.", proxy407))
	}
	if staleCount > 0 {
		anomalies = append(anomalies, fmt.Sprintf("ℹ️ Stale nonce flag set in %d challenge(s). Server is forcing nonce refresh (normal behavior but affects performance).", staleCount))
	}
	if len(responses) > 0 && failedCount > 0 {
		authedSuccess := 0
		for _, a := range attempts {
			if a.Authenticated {
				authedSuccess++
			}
		}
		if authedSuccess == 0 {
			anomalies = append(anomalies, "⚠️ No successful authenticated REGISTER requests detected. All registration attempts may be failing due to authentication issues.")
		}
	}
	return anomalies
}
