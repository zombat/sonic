// Package extract parses SIP Digest/Basic authentication challenges, responses,
// and server posture metadata matching extractors/auth_info.py.
package extract

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

// AuthChallenge represents one 401 or 407 SIP authentication challenge packet.
type AuthChallenge struct {
	PacketNum     int    `json:"packet_num"`
	Timestamp     string `json:"timestamp"`
	StatusCode    string `json:"status_code"`
	ChallengeType string `json:"challenge_type"`
	FromIP        string `json:"from_ip"`
	ToIP          string `json:"to_ip"`
	Method        string `json:"method"`
	CallID        string `json:"call_id"`
	Realm         string `json:"realm"`
	Nonce         string `json:"nonce"`
	Algorithm     string `json:"algorithm"`
	QoP           string `json:"qop"`
	Opaque        string `json:"opaque"`
	Stale         bool   `json:"stale"`
	Domain        string `json:"domain"`
	FullHeader    string `json:"full_header"`
}

// AuthResponse summarizes one Authorization or Proxy-Authorization header without secret hashes.
type AuthResponse struct {
	PacketNum    int    `json:"packet_num"`
	Timestamp    string `json:"timestamp"`
	Method       string `json:"method"`
	RequestURI   string `json:"request_uri"`
	FromIP       string `json:"from_ip"`
	ToIP         string `json:"to_ip"`
	CallID       string `json:"call_id"`
	IsProxy      bool   `json:"is_proxy"`
	Username     string `json:"username"`
	Realm        string `json:"realm"`
	Nonce        string `json:"nonce"`
	URI          string `json:"uri"`
	ResponseHash string `json:"response_hash"`
	Algorithm    string `json:"algorithm"`
	QoP          string `json:"qop"`
	NC           string `json:"nc"`
	CNonce       string `json:"cnonce"`
	FullHeader   string `json:"full_header"`
}

// SIPServerAuthInfo aggregates authentication challenges seen per server IP.
type SIPServerAuthInfo struct {
	ChallengeCount   int      `json:"challenge_count"`
	ServerChallenges int      `json:"server_challenges"`
	ProxyChallenges  int      `json:"proxy_challenges"`
	Realms           []string `json:"realms"`
}

// AuthInfo holds extracted SIP challenges, responses, REGISTER lifecycles, and anomalies.
type AuthInfo struct {
	AuthChallenges   []AuthChallenge              `json:"auth_challenges"`
	AuthResponses    []AuthResponse               `json:"auth_responses"`
	RegisterAttempts []RegisterAttempt            `json:"register_attempts"`
	SIPServers       map[string]SIPServerAuthInfo `json:"sip_servers"`
	Realms           []string                     `json:"realms"`
	AuthAnomalies    []string                     `json:"auth_anomalies"`
}

var (
	authSchemeParamsRe = regexp.MustCompile(`^(\w+)\s+(.+)$`)
	authRealmRe        = regexp.MustCompile(`realm="([^"]*)"`)
	authDomainRe       = regexp.MustCompile(`domain="([^"]*)"`)
	authNonceRe        = regexp.MustCompile(`nonce="([^"]*)"`)
	authOpaqueRe       = regexp.MustCompile(`opaque="([^"]*)"`)
	authUserRe         = regexp.MustCompile(`username="([^"]*)"`)
	authURIRe          = regexp.MustCompile(`uri="([^"]*)"`)
	authResponseRe     = regexp.MustCompile(`response="([^"]*)"`)
	authCNonceRe       = regexp.MustCompile(`cnonce="([^"]*)"`)
	authAlgoRe         = regexp.MustCompile(`algorithm=([^\s,]+)`)
	authChalQoPRe      = regexp.MustCompile(`qop="?([^",\s]+)"?`)
	authRespQoPRe      = regexp.MustCompile(`qop=(\w+)`)
	authStaleRe        = regexp.MustCompile(`stale=(\w+)`)
	authNCRe           = regexp.MustCompile(`nc=([0-9a-f]+)`)
)

func shortenHeader(h string) string {
	if len(h) > 80 {
		return h[:80] + "..."
	}
	return h
}

func firstGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// ParseAuthenticationHeader parses WWW-Authenticate or Proxy-Authenticate Digest parameters.
func ParseAuthenticationHeader(headerValue string) (scheme, realm, domain, nonce, opaque, algo, qop string, stale bool) {
	algo = "MD5"
	if headerValue == "" {
		return
	}
	m := authSchemeParamsRe.FindStringSubmatch(headerValue)
	if m == nil {
		return
	}
	scheme = m[1]
	params := m[2]
	realm = firstGroup(authRealmRe, params)
	domain = firstGroup(authDomainRe, params)
	nonce = firstGroup(authNonceRe, params)
	opaque = firstGroup(authOpaqueRe, params)
	if a := firstGroup(authAlgoRe, params); a != "" {
		algo = strings.Trim(a, `"`)
	}
	qop = firstGroup(authChalQoPRe, params)
	stale = strings.EqualFold(firstGroup(authStaleRe, params), "true")
	return
}

// ParseAuthorizationHeader parses Authorization or Proxy-Authorization Digest parameters.
func ParseAuthorizationHeader(headerValue string) (scheme, username, realm, nonce, uri, response, opaque, algo, qop, nc, cnonce string) {
	algo = "MD5"
	if headerValue == "" {
		return
	}
	m := authSchemeParamsRe.FindStringSubmatch(headerValue)
	if m == nil {
		return
	}
	scheme = m[1]
	params := m[2]
	username = firstGroup(authUserRe, params)
	realm = firstGroup(authRealmRe, params)
	nonce = firstGroup(authNonceRe, params)
	uri = firstGroup(authURIRe, params)
	response = firstGroup(authResponseRe, params)
	opaque = firstGroup(authOpaqueRe, params)
	cnonce = firstGroup(authCNonceRe, params)
	if a := firstGroup(authAlgoRe, params); a != "" {
		algo = strings.Trim(a, `"`)
	}
	qop = firstGroup(authRespQoPRe, params)
	nc = firstGroup(authNCRe, params)
	return
}

// ExtractAuthChallenges returns 401 and 407 challenges extracted from sipPackets.
func ExtractAuthChallenges(sipPackets []SIPPacket) []AuthChallenge {
	out := []AuthChallenge{}
	for _, pkt := range sipPackets {
		hdr, cType := pkt.WWWAuthenticate, "server"
		if pkt.StatusCode == "407" {
			hdr, cType = pkt.ProxyAuthenticate, "proxy"
		} else if pkt.StatusCode != "401" {
			continue
		}
		if hdr == "" {
			continue
		}
		_, realm, domain, nonce, opaque, algo, qop, stale := ParseAuthenticationHeader(hdr)
		out = append(out, AuthChallenge{
			PacketNum: pkt.PacketNum, Timestamp: pkt.Time, StatusCode: pkt.StatusCode,
			ChallengeType: cType, FromIP: pkt.SrcIP, ToIP: pkt.DstIP,
			Method: pkt.Method, CallID: pkt.CallID, Realm: realm, Nonce: nonce,
			Algorithm: algo, QoP: qop, Opaque: opaque, Stale: stale, Domain: domain,
			FullHeader: hdr,
		})
	}
	return out
}

// ExtractAuthResponses returns masked Authorization and Proxy-Authorization metadata rows.
func ExtractAuthResponses(sipPackets []SIPPacket) []AuthResponse {
	out := []AuthResponse{}
	for _, pkt := range sipPackets {
		hdr := pkt.Authorization
		isProxy := false
		if hdr == "" {
			hdr = pkt.ProxyAuthorization
			isProxy = true
		}
		if hdr == "" {
			continue
		}
		_, user, realm, nonce, uri, resp, _, algo, qop, nc, cnonce := ParseAuthorizationHeader(hdr)
		respHash := ""
		if resp != "" {
			respHash = SIPCredentialMask
		}
		cnShort := ""
		if cnonce != "" {
			if len(cnonce) > 8 {
				cnShort = cnonce[:8] + "..."
			} else {
				cnShort = cnonce + "..."
			}
		}
		out = append(out, AuthResponse{
			PacketNum: pkt.PacketNum, Timestamp: pkt.Time, Method: pkt.Method,
			RequestURI: pkt.RequestURI, FromIP: pkt.SrcIP, ToIP: pkt.DstIP,
			CallID: pkt.CallID, IsProxy: isProxy, Username: user, Realm: realm,
			Nonce: nonce, URI: uri, ResponseHash: respHash, Algorithm: algo,
			QoP: qop, NC: nc, CNonce: cnShort,
			FullHeader: shortenHeader(MaskSIPCredentials(hdr)),
		})
	}
	return out
}

// ExtractAuthAndRegistrationInfo runs SIP extraction and compiles auth challenges, responses, and REGISTER attempts.
func ExtractAuthAndRegistrationInfo(ctx context.Context, filePath string) AuthInfo {
	summary, rawText, err := ExtractSIPData(ctx, filePath)
	if err != nil || (summary == nil && rawText == "") {
		return emptyAuthInfo()
	}
	var packets []SIPPacket
	if summary != nil {
		packets = summary.SIPPackets
	} else {
		var parsed SIPExtractionSummary
		if json.Unmarshal([]byte(rawText), &parsed) == nil {
			packets = parsed.SIPPackets
		}
	}
	return ExtractAuthFromPackets(packets)
}

// ExtractAuthFromPackets computes AuthInfo directly from pre-parsed SIPPacket slices.
func ExtractAuthFromPackets(packets []SIPPacket) AuthInfo {
	challenges := ExtractAuthChallenges(packets)
	responses := ExtractAuthResponses(packets)
	attempts := ExtractRegisterAttempts(packets)

	realmSeen := make(map[string]bool)
	realms := []string{}
	servers := make(map[string]*SIPServerAuthInfo)
	srvOrder := []string{}
	srvRealms := make(map[string]map[string]bool)

	for _, ch := range challenges {
		if ch.Realm != "" && !realmSeen[ch.Realm] {
			realmSeen[ch.Realm] = true
			realms = append(realms, ch.Realm)
		}
		ip := ch.FromIP
		if ip == "" {
			ip = "Unknown"
		}
		info, ok := servers[ip]
		if !ok {
			info = &SIPServerAuthInfo{Realms: []string{}}
			servers[ip] = info
			srvOrder = append(srvOrder, ip)
			srvRealms[ip] = make(map[string]bool)
		}
		info.ChallengeCount++
		if ch.ChallengeType == "server" {
			info.ServerChallenges++
		} else {
			info.ProxyChallenges++
		}
		if ch.Realm != "" && !srvRealms[ip][ch.Realm] {
			srvRealms[ip][ch.Realm] = true
			info.Realms = append(info.Realms, ch.Realm)
		}
	}
	slices.Sort(realms)
	srvOut := make(map[string]SIPServerAuthInfo, len(srvOrder))
	for _, ip := range srvOrder {
		info := *servers[ip]
		slices.Sort(info.Realms)
		srvOut[ip] = info
	}

	return AuthInfo{
		AuthChallenges:   challenges,
		AuthResponses:    responses,
		RegisterAttempts: attempts,
		SIPServers:       srvOut,
		Realms:           realms,
		AuthAnomalies:    DetectAuthAnomalies(challenges, attempts, responses),
	}
}

func emptyAuthInfo() AuthInfo {
	return AuthInfo{AuthChallenges: []AuthChallenge{}, AuthResponses: []AuthResponse{}, RegisterAttempts: []RegisterAttempt{}, SIPServers: map[string]SIPServerAuthInfo{}, Realms: []string{}, AuthAnomalies: []string{}}
}
