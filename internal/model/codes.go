// Package model defines protocol code tables, hint maps, and IKE/BGP/NHRP
// lookup helpers mirroring analyzers/network_common.py.
package model

import (
	"encoding/json"
	"fmt"
)

// ProtectedLabels identifies packet protocol labels treated as IPsec/NAT-T protected traffic.
var ProtectedLabels = map[string]bool{
	"esp":           true,
	"esp-in-udp":    true,
	"ike":           true,
	"nat-keepalive": true,
	"ah":            true,
}

// IKEv2Exchanges maps IKEv2 exchange type numbers to canonical names.
var IKEv2Exchanges = map[int]string{
	34: "IKE_SA_INIT",
	35: "IKE_AUTH",
	36: "CREATE_CHILD_SA",
	37: "INFORMATIONAL",
	38: "IKE_SESSION_RESUME",
	43: "IKE_INTERMEDIATE",
	44: "IKE_FOLLOWUP_KE",
}

// IKEv1Exchanges maps IKEv1 exchange type numbers to canonical names.
var IKEv1Exchanges = map[int]string{
	1:  "Base",
	2:  "Main Mode",
	3:  "Authentication Only",
	4:  "Aggressive Mode",
	5:  "Informational",
	6:  "Transaction (Config Mode)",
	32: "Quick Mode",
	33: "New Group Mode",
}

// IKEv2Notify maps IKEv2 Notify message type numbers to IANA symbol names.
var IKEv2Notify = map[int]string{
	1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION",
	7: "INVALID_SYNTAX", 9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN",
	17: "INVALID_KE_PAYLOAD", 24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED",
	35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE", 37: "FAILED_CP_REQUIRED",
	38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS", 40: "UNACCEPTABLE_ADDRESSES",
	41: "UNEXPECTED_NAT_DETECTED", 43: "TEMPORARY_FAILURE", 44: "CHILD_SA_NOT_FOUND",
	45: "INVALID_GROUP_ID", 46: "AUTHORIZATION_FAILED",
	16384: "INITIAL_CONTACT", 16385: "SET_WINDOW_SIZE", 16386: "ADDITIONAL_TS_POSSIBLE",
	16387: "IPCOMP_SUPPORTED", 16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
	16390: "COOKIE", 16391: "USE_TRANSPORT_MODE", 16392: "HTTP_CERT_LOOKUP_SUPPORTED",
	16393: "REKEY_SA", 16394: "ESP_TFC_PADDING_NOT_SUPPORTED", 16395: "NON_FIRST_FRAGMENTS_ALSO",
	16396: "MOBIKE_SUPPORTED", 16404: "MULTIPLE_AUTH_SUPPORTED", 16406: "EAP_ONLY_AUTHENTICATION",
	16418: "IKEV2_FRAGMENTATION_SUPPORTED", 16431: "SIGNATURE_HASH_ALGORITHMS",
}

// IKEv2NotifyHints explains common IKEv2 error notification codes for operators.
var IKEv2NotifyHints = map[int]string{
	14: "the peers share no common proposal: compare the IKEv2 proposal (encryption, integrity, PRF, DH group) on both ends",
	17: "the initiator offered a DH group the responder does not accept; it normally retries with the group the responder names",
	24: "pre-shared key, certificate or identity mismatch",
	38: "traffic selectors (crypto ACL / proxy identities) do not match",
	7:  "a malformed message, often a mismatched IKE version or proposal syntax",
	4:  "the peer has no IKE SA for this SPI (it restarted or cleared its SAs)",
	11: "the peer has no IPsec SA for this SPI (stale SA after a rekey or restart)",
	43: "the peer is busy (rekey collision); a retry normally succeeds",
}

// IKEv1Notify maps IKEv1 Notify type numbers to symbol names.
var IKEv1Notify = map[int]string{
	1: "INVALID-PAYLOAD-TYPE", 2: "DOI-NOT-SUPPORTED", 3: "SITUATION-NOT-SUPPORTED", 4: "INVALID-COOKIE",
	5: "INVALID-MAJOR-VERSION", 6: "INVALID-MINOR-VERSION", 7: "INVALID-EXCHANGE-TYPE", 8: "INVALID-FLAGS",
	9: "INVALID-MESSAGE-ID", 10: "INVALID-PROTOCOL-ID", 11: "INVALID-SPI", 12: "INVALID-TRANSFORM-ID",
	13: "ATTRIBUTES-NOT-SUPPORTED", 14: "NO-PROPOSAL-CHOSEN", 15: "BAD-PROPOSAL-SYNTAX",
	16: "PAYLOAD-MALFORMED", 17: "INVALID-KEY-INFORMATION", 18: "INVALID-ID-INFORMATION",
	19: "INVALID-CERT-ENCODING", 20: "INVALID-CERTIFICATE", 21: "CERT-TYPE-UNSUPPORTED",
	22: "INVALID-CERT-AUTHORITY", 23: "INVALID-HASH-INFORMATION", 24: "AUTHENTICATION-FAILED",
	25: "INVALID-SIGNATURE", 26: "ADDRESS-NOTIFICATION", 27: "NOTIFY-SA-LIFETIME",
	28: "CERTIFICATE-UNAVAILABLE", 29: "UNSUPPORTED-EXCHANGE-TYPE", 30: "UNEQUAL-PAYLOAD-LENGTHS",
	24576: "RESPONDER-LIFETIME", 24577: "REPLAY-STATUS", 24578: "INITIAL-CONTACT",
	36136: "R-U-THERE", 36137: "R-U-THERE-ACK",
}

// IKEv2TransformTypes maps IKEv2 transform type codes to field labels.
var IKEv2TransformTypes = map[int]string{
	1: "encryption",
	2: "prf",
	3: "integrity",
	4: "dh_group",
	5: "esn",
}

// IKEv2TransformIDs maps transform type -> transform ID -> algorithm name.
var IKEv2TransformIDs = map[int]map[int]string{
	1: {
		1: "DES-IV64", 2: "DES", 3: "3DES", 4: "RC5", 5: "IDEA", 6: "CAST", 7: "BLOWFISH", 9: "DES-IV32",
		11: "NULL", 12: "AES-CBC", 13: "AES-CTR", 14: "AES-CCM-8", 15: "AES-CCM-12", 16: "AES-CCM-16",
		18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16", 21: "NULL-AUTH-AES-GMAC", 23: "CAMELLIA-CBC",
		24: "CAMELLIA-CTR", 28: "CHACHA20-POLY1305",
	},
	2: {
		1: "HMAC-MD5", 2: "HMAC-SHA1", 3: "HMAC-TIGER", 4: "AES128-XCBC", 5: "HMAC-SHA2-256",
		6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512", 8: "AES128-CMAC",
	},
	3: {
		0: "NONE", 1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 3: "DES-MAC", 4: "KPDK-MD5", 5: "AES-XCBC-96",
		6: "HMAC-MD5-128", 7: "HMAC-SHA1-160", 8: "AES-CMAC-96", 9: "AES-128-GMAC", 10: "AES-192-GMAC",
		11: "AES-256-GMAC", 12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256",
	},
	4: {
		0: "NONE", 1: "MODP-768 (group 1)", 2: "MODP-1024 (group 2)", 5: "MODP-1536 (group 5)",
		14: "MODP-2048 (group 14)", 15: "MODP-3072 (group 15)", 16: "MODP-4096 (group 16)",
		17: "MODP-6144 (group 17)", 18: "MODP-8192 (group 18)", 19: "ECP-256 (group 19)",
		20: "ECP-384 (group 20)", 21: "ECP-521 (group 21)", 22: "MODP-1024-160 (group 22)",
		23: "MODP-2048-224 (group 23)", 24: "MODP-2048-256 (group 24)", 25: "ECP-192 (group 25)",
		26: "ECP-224 (group 26)", 31: "Curve25519 (group 31)", 32: "Curve448 (group 32)",
	},
	5: {0: "no ESN", 1: "ESN"},
}

// IKEv2Weak lists transform IDs deprecated by RFC 8247 for informational reporting.
var IKEv2Weak = map[int]map[int]bool{
	1: {1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 9: true, 11: true},
	2: {1: true, 3: true},
	3: {1: true, 3: true, 4: true, 6: true},
	4: {1: true, 2: true, 5: true, 22: true, 23: true, 24: true},
}

// IKEv2AEAD identifies combined AEAD encryption transform IDs where integrity is implicit.
var IKEv2AEAD = map[int]bool{14: true, 15: true, 16: true, 18: true, 19: true, 20: true, 28: true}

// IKEProtocols maps IKE SA proposal protocol numbers to short names.
var IKEProtocols = map[int]string{1: "IKE", 2: "AH", 3: "ESP"}

// ProposalProtocol marshals known IKE protocol IDs as string names and unknown IDs as ints.
type ProposalProtocol struct {
	Code int
}

// MarshalJSON encodes ProposalProtocol matching Python IKE_PROTOCOLS.get(proto, proto).
func (p ProposalProtocol) MarshalJSON() ([]byte, error) {
	if name, ok := IKEProtocols[p.Code]; ok {
		return json.Marshal(name)
	}
	return json.Marshal(p.Code)
}

// IKEv2ProposalSummary holds human-readable transform names grouped by transform type.
type IKEv2ProposalSummary struct {
	Number     int              `json:"number"`
	Protocol   ProposalProtocol `json:"protocol"`
	Encryption []string         `json:"encryption"`
	PRF        []string         `json:"prf"`
	Integrity  []string         `json:"integrity"`
	DHGroup    []string         `json:"dh_group"`
	ESN        []string         `json:"esn"`
	Weak       []string         `json:"weak"`
}

// IKEv2TransformName formats an IKEv2 transform code and optional key length in bits.
func IKEv2TransformName(ttype, tid int, keyLength *int) string {
	name, ok := IKEv2TransformIDs[ttype][tid]
	if !ok {
		name = fmt.Sprintf("id %d", tid)
	}
	if keyLength != nil && *keyLength != 0 && ttype == 1 {
		return fmt.Sprintf("%s-%d", name, *keyLength)
	}
	return name
}

// SummarizeIKEv2Proposal converts raw numeric IKEProposal transforms into grouped names.
func SummarizeIKEv2Proposal(p IKEProposal) IKEv2ProposalSummary {
	byType := map[int][]string{
		1: {}, 2: {}, 3: {}, 4: {}, 5: {},
	}
	weak := []string{}
	hasAEAD := false
	for _, t := range p.Transforms {
		if t.Type == 1 && IKEv2AEAD[t.ID] {
			hasAEAD = true
		}
	}
	for _, ttype := range []int{1, 2, 3, 4, 5} {
		for _, t := range p.Transforms {
			if t.Type != ttype {
				continue
			}
			name := IKEv2TransformName(t.Type, t.ID, t.KeyLength)
			byType[ttype] = append(byType[ttype], name)
			if IKEv2Weak[ttype][t.ID] {
				weak = append(weak, name)
			}
		}
	}
	if len(byType[3]) == 0 && hasAEAD {
		byType[3] = []string{"(AEAD: integrity is part of the cipher)"}
	}
	return IKEv2ProposalSummary{
		Number:     p.Num,
		Protocol:   ProposalProtocol{Code: p.Protocol},
		Encryption: byType[1],
		PRF:        byType[2],
		Integrity:  byType[3],
		DHGroup:    byType[4],
		ESN:        byType[5],
		Weak:       weak,
	}
}

// IKENotifyName returns the canonical name for an IKEv1 or IKEv2 Notify type code.
func IKENotifyName(version, code int) string {
	table := IKEv1Notify
	if version == 2 {
		table = IKEv2Notify
	}
	if name, ok := table[code]; ok {
		return name
	}
	return fmt.Sprintf("NOTIFY_%d", code)
}

// IKENotifyIsError reports whether code represents a protocol error notification rather than informational status.
func IKENotifyIsError(version, code int) bool {
	if version == 2 {
		return code < 16384
	}
	return code < 8192
}
