// Package tlsinspect certificate parser and session SAN hint helpers.
package tlsinspect

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// ParseCertificate extracts subject, issuer, validity, and SANs from a TLS <= 1.2 Certificate message body.
func ParseCertificate(body []byte, captureTime float64) CertificateInfo {
	chainLen := 0
	out := CertificateInfo{
		Visible:     true,
		ChainLength: &chainLen,
	}

	var total int
	for i := 0; i < 3 && i < len(body); i++ {
		total = (total << 8) | int(body[i])
	}

	pos := 3
	limit := min(len(body), 3+total)
	var certs [][]byte
	for pos+3 <= limit {
		length := int(body[pos])<<16 | int(body[pos+1])<<8 | int(body[pos+2])
		end := min(len(body), pos+3+length)
		certs = append(certs, body[pos+3:end])
		pos += 3 + length
	}

	chainLen = len(certs)
	if chainLen == 0 {
		return out
	}

	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		parsed := false
		out.Parsed = &parsed
		out.Note = fmt.Sprintf("leaf certificate not parsed: %T", err)
		return out
	}

	subj := commonNameOrString(cert.Subject)
	iss := commonNameOrString(cert.Issuer)
	selfSigned := bytes.Equal(cert.RawSubject, cert.RawIssuer)
	nbStr := cert.NotBefore.UTC().Format(time.RFC3339Nano)
	naStr := cert.NotAfter.UTC().Format(time.RFC3339Nano)

	now := time.UnixMicro(int64(math.Round(captureTime * 1e6))).UTC()
	valid := !now.Before(cert.NotBefore.UTC()) && !now.After(cert.NotAfter.UTC())

	dns := make([]string, 0, min(len(cert.DNSNames), 20))
	for i := 0; i < len(cert.DNSNames) && i < 20; i++ {
		dns = append(dns, cert.DNSNames[i])
	}

	ips := make([]string, 0, min(len(cert.IPAddresses), 20))
	for i := 0; i < len(cert.IPAddresses) && i < 20; i++ {
		addr, ok := netip.AddrFromSlice(cert.IPAddresses[i])
		if !ok {
			continue
		}
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		ips = append(ips, addr.String())
	}

	parsed := true
	out.Parsed = &parsed
	out.Subject = &subj
	out.Issuer = &iss
	out.SelfSigned = &selfSigned
	out.NotBefore = &nbStr
	out.NotAfter = &naStr
	out.ValidAtCaptureTime = &valid
	out.DNSNames = &dns
	out.IPAddresses = &ips
	return out
}

// SessionHints produces SAN mismatch or obscured-cert hints when a client appears to dial an IP without SNI.
func SessionHints(serverIP string, sni *string, version string, cert CertificateInfo) []HintRecord {
	hints := []HintRecord{}
	byIP := sni == nil || *sni == "" || isIPLiteral(*sni)
	if cert.Parsed != nil && *cert.Parsed {
		var ips []string
		if cert.IPAddresses != nil {
			ips = *cert.IPAddresses
		}
		if byIP && !slices.Contains(ips, serverIP) {
			ipList := strings.Join(ips, ", ")
			if ipList == "" {
				ipList = "none"
			}
			var dns []string
			if cert.DNSNames != nil {
				dns = *cert.DNSNames
			}
			dnsList := strings.Join(dns, ", ")
			if dnsList == "" {
				dnsList = "none"
			}
			hints = append(hints, HintRecord{
				Code:     "TLS_CERT_NO_IP_SAN",
				Severity: "warning",
				Text: fmt.Sprintf(
					"the client sent no SNI name, so it most likely dialled the address %s, and the certificate has no IP SAN for it (IP SANs: %s; DNS names: %s): a client that verifies the server refuses it (Go reports that the certificate does not contain any IP SANs); dial a name the certificate lists, or reissue it with the IP as a SAN",
					serverIP, ipList, dnsList,
				),
			})
		}
	} else if version == "TLS1.3" && byIP {
		hints = append(hints, HintRecord{
			Code:     "TLS_NO_SNI",
			Severity: "info",
			Text: fmt.Sprintf(
				"the client sent no SNI name, so it most likely dialled the address %s; TLS 1.3 encrypts the certificate, so whether it carries that address as an IP SAN cannot be seen here",
				serverIP,
			),
		})
	}
	return hints
}

// commonNameOrString returns the certificate CN value if present, or the RFC2253 string form otherwise.
func commonNameOrString(name pkix.Name) string {
	if name.CommonName != "" {
		return name.CommonName
	}
	return name.String()
}

// isIPLiteral reports whether text (after trimming optional IPv6 brackets) parses as an IP literal.
func isIPLiteral(text string) bool {
	trimmed := strings.Trim(text, "[]")
	_, err := netip.ParseAddr(trimmed)
	return err == nil
}
