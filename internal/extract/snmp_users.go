// Package extract parses and validates SNMPv3 USM users files (block and CSV formats)
// into Wireshark snmp_users UAT rows without echoing passphrases.
package extract

import (
	"fmt"
	"strings"
)

// SnmpUsersError indicates an invalid USM users file and never includes passphrases.
type SnmpUsersError struct {
	Message string
}

// Error returns the descriptive USM users parsing error message.
func (e *SnmpUsersError) Error() string { return e.Message }

// SnmpUser represents one normalized USM user entry ready for tshark's snmp_users UAT.
type SnmpUser struct {
	User     string
	EngineID string
	Auth     string
	AuthPass string
	Priv     string
	PrivPass string
}

// SnmpAuthLabels maps operator auth spellings to exact Wireshark snmp_users UAT enum labels.
var SnmpAuthLabels = map[string]string{
	"md5": "MD5", "hmac-md5": "MD5", "hmac-md5-96": "MD5",
	"sha": "SHA1", "sha1": "SHA1", "sha-1": "SHA1", "hmac-sha": "SHA1", "hmac-sha-96": "SHA1",
	"sha224": "SHA2-224", "sha-224": "SHA2-224", "sha2-224": "SHA2-224",
	"sha256": "SHA2-256", "sha-256": "SHA2-256", "sha2-256": "SHA2-256",
	"sha384": "SHA2-384", "sha-384": "SHA2-384", "sha2-384": "SHA2-384",
	"sha512": "SHA2-512", "sha-512": "SHA2-512", "sha2-512": "SHA2-512",
}

// SnmpPrivLabels maps operator privacy spellings to exact Wireshark snmp_users UAT enum labels.
var SnmpPrivLabels = map[string]string{
	"des": "DES", "cbc-des": "DES",
	"aes": "AES", "aes128": "AES", "aes-128": "AES", "cfb128-aes-128": "AES",
	"aes192": "AES192", "aes-192": "AES192",
	"aes256": "AES256", "aes-256": "AES256",
}

// SnmpAuthHashBytes gives digest byte lengths per tshark USM auth label.
var SnmpAuthHashBytes = map[string]int{
	"MD5": 16, "SHA1": 20, "SHA2-224": 28, "SHA2-256": 32, "SHA2-384": 48, "SHA2-512": 64,
}

// SnmpPrivKeyBytes gives key byte lengths per tshark USM privacy label.
var SnmpPrivKeyBytes = map[string]int{
	"DES": 16, "AES": 16, "AES192": 24, "AES256": 32,
}

var snmpUserAliases = map[string]string{
	"user": "user", "username": "user", "name": "user", "securityname": "user",
	"engine_id": "engine_id", "engineid": "engine_id", "engine": "engine_id",
	"auth": "auth", "auth_proto": "auth", "auth_protocol": "auth", "authentication": "auth",
	"auth_pass": "auth_pass", "auth_passphrase": "auth_pass", "authpass": "auth_pass", "auth_password": "auth_pass",
	"priv": "priv", "priv_proto": "priv", "priv_protocol": "priv", "privacy": "priv",
	"priv_pass": "priv_pass", "priv_passphrase": "priv_pass", "privpass": "priv_pass", "priv_password": "priv_pass",
}

// ParseSnmpUsersFile parses block or CSV SNMPv3 USM user definitions and normalizes algorithms.
func ParseSnmpUsersFile(text string) ([]SnmpUser, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	looksCSV := false
	for _, ln := range lines {
		st := strings.TrimSpace(ln)
		if st != "" && !strings.HasPrefix(st, "#") && strings.Contains(st, ",") && !strings.Contains(st, ":") {
			looksCSV = true
			break
		}
	}
	var users []SnmpUser
	if looksCSV {
		users = parseSnmpCSV(lines)
	} else {
		users = parseSnmpBlocks(lines)
	}
	var valid []SnmpUser
	for _, u := range users {
		if u.User != "" {
			if err := normalizeSnmpUser(&u); err != nil {
				return nil, err
			}
			valid = append(valid, u)
		}
	}
	if len(valid) == 0 {
		return nil, &SnmpUsersError{Message: "no SNMPv3 user with a name found in the users file"}
	}
	return valid, nil
}

// parseSnmpCSV decodes comma-separated USM user rows.
func parseSnmpCSV(lines []string) []SnmpUser {
	var users []SnmpUser
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) > 0 {
			low := strings.ToLower(parts[0])
			if low == "user" || low == "username" || low == "name" {
				continue
			}
		}
		var u SnmpUser
		if len(parts) > 0 {
			u.User = parts[0]
		}
		if len(parts) > 1 {
			u.Auth = parts[1]
		}
		if len(parts) > 2 {
			u.AuthPass = parts[2]
		}
		if len(parts) > 3 {
			u.Priv = parts[3]
		}
		if len(parts) > 4 {
			u.PrivPass = parts[4]
		}
		if len(parts) > 5 {
			u.EngineID = parts[5]
		}
		if u.User != "" {
			users = append(users, u)
		}
	}
	return users
}

// setSnmpUserField assigns a canonical USM field on u.
func setSnmpUserField(u *SnmpUser, canon, val string) {
	switch canon {
	case "user":
		u.User = val
	case "engine_id":
		u.EngineID = val
	case "auth":
		u.Auth = val
	case "auth_pass":
		u.AuthPass = val
	case "priv":
		u.Priv = val
	case "priv_pass":
		u.PrivPass = val
	}
}

// parseSnmpBlocks decodes YAML-like/INI key-value blocks of USM users.
func parseSnmpBlocks(lines []string) []SnmpUser {
	var users []SnmpUser
	var cur SnmpUser
	hasCur := false
	flush := func() {
		if hasCur {
			users = append(users, cur)
			cur = SnmpUser{}
			hasCur = false
		}
	}
	for _, raw := range lines {
		st := strings.TrimSpace(raw)
		if st == "" || strings.HasPrefix(st, "#") || st == "---" || st == "[user]" {
			flush()
			continue
		}
		line := st
		if strings.HasPrefix(st, "- ") {
			line = strings.TrimSpace(st[1:])
		}
		sep := "="
		cIdx := strings.IndexByte(line, ':')
		eIdx := strings.IndexByte(line, '=')
		if cIdx >= 0 && (eIdx < 0 || cIdx < eIdx) {
			sep = ":"
		}
		idx := strings.Index(line, sep)
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		val := strings.Trim(strings.Trim(strings.TrimSpace(line[idx+len(sep):]), `"`), `'`)
		canon := snmpUserAliases[strings.ToLower(name)]
		if canon != "" && val != "" {
			if canon == "user" && cur.User != "" {
				flush()
			}
			setSnmpUserField(&cur, canon, val)
			hasCur = true
		}
	}
	flush()
	return users
}

// normalizeSnmpUser validates algorithm labels, rejects unsafe UAT quote/backslash passphrases,
// and canonicalizes EngineID hex strings.
func normalizeSnmpUser(u *SnmpUser) error {
	auth := strings.TrimSpace(u.Auth)
	if auth != "" {
		if lbl, ok := SnmpAuthLabels[strings.ToLower(auth)]; ok {
			u.Auth = lbl
		} else if _, ok := SnmpAuthHashBytes[auth]; ok {
			u.Auth = auth
		} else {
			return &SnmpUsersError{Message: fmt.Sprintf("user %s: auth protocol %q is not one tshark 3.6.2 offers (MD5, SHA1, SHA2-224, SHA2-256, SHA2-384, SHA2-512)", u.User, auth)}
		}
	}
	priv := strings.TrimSpace(u.Priv)
	if priv != "" {
		if lbl, ok := SnmpPrivLabels[strings.ToLower(priv)]; ok {
			u.Priv = lbl
		} else if _, ok := SnmpPrivKeyBytes[priv]; ok {
			u.Priv = priv
		} else {
			return &SnmpUsersError{Message: fmt.Sprintf("user %s: privacy protocol %q is not one tshark 3.6.2 offers (DES, AES, AES192, AES256)", u.User, priv)}
		}
	}
	for _, pair := range []struct{ key, val string }{{"auth_pass", u.AuthPass}, {"priv_pass", u.PrivPass}} {
		if strings.ContainsAny(pair.val, `"\`) {
			return &SnmpUsersError{Message: fmt.Sprintf("user %s: a %s holding a double quote or a backslash cannot be written to tshark's users table", u.User, pair.key)}
		}
	}
	eng := strings.ToLower(strings.TrimSpace(u.EngineID))
	eng = strings.TrimPrefix(eng, "0x")
	eng = strings.ReplaceAll(eng, ":", "")
	eng = strings.ReplaceAll(eng, " ", "")
	u.EngineID = eng
	return nil
}

// SnmpNeedsKeyExtension reports whether priv key length exceeds auth digest length.
func SnmpNeedsKeyExtension(u SnmpUser) bool {
	if u.Auth == "" || (u.Priv != "AES192" && u.Priv != "AES256") {
		return false
	}
	return SnmpAuthHashBytes[u.Auth] < SnmpPrivKeyBytes[u.Priv]
}

// SnmpUserUATRow formats one Wireshark snmp_users UAT record line.
func SnmpUserUATRow(u SnmpUser) string {
	auth := u.Auth
	if auth == "" {
		auth = "MD5"
	}
	priv := u.Priv
	if priv == "" {
		priv = "DES"
	}
	fields := []string{u.EngineID, u.User, auth, u.AuthPass, priv, u.PrivPass}
	for i, f := range fields {
		fields[i] = `"` + f + `"`
	}
	return strings.Join(fields, ",")
}
