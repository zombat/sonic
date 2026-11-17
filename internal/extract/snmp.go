// Package extract handles SNMP v1/v2c/v3 tshark extraction into raw field maps.
package extract

import (
	"context"
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/wsconfig"
)

// SnmpFieldSep separates repeated tshark field values inside one SNMP packet row.
const SnmpFieldSep = "\x1f"

// SnmpFields lists the exact tshark fields extracted for every SNMP frame.
var SnmpFields = []string{
	"frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
	"udp.srcport", "udp.dstport", "snmp.version", "snmp.msgVersion", "snmp.community",
	"snmp.msgUserName", "snmp.msgAuthoritativeEngineID", "snmp.v3.flags.auth", "snmp.v3.flags.crypt",
	"snmp.data", "snmp.decrypted_pdu", "_ws.malformed", "snmp.decrypted_data_bad_formatted",
	"snmp.failed_decrypted_data_pdu", "snmp.authentication_ok", "snmp.authentication_error",
	"snmp.verify_authentication_error", "snmp.name",
}

// ExtractSNMP runs tshark over SNMP packets using temporary snmp_users UAT config when given,
// returning raw rows, observed v1/v2c community strings (in memory for scrubbing), and UAT warnings.
func ExtractSNMP(
	ctx context.Context,
	filePath string,
	users []SnmpUser,
	displayFilter string,
	maxPackets *int,
) ([]map[string]string, map[string]bool, []string, error) {
	var uatRows []string
	for _, u := range users {
		if u.Auth != "" {
			uatRows = append(uatRows, SnmpUserUATRow(u))
		}
	}
	var uats map[string][]string
	if len(uatRows) > 0 {
		uats = map[string][]string{"snmp_users": uatRows}
	}

	var rows []map[string]string
	var rawStderr string
	err := wsconfig.WithConfig(nil, uats, func(configDir string) error {
		flt := "snmp"
		if displayFilter != "" {
			flt = fmt.Sprintf("(%s) && snmp", displayFilter)
		}
		var runErr error
		rawStderr, runErr = streamTsharkFields(ctx, filePath, nil, flt, SnmpFields, SnmpFieldSep, maxPackets, wsconfig.Env(configDir), func(row map[string]string) error {
			rows = append(rows, row)
			return nil
		})
		return runErr
	})
	if err != nil {
		return nil, nil, nil, err
	}

	var warnings []string
	if rawStderr != "" {
		for _, ln := range strings.Split(rawStderr, "\n") {
			if strings.Contains(ln, "snmp_users") || strings.Contains(ln, "SNMP Users") {
				s := strings.TrimSpace(ln)
				if len(s) > 300 {
					s = s[:300]
				}
				warnings = append(warnings, s)
			}
		}
	}

	communities := make(map[string]bool)
	for _, row := range rows {
		for _, val := range strings.Split(row["snmp.community"], SnmpFieldSep) {
			if val != "" {
				communities[val] = true
			}
		}
	}
	return rows, communities, warnings, nil
}
