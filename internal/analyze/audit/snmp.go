// The protection and label of an SNMP frame in the cleartext audit, judged by
// the SNMP version and the SNMPv3 security flags.
package audit

import (
	"fmt"
	"strconv"

	"github.com/zombat/sonic/internal/model"
)

// SNMPDecodeAs turns SNMP ports into tshark -d arguments, so a manager or agent
// on a non-standard UDP port is decoded and its frames classed by version.
func SNMPDecodeAs(ports []int) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, fmt.Sprintf("udp.port==%d,snmp", p))
	}
	return out
}

// snmpPrivacyBit is the SNMPv3 msgFlags bit that says the scoped PDU is encrypted.
const snmpPrivacyBit = 0x02

// snmpPrivate reports whether an SNMPv3 message's scoped PDU is encrypted.
// SNMPv1 and v2c never are, and an unreadable flags byte counts as not encrypted.
func snmpPrivate(s *model.SNMPHeader) bool {
	if s.Version != 3 {
		return false
	}
	flags, err := strconv.ParseUint(s.Flags, 16, 8)
	return err == nil && flags&snmpPrivacyBit != 0
}

// snmpCategory is the protection of an SNMP frame. Only an SNMPv3 message
// with privacy is encrypted. Everything else is cleartext, including v3
// discovery and authenticated-only messages, whose PDUs are readable.
func snmpCategory(s *model.SNMPHeader) string {
	if snmpPrivate(s) {
		return "encrypted"
	}
	return "cleartext"
}

// snmpLabel names an SNMP frame for the report, saying whether v3 has privacy.
func snmpLabel(s *model.SNMPHeader) string {
	// tshark's snmp.version: 0 is v1, 1 is v2c, 3 is v3.
	switch {
	case s.Version == 0:
		return "snmp v1"
	case s.Version == 1:
		return "snmp v2c"
	case snmpPrivate(s):
		return "snmp v3 (privacy)"
	case s.Version == 3:
		return "snmp v3 (no privacy)"
	default:
		return "snmp version " + strconv.Itoa(s.Version)
	}
}
