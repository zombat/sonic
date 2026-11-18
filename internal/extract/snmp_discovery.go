package extract

import (
	"strconv"
	"strings"
)

// usmStatsPrefix is the OID subtree of the SNMP USM statistics counters, the
// only variable bindings a discovery Report carries.
const usmStatsPrefix = "1.3.6.1.6.3.15."

// snmpDiscovery reports whether an SNMP message is part of SNMPv3 engine
// discovery: the request with no variable bindings, and the Report that answers
// it with USM statistics. It needs version 3, no authentication and no privacy.
// Such a message carries no security and no data, so the audit allows it. A data
// message with an object name, such as sysDescr, is not discovery, even without
// security.
func snmpDiscovery(version int, flags string, oids []string) bool {
	if version != 3 {
		return false
	}
	bits, err := strconv.ParseUint(flags, 16, 8)
	if err != nil || bits&0x03 != 0 {
		return false
	}
	for _, oid := range oids {
		if oid != "" && !strings.HasPrefix(oid, usmStatsPrefix) {
			return false
		}
	}
	return true
}
