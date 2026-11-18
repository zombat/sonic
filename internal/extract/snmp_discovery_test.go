package extract

import "testing"

// TestSNMPDiscovery_OnlyTheEngineExchangeIsDiscovery proves engine discovery is
// the v3 request with no variables and the Report with USM statistics, and that
// a data message is never discovery, even with no security on it.
func TestSNMPDiscovery_OnlyTheEngineExchangeIsDiscovery(t *testing.T) {
	usmReport := []string{"1.3.6.1.6.3.15.1.1.4.0"}
	sysDescr := []string{"1.3.6.1.2.1.1.1.0"}
	cases := []struct {
		name    string
		version int
		flags   string
		oids    []string
		want    bool
	}{
		{"request with no variables", 3, "04", nil, true},
		{"report with usm statistics", 3, "00", usmReport, true},
		{"unauthenticated get of sysDescr", 3, "00", sysDescr, false},
		{"authenticated message", 3, "03", nil, false},
		{"private message", 3, "07", nil, false},
		{"v2c is not v3 discovery", 1, "", nil, false},
		{"unreadable flags", 3, "zz", nil, false},
	}
	for _, c := range cases {
		if got := snmpDiscovery(c.version, c.flags, c.oids); got != c.want {
			t.Errorf("%s: discovery = %v, want %v", c.name, got, c.want)
		}
	}
}
