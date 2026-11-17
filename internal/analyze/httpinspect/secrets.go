// Package httpinspect inspects keylog files and pcapng blocks for TLS session coverage.
package httpinspect

import (
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

type randomSecretInfo struct {
	labels  map[string]bool
	sources map[string]bool
}

type secretsInfo struct {
	KeyLogFile       bool
	PCAPNGBlocks     int
	ByRandom         map[string]randomSecretInfo
	Source           *string
	SessionsInKeyLog int
	SessionsInPCAPNG int
}

// endpointStr formats ip:port, enclosing IPv6 addresses in brackets.
func endpointStr(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// connectionFlow formats "client -> server" using inferred client/server or raw endpoints A/B.
func connectionFlow(c *extract.TCPConnection) string {
	cli, srv := c.A, c.B
	if c.Client != nil {
		cli = *c.Client
	}
	if c.Server != nil {
		srv = *c.Server
	}
	return endpointStr(cli.IP, cli.Port) + " -> " + endpointStr(srv.IP, srv.Port)
}

// secretsView inspects keylog_file and pcapng DSBs for session coverage without keeping secret values.
func secretsView(filePath, keylogFile string) secretsInfo {
	var keyLog map[string]map[string]bool
	if keylogFile != "" {
		if kl, err := extract.KeyLogLabels(keylogFile); err == nil {
			keyLog = kl
		}
	}
	blocks := 0
	var pcapLabels map[string]map[string]bool
	if res, err := extract.PCAPNGSecrets(filePath); err == nil && res != nil {
		blocks = res.Blocks
		pcapLabels = res.Labels
	}

	byRandom := make(map[string]randomSecretInfo)
	merge := func(source string, table map[string]map[string]bool) {
		for randHex, labels := range table {
			entry, ok := byRandom[randHex]
			if !ok {
				entry = randomSecretInfo{
					labels:  make(map[string]bool),
					sources: make(map[string]bool),
				}
			}
			for lbl := range labels {
				entry.labels[lbl] = true
			}
			entry.sources[source] = true
			byRandom[randHex] = entry
		}
	}
	merge("key log", keyLog)
	merge("pcapng", pcapLabels)

	var names []string
	if keylogFile != "" {
		names = append(names, "the key log")
	}
	if blocks > 0 {
		names = append(names, "the secrets in the pcapng")
	}
	var srcPtr *string
	if len(names) > 0 {
		s := strings.Join(names, " and ")
		srcPtr = &s
	}

	return secretsInfo{
		KeyLogFile:       keylogFile != "",
		PCAPNGBlocks:     blocks,
		ByRandom:         byRandom,
		Source:           srcPtr,
		SessionsInKeyLog: len(keyLog),
		SessionsInPCAPNG: len(pcapLabels),
	}
}
