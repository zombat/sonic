// Package guide renders reference/interpreting-results.md covering report
// fields and packet capture vantage pitfalls.
package guide

import (
	"fmt"
	"strings"

	"github.com/zombat/sonic/internal/analyze/netorch"
)

func renderInterpreting() string {
	return strings.Join([]string{
		"# Interpreting results and common pitfalls",
		"",
		"## Reading a network report",
		"",
		fmt.Sprintf("- `schema` is `%s`. Check `status` first; an error carries `error` (and `valid_detectors` for an unknown detector name).", netorch.ReportSchema),
		"- `overall_status` is the worst detector status, conversations and SIP excluded. `not_present` means the protocol was not in the capture, which is not a pass.",
		"- `verdicts` holds one sentence per detector; quote it rather than paraphrasing.",
		"- `issues` are sorted errors first; `frames` are Wireshark frame numbers the user can open.",
		"- `timeline` events carry `t`, seconds from the first frame, and `time` in UTC.",
		"- Lists are cut at `max_items` (default 25); `issues_omitted` and `timeline_omitted` count the rest. Raise `max_items` or narrow with `display_filter` instead of assuming the list is whole.",
		"- `capture.backend` is `tshark`; `capture.missing_tshark_fields` and `capture.warnings` say what the installed tshark could not decode.",
		"",
		"## Pitfalls",
		"",
		"- Relative paths resolve against the server's working directory. Always pass absolute paths.",
		"- A verdict covers only what crossed the capture point. Encryption is proven on the underlay (WAN) link; a capture on the tunnel interface shows decrypted traffic.",
		"- With IPsec tunnel protection, GRE, NHRP and routing protocols travel inside ESP and are invisible on the WAN. `overlay_verdict` says so; capture the tunnel interface to see the overlay.",
		"- IKEv2 IKE_AUTH is encrypted: `auth_likely_failed` is a labelled heuristic (a small response and no ESP), not a decoded AUTHENTICATION_FAILED.",
		"- ESP with NULL encryption cannot be told apart from encrypted ESP without the keys.",
		"- A PSK mismatch is never visible as a hash: it shows as `auth_failed` (a small encrypted IKE_AUTH response, no ESP) or `auth_no_reply` (IKE_AUTH retransmitted, no reply) in `ike_diagnoses`.",
		"- DPD is recognised by size (an empty encrypted INFORMATIONAL); a stale ESP SPI is inferred from timing.",
		"- `audit_cleartext_pcap`'s default (`encrypted`) passes SSH and TLS whose handshake shows real encryption; pass `allow: [\"crypto\"]` to require IPsec. A session whose handshake is not in the capture passes only as encrypted, unverified (`clean` false): start the capture before the session.",
		"- `audit_cleartext_pcap` fails on a Cisco transport link's loopback keepalives and CDP unless `l2-control` is allowed; an empty capture fails.",
		"- On a protected DMVPN, NHRP Phase 3 steps are inside ESP: pass `hubs` to check the encrypted spoke-to-spoke shortcuts instead.",
		"- `analyze_convergence_pcap` deltas use the capture clock; an event time from another host is off by that host's clock skew. Without `event_time`, it starts at the first failure sign.",
		"- OSPFv3 and IS-IS are not decoded; EIGRP speakers are grouped per link by unicast exchange or a shared /24.",
		"- Without `peers`, the encryption verdict judges only pairs that spoke IKE/ESP plus GRE endpoints. Pass the WAN addresses to judge all traffic between them.",
		"- `display_filter` needs tshark; invalid filters return an error.",
		fmt.Sprintf("- Every LLM tool without `provider` uses the server's `%s`, else `%s`. Pass `provider` when the user named one, or check `list_llm_providers` first; a cloud provider receives the SIP data.",
			ProviderVariable, DefaultProvider),
		"- LLM output varies from call to call; the deterministic tools give the same answer every time.",
		"",
	}, "\n")
}
