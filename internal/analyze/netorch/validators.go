// Package netorch validates detector selections and options for network capture orchestration.
package netorch

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/analyze/audit"
	"github.com/zombat/sonic/internal/analyze/convergence"
)

func errNetworkReport(msg string, valid ...string) NetworkReport {
	return NetworkReport{
		NetworkBody: NetworkBody{
			Status:         "error",
			Error:          msg,
			ValidDetectors: valid,
		},
	}
}

func validateOptions(filePath string, opts Options) ([]string, int, *NetworkReport) {
	if filePath == "" {
		r := errNetworkReport("File not found: " + filePath)
		return nil, 0, &r
	}
	info, err := os.Stat(filePath)
	if err != nil {
		r := errNetworkReport("File not found: " + filePath)
		return nil, 0, &r
	}
	if info.IsDir() {
		r := errNetworkReport("File not readable: " + filePath)
		return nil, 0, &r
	}
	if f, err := os.Open(filePath); err != nil {
		r := errNetworkReport("File not readable: " + filePath)
		return nil, 0, &r
	} else {
		_ = f.Close()
	}

	names := slices.Clone(DetectorNames)
	if len(opts.Detectors) > 0 {
		names = slices.Clone(opts.Detectors)
	}
	var unknown []string
	for _, n := range names {
		if !slices.Contains(AllDetectors, n) {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		r := errNetworkReport("Unknown detector(s): "+strings.Join(unknown, ", "), AllDetectors...)
		return nil, 0, &r
	}

	for _, peer := range opts.Peers {
		if _, err := netip.ParseAddr(peer); err != nil {
			r := errNetworkReport(fmt.Sprintf("Not an IP address in peers: '%s'", peer))
			return nil, 0, &r
		}
	}
	if opts.MaxPackets != nil && *opts.MaxPackets <= 0 {
		r := errNetworkReport("max_packets must be a positive number")
		return nil, 0, &r
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = 25
	}

	if msg := validateControlPlaneOptions(opts.DetectorOpts); msg != "" {
		r := errNetworkReport(msg)
		return nil, 0, &r
	}
	return names, maxItems, nil
}

func validateControlPlaneOptions(d DetectorOptions) string {
	for _, hub := range d.DMVPNHubs {
		if _, err := netip.ParseAddr(hub); err != nil {
			return fmt.Sprintf("Not an IP address in hubs: '%s'", hub)
		}
	}
	if d.RoutingMSS != nil && *d.RoutingMSS <= 0 {
		return "expected_mss must be a positive number"
	}
	if d.CleartextAudit != nil && d.CleartextAudit.HasAllow {
		if _, _, err := audit.ParseAllowlist(d.CleartextAudit.Allow); err != nil {
			return err.Error()
		}
	}
	if d.Convergence != nil {
		c := d.Convergence
		if c.FailedPeer != "" {
			if _, err := netip.ParseAddr(c.FailedPeer); err != nil {
				return fmt.Sprintf("failed_peer is not an IP address: '%s'", c.FailedPeer)
			}
		}
		if c.HoldTime != nil && *c.HoldTime <= 0 {
			return "hold_time must be a positive number"
		}
		if c.SilenceS != nil && *c.SilenceS <= 0 {
			return "silence_s must be a positive number"
		}
		if c.EventTime != "" {
			if _, err := convergence.ParseEventTime(c.EventTime, nil); err != nil {
				return err.Error()
			}
		}
	}
	return ""
}
