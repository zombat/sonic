// Package dmvpn implements the DMVPN Phase 3 sequence, thrashing, and encrypted
// shortcut detector matching analyzers/dmvpn_phase3.py.
package dmvpn

import "github.com/zombat/sonic/internal/model"

const (
	thrashRatePerS          = 5
	thrashUnansweredRepeats = 5
	maxDataOutersPerInner   = 64
	maxTrackedRequests      = 100000
	maxESPTimesPerFlow      = 4096
)

// EncryptedNotVisible explains why transport captures hide Phase 3 NHRP redirects/resolutions under IPsec.
const EncryptedNotVisible = "NHRP redirect, resolution request and resolution reply travel inside ESP on a protected tunnel, so on the transport link only the IKE negotiation and ESP between the spokes are visible; capture on the tunnel interface to see steps 2 to 4"

// Steps lists the ordered Phase 3 shortcut sequence step names.
var Steps = []string{"via_hub", "redirect", "resolution_request", "resolution_reply", "direct"}

// MissingHints maps each Phase 3 step name to its operator diagnosis text.
var MissingHints = map[string]string{
	"via_hub":            "no packet of this flow was seen going through the hub (the capture probably started after it)",
	"redirect":           "the hub relayed spoke-to-spoke traffic but sent no NHRP redirect: 'ip nhrp redirect' missing on the hub tunnel, or the traffic did not enter and leave the same tunnel interface",
	"resolution_request": "the spoke got the redirect but never asked NHRP to resolve the destination: 'ip nhrp shortcut' missing on the spoke, or the redirect was rate limited",
	"resolution_reply":   "the resolution request was never answered: the remote spoke did not receive it or could not answer (not registered, no route back over the tunnel, or NHRP blocked)",
	"direct":             "the destination was resolved but no data went directly between the spokes: the spoke-to-spoke tunnel (and its IPsec SA, if protected) never carried traffic, or the flow ended",
}

// Report is the top-level JSON structure returned by Detector.
type Report struct {
	Detector               string          `json:"detector"`
	Status                 model.Status    `json:"status"`
	Verdict                string          `json:"verdict"`
	Hubs                   []string        `json:"hubs"`
	HubsSource             HubsSource      `json:"hubs_source"`
	Flows                  []FlowReport    `json:"flows"`
	FlowsOmitted           int             `json:"flows_omitted"`
	HubRelayedWithoutRedir []RelayedEntry  `json:"hub_relayed_without_redirect"`
	ResolutionThrashing    ThrashingReport `json:"resolution_thrashing"`
	ErrorIndications       []ErrorEntry    `json:"error_indications"`
	EncryptedShortcuts     EncryptedReport `json:"encrypted_shortcuts"`
	CannotShow             []string        `json:"cannot_show"`
	Issues                 []model.Issue   `json:"issues"`
	Events                 []model.Event   `json:"events"`
}

// HubsSource records how each discovered hub NBMA IP was identified.
type HubsSource struct {
	Given             []string `json:"given"`
	FromRegistrations []string `json:"from_registrations"`
	FromRedirects     []string `json:"from_redirects"`
}

// StepDetail describes a single observed milestone in a Phase 3 sequence or encrypted shortcut.
type StepDetail struct {
	T        *float64 `json:"t"`
	Frame    int      `json:"frame"`
	Detail   string   `json:"detail"`
	Negative bool     `json:"negative,omitempty"`
}

// Timings holds computed inter-step latencies in milliseconds for one Phase 3 flow.
type Timings struct {
	RedirectAfterFirstDataMs *float64 `json:"redirect_after_first_data_ms,omitempty"`
	ResolutionRTTMs          *float64 `json:"resolution_rtt_ms,omitempty"`
	ShortcutAfterFirstDataMs *float64 `json:"shortcut_after_first_data_ms,omitempty"`
}

// FlowReport summarizes one redirected DMVPN Phase 3 spoke-to-spoke flow.
type FlowReport struct {
	Spoke            string                 `json:"spoke"`
	Hub              string                 `json:"hub"`
	OriginalSrc      *string                `json:"original_src"`
	OriginalDst      *string                `json:"original_dst"`
	ForwardedByHubTo *string                `json:"forwarded_by_hub_to"`
	Result           string                 `json:"result"`
	MissingStep      *string                `json:"missing_step"`
	Diagnosis        string                 `json:"diagnosis"`
	Steps            map[string]*StepDetail `json:"steps"`
	Timings          Timings                `json:"timings"`
	ErrorIndications []string               `json:"error_indications"`
}

// RelayedEntry records spoke-to-spoke data relayed through a hub without an NHRP Traffic Indication.
type RelayedEntry struct {
	Spoke         string   `json:"spoke"`
	Hub           string   `json:"hub"`
	ToSpoke       string   `json:"to_spoke"`
	InnerSrc      string   `json:"inner_src"`
	InnerDst      string   `json:"inner_dst"`
	PacketsViaHub int      `json:"packets_via_hub"`
	FirstT        *float64 `json:"first_t"`
	Frame         int      `json:"frame"`
}

// TargetThrash tracks resolution request attempts and unanswered counts for one target IP from a spoke.
type TargetThrash struct {
	Target     *string `json:"target"`
	Requests   int     `json:"requests"`
	Answered   int     `json:"answered"`
	Unanswered int     `json:"unanswered"`
	Frames     []int   `json:"frames"`
}

// SpokeThrash reports peak/average resolution request rates and targets for one spoke NBMA.
type SpokeThrash struct {
	SpokeNBMA        string         `json:"spoke_nbma"`
	Requests         int            `json:"requests"`
	PeakPerSecond    int            `json:"peak_per_second"`
	AveragePerSecond *float64       `json:"average_per_second"`
	Targets          []TargetThrash `json:"targets"`
	Thrashing        bool           `json:"thrashing"`
}

// ThrashThresholds records the rate and repeat thresholds used for thrashing detection.
type ThrashThresholds struct {
	PeakPerSecond              int `json:"peak_per_second"`
	UnansweredRepeatsPerTarget int `json:"unanswered_repeats_per_target"`
}

// ThrashingReport summarizes NHRP resolution thrashing across all requesters.
type ThrashingReport struct {
	Thrashing  bool             `json:"thrashing"`
	Spokes     []SpokeThrash    `json:"spokes"`
	Thresholds ThrashThresholds `json:"thresholds"`
}

// ErrorEntry records one NHRP Error Indication seen during resolution tracking.
type ErrorEntry struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	Error     string   `json:"error"`
	ErrorCode *int     `json:"error_code"`
	RequestID *uint32  `json:"request_id"`
	T         *float64 `json:"t"`
	Frame     int      `json:"frame"`
}

// EncryptedShortcut summarizes direct spoke-to-spoke IKE/ESP evidence on an encrypted transport link.
type EncryptedShortcut struct {
	Spokes      []string               `json:"spokes"`
	Initiator   *string                `json:"initiator"`
	Result      string                 `json:"result"`
	MissingStep *string                `json:"missing_step"`
	Steps       map[string]*StepDetail `json:"steps"`
	SetupMs     *float64               `json:"setup_ms"`
}

// EncryptedReport wraps all detected encrypted spoke-to-spoke shortcut negotiations.
type EncryptedReport struct {
	Shortcuts  []EncryptedShortcut `json:"shortcuts"`
	Note       *string             `json:"note"`
	NotVisible string              `json:"not_visible"`
}
