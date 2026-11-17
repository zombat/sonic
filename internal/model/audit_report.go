// Package model defines the JSON structures emitted by cleartext_audit.
package model

// AuditReport is the full JSON report produced by cleartext_audit.
type AuditReport struct {
	Status                 string            `json:"status"`
	Error                  string            `json:"error,omitempty"`
	Passed                 bool              `json:"passed"`
	Clean                  bool              `json:"clean"`
	Result                 string            `json:"result"`
	Verdict                string            `json:"verdict"`
	Allowlist              []string          `json:"allowlist"`
	FramesAudited          int               `json:"frames_audited"`
	FramesAllowed          int               `json:"frames_allowed"`
	FramesOutsideAllowlist int               `json:"frames_outside_allowlist"`
	CleartextFrames        int               `json:"cleartext_frames"`
	Protection             map[string]int    `json:"protection"`
	Encryption             EncryptionSummary `json:"encryption"`
	FirstViolationFrame    *int              `json:"first_violation_frame"`
	ByProtocol             []ByProtocol      `json:"by_protocol"`
	Violations             []AuditViolation  `json:"violations"`
	ViolationsOmitted      int               `json:"violations_omitted"`
	TCPSessions            []TCPSession      `json:"tcp_sessions"`
	TCPSessionsOmitted     int               `json:"tcp_sessions_omitted"`
	AllowedByRule          map[string]int    `json:"allowed_by_rule"`
	CannotShow             []string          `json:"cannot_show"`
	Issues                 []Issue           `json:"issues"`
	File                   string            `json:"file"`
	Capture                CaptureInfo       `json:"capture"`
	ProtocolsPresent       []string          `json:"protocols_present"`
}

// EncryptionSummary aggregates session counts across SSH and TLS encryption states.
type EncryptionSummary struct {
	Sessions   int `json:"sessions"`
	Encrypted  int `json:"encrypted"`
	Weak       int `json:"weak"`
	Unverified int `json:"unverified"`
	Cleartext  int `json:"cleartext"`
	NotStarted int `json:"not_started"`
}

// ByProtocol summarizes out-of-allowlist traffic grouped by protocol label.
type ByProtocol struct {
	Protocol   string `json:"protocol"`
	Category   string `json:"category"`
	Packets    int    `json:"packets"`
	Bytes      int    `json:"bytes"`
	Pairs      int    `json:"pairs"`
	FirstFrame int    `json:"first_frame"`
}

// AuditViolation describes one (protocol, src, dst) bucket of frames outside the allowlist.
type AuditViolation struct {
	Protocol   string         `json:"protocol"`
	Category   string         `json:"category"`
	Hint       string         `json:"hint"`
	Src        *string        `json:"src"`
	Dst        *string        `json:"dst"`
	Packets    int            `json:"packets"`
	Bytes      int            `json:"bytes"`
	FirstFrame int            `json:"first_frame"`
	LastFrame  int            `json:"last_frame"`
	FirstT     float64        `json:"first_t"`
	LastT      float64        `json:"last_t"`
	Frames     []int          `json:"frames"`
	Protection map[string]int `json:"protection"`
	Reasons    []string       `json:"reasons,omitempty"`
}

// TCPSession summarizes one observed TCP flow and its SSH/TLS verdict.
type TCPSession struct {
	Service            string             `json:"service"`
	Protocol           string             `json:"protocol"`
	Category           string             `json:"category"`
	Client             string             `json:"client"`
	Server             string             `json:"server"`
	ServerKnownBy      *string            `json:"server_known_by"`
	Packets            int                `json:"packets"`
	FirstFrame         int                `json:"first_frame"`
	Protection         map[string]int     `json:"protection"`
	Encryption         *SessionEncryption `json:"encryption,omitempty"`
	AllowedAsEncrypted *bool              `json:"allowed_as_encrypted,omitempty"`
}

// SessionEncryption captures TLS or SSH encryption diagnostics for one TCP session.
type SessionEncryption struct {
	State               string         `json:"state"`
	HandshakeCaptured   bool           `json:"handshake_captured"`
	Reason              *string        `json:"reason"`
	Version             *string        `json:"version,omitempty"`
	CipherSuite         *string        `json:"cipher_suite,omitempty"`
	ServerHelloFrame    *int           `json:"server_hello_frame,omitempty"`
	KexInitFrames       *KexInitFrames `json:"kexinit_frames,omitempty"`
	CipherClientToServe *string        `json:"cipher_client_to_server,omitempty"`
	MACClientToServer   *string        `json:"mac_client_to_server,omitempty"`
	CipherServerToClien *string        `json:"cipher_server_to_client,omitempty"`
	MACServerToClient   *string        `json:"mac_server_to_client,omitempty"`
}

// KexInitFrames records the frame numbers of SSH KEXINIT messages in each direction.
type KexInitFrames struct {
	Client *int `json:"client"`
	Server *int `json:"server"`
}
