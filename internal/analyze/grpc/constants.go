// Package grpc holds status tables, protocol error hints, and analytical limits for gRPC reporting.
package grpc

const (
	// ReportSchema identifies the JSON schema for sonic.grpc_report/1 outputs.
	ReportSchema = "sonic.grpc_report/1"

	defaultWindow      = 65535
	defaultMaxFrame    = 16384
	grpcDefaultMaxRecv = 4 * 1024 * 1024
	stallWarnS         = 0.2
	maxMessagesDecoded = 50
	maxDecodeBytes     = 65536
)

// GrpcStatus maps numeric gRPC status codes to canonical status names.
var GrpcStatus = map[int]string{
	0: "OK", 1: "CANCELLED", 2: "UNKNOWN", 3: "INVALID_ARGUMENT", 4: "DEADLINE_EXCEEDED",
	5: "NOT_FOUND", 6: "ALREADY_EXISTS", 7: "PERMISSION_DENIED", 8: "RESOURCE_EXHAUSTED",
	9: "FAILED_PRECONDITION", 10: "ABORTED", 11: "OUT_OF_RANGE", 12: "UNIMPLEMENTED",
	13: "INTERNAL", 14: "UNAVAILABLE", 15: "DATA_LOSS", 16: "UNAUTHENTICATED",
}

// GrpcStatusHints maps non-zero gRPC status codes to plain-English diagnoses.
var GrpcStatusHints = map[int]string{
	1:  "the client cancelled the RPC (its own deadline, or the caller gave up)",
	2:  "the server failed with an error it did not classify; read grpc-message",
	3:  "the server refused the request as malformed for this target: check the path, the encoding and the values",
	4:  "the RPC ran past its deadline (grpc-timeout): the target was slow or the deadline is too short",
	5:  "the target has no such path or object",
	6:  "the object already exists",
	7:  "the credentials were accepted but this user may not call this RPC or touch this path: check the role or AAA authorization on the target",
	8:  "a limit was hit: a message over the receiver's maximum size (4 MiB by default), too many streams, or rate limiting",
	9:  "the target is not in a state that allows this request (a precondition failed)",
	10: "the operation was aborted, typically a conflict with a concurrent change; retry",
	11: "a value was out of range",
	12: "the server does not implement this RPC, or an option it asked for (for gNMI often an encoding)",
	13: "the server hit an internal error; read grpc-message and the target's logs",
	14: "the server is unavailable or shutting down (transient): retry with backoff",
	15: "unrecoverable data loss on the server",
	16: "the server rejected the credentials: check the username and password metadata (gNMI sends them as 'username' and 'password'), a token, or the client certificate",
}

// H2Errors maps RFC 9113 HTTP/2 error codes to symbolic names.
var H2Errors = map[int]string{
	0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR",
	4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM",
	8: "CANCEL", 9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM",
	12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED",
}

// H2ErrorHints maps HTTP/2 error codes to concise explanations.
var H2ErrorHints = map[int]string{
	0:  "closed without an error",
	1:  "a protocol violation: one side sent something HTTP/2 does not allow",
	2:  "the sender hit an internal error",
	3:  "a peer sent more data than the flow-control window allowed",
	4:  "SETTINGS were not acknowledged in time",
	5:  "a frame arrived on a stream that was already closed",
	6:  "a frame was larger than the receiver's SETTINGS_MAX_FRAME_SIZE",
	7:  "the server refused the stream before processing it (too many concurrent streams, or shutting down): safe to retry; gRPC reports it as UNAVAILABLE",
	8:  "the stream was cancelled: from the client usually a deadline or a cancelled call (gRPC CANCELLED or DEADLINE_EXCEEDED), from the server an aborted handler",
	9:  "the HPACK header compression state broke",
	11: "the peer is generating excessive load (for gRPC usually too many keepalive pings)",
	12: "the TLS parameters are below what HTTP/2 requires",
	13: "the server wants HTTP/1.1, which gRPC cannot use",
}

// HTTPToGrpc maps HTTP status responses (from proxies/gateways without grpc-status) to gRPC codes.
var HTTPToGrpc = map[int]int{
	400: 13, 401: 16, 403: 7, 404: 12, 429: 14, 502: 14, 503: 14, 504: 14,
}

type familyPrefix struct {
	prefix string
	family string
}

// ServiceFamilies classifies RPC service prefixes into telemetry/management families.
var ServiceFamilies = []familyPrefix{
	{"gnmi.", "gNMI"},
	{"gnoi.", "gNOI"},
	{"gribi.", "gRIBI"},
	{"p4.v1.", "P4Runtime"},
	{"gnsi.", "gNSI"},
	{"grpc.health.", "gRPC health"},
	{"grpc.reflection.", "gRPC reflection"},
}

// StateChanging lists gRPC methods treated as mutating target state in the timeline.
var StateChanging = map[string]bool{
	"gnmi.gNMI/Set":                                             true,
	"gnoi.system.System/Reboot":                                 true,
	"gnoi.system.System/SetPackage":                             true,
	"gnoi.system.System/SwitchControlProcessor":                 true,
	"gnoi.system.System/KillProcess":                            true,
	"gnoi.factory_reset.FactoryReset/Start":                     true,
	"gnoi.os.OS/Install":                                        true,
	"gnoi.os.OS/Activate":                                       true,
	"gnoi.file.File/Put":                                        true,
	"gnoi.file.File/Remove":                                     true,
	"gnoi.certificate.CertificateManagement/Install":            true,
	"gnoi.certificate.CertificateManagement/Rotate":             true,
	"gnoi.certificate.CertificateManagement/RevokeCertificates": true,
	"gnoi.containerz.Containerz/Deploy":                         true,
	"gnoi.containerz.Containerz/RemoveContainer":                true,
	"gribi.gRIBI/Modify":                                        true,
}

// ReservedHeaders lists transport headers gRPC uses internally rather than user metadata.
var ReservedHeaders = map[string]bool{
	"content-type": true, "te": true, "user-agent": true, "grpc-timeout": true,
	"grpc-encoding": true, "grpc-accept-encoding": true, "accept-encoding": true,
	"content-length": true, "grpc-message-type": true,
}

// Limits documents capture-vantage boundaries included in every gRPC report.
var Limits = []string{
	"Wireshark needs the start of each HTTP/2 connection: HPACK headers are compressed against a table both sides build from the first request on, so a capture that begins mid-connection may show headers as undecodable and RPCs without a method.",
	"Without a key log (or TLS secrets embedded in a pcapng), TLS-wrapped gRPC shows only the handshake: no method, status or metadata. In TLS 1.3 the certificate is encrypted too.",
	"A session's secret is matched by its ClientHello random: a session whose ClientHello is not in the capture cannot be decrypted, whatever the key log holds.",
	"Plaintext HTTP/2 is found by its preface on any port and assumed on the well-known gRPC ports; HTTP/2 that upgraded from HTTP/1.1 (Upgrade: h2c) on another port is not decoded.",
	"Flow control is followed only when the connection's start was captured (the initial windows are in it).",
	"A gRPC message over 4 MiB is flagged against the common default receive limit; the receiver's real limit is configuration and is not on the wire.",
	"Message contents are decoded only for gNMI and gNOI system.Time (paths, encodings, modes, counts); values are never decoded. Other services show sizes and counts, or Wireshark's protobuf view with .proto files.",
}
