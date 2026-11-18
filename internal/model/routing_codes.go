// Package model defines NHRP, BGP, OSPF, and EIGRP protocol code tables
// and lookup helpers mirroring analyzers/network_common.py.
package model

import "fmt"

// NHRPOps maps NHRP opcode integers to snake_case names.
var NHRPOps = map[int]string{
	1: "resolution_request",
	2: "resolution_reply",
	3: "registration_request",
	4: "registration_reply",
	5: "purge_request",
	6: "purge_reply",
	7: "error_indication",
	8: "traffic_indication",
}

// NHRPCIECodes maps NHRP Client Information Element codes to descriptions.
var NHRPCIECodes = map[int]string{
	0:  "Success",
	4:  "Administratively Prohibited",
	5:  "Insufficient Resources",
	12: "No Internetworking Layer Address to NBMA Address Binding Exists",
	13: "Binding Exists But Is Not Unique",
	14: "Unique Internetworking Layer Address Already Registered",
}

// NHRPErrorCodes maps NHRP Error Indication codes to descriptions.
var NHRPErrorCodes = map[int]string{
	1:  "Unrecognized Extension",
	3:  "NHRP Loop Detected",
	6:  "Protocol Address Unreachable",
	7:  "Protocol Error",
	8:  "NHRP SDU Size Exceeded",
	9:  "Invalid Extension",
	10: "Invalid NHRP Resolution Reply Received",
	11: "Authentication Failure",
	15: "Hop Count Exceeded",
}

// BGPTypes maps BGP header type numbers to RFC names.
var BGPTypes = map[int]string{1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"}

// bgpErrorClass pairs a BGP NOTIFICATION major error name with its subcode table.
type bgpErrorClass struct {
	Name     string
	Subcodes map[int]string
}

// BGPErrors maps BGP major error codes to names and subcode tables.
var BGPErrors = map[int]bgpErrorClass{
	1: {Name: "Message Header Error", Subcodes: map[int]string{1: "Connection Not Synchronized", 2: "Bad Message Length", 3: "Bad Message Type"}},
	2: {Name: "OPEN Message Error", Subcodes: map[int]string{1: "Unsupported Version Number", 2: "Bad Peer AS", 3: "Bad BGP Identifier", 4: "Unsupported Optional Parameter", 6: "Unacceptable Hold Time", 7: "Unsupported Capability", 8: "Role Mismatch"}},
	3: {Name: "UPDATE Message Error", Subcodes: map[int]string{1: "Malformed Attribute List", 2: "Unrecognized Well-known Attribute", 3: "Missing Well-known Attribute", 4: "Attribute Flags Error", 5: "Attribute Length Error", 6: "Invalid ORIGIN Attribute", 8: "Invalid NEXT_HOP Attribute", 9: "Optional Attribute Error", 10: "Invalid Network Field", 11: "Malformed AS_PATH"}},
	4: {Name: "Hold Timer Expired"},
	5: {Name: "Finite State Machine Error", Subcodes: map[int]string{1: "Unexpected Message in OpenSent", 2: "Unexpected Message in OpenConfirm", 3: "Unexpected Message in Established"}},
	6: {Name: "Cease", Subcodes: map[int]string{1: "Maximum Number of Prefixes Reached", 2: "Administrative Shutdown", 3: "Peer De-configured", 4: "Administrative Reset", 5: "Connection Rejected", 6: "Other Configuration Change", 7: "Connection Collision Resolution", 8: "Out of Resources", 9: "Hard Reset", 10: "BFD Down"}},
	7: {Name: "ROUTE-REFRESH Message Error", Subcodes: map[int]string{1: "Invalid Message Length"}},
}

// bgpHintKey indexes BGP_ERROR_HINTS by major code and optional subcode (-1 wildcard).
type bgpHintKey struct {
	Major int
	Minor int
}

// BGPErrorHints provides operator guidance for common BGP NOTIFICATION codes.
var BGPErrorHints = map[bgpHintKey]string{
	{2, 2}:  "the AS this speaker sent does not match the remote-as configured on the receiver",
	{2, 3}:  "duplicate or invalid BGP router ID",
	{2, 6}:  "a hold time of 1 or 2 seconds was proposed (not allowed)",
	{2, 7}:  "a required capability (address family, 4-byte AS) is not supported by the peer",
	{4, -1}: "no KEEPALIVE or UPDATE arrived within the hold time: peer down, path to it lost, or TCP 179 filtered",
	{6, 2}:  "the neighbor was shut down by configuration",
	{6, 3}:  "the neighbor was removed from the configuration",
	{6, 4}:  "the session was cleared administratively (clear ip bgp)",
	{6, 5}:  "the receiver has no neighbor statement for this source address",
	{6, 6}:  "a configuration change forced a reset",
	{6, 7}:  "two TCP connections collided; one was closed (normal and harmless)",
	{6, 10}: "BFD declared the neighbor down",
}

// BGPCapabilities maps BGP OPEN capability numbers to readable names.
var BGPCapabilities = map[int]string{
	1: "multiprotocol", 2: "route-refresh", 3: "outbound-route-filtering", 5: "extended-nexthop",
	6: "extended-message", 9: "bgp-role", 64: "graceful-restart", 65: "4-byte-as",
	67: "dynamic-capability", 69: "add-path", 70: "enhanced-route-refresh",
	71: "long-lived-graceful-restart", 73: "fqdn", 128: "route-refresh-cisco-old",
	131: "multisession-cisco",
}

// BGPErrorName formats a BGP NOTIFICATION major/minor pair into a human-readable string.
func BGPErrorName(major, minor *int) string {
	if major == nil {
		return "unknown"
	}
	cls, ok := BGPErrors[*major]
	name := cls.Name
	if !ok {
		name = fmt.Sprintf("error %d", *major)
	}
	if len(cls.Subcodes) > 0 && minor != nil {
		sub, sok := cls.Subcodes[*minor]
		if !sok {
			sub = fmt.Sprintf("subcode %d", *minor)
		}
		return fmt.Sprintf("%s / %s", name, sub)
	}
	return name
}

// BGPErrorHint returns an optional operator hint for a BGP NOTIFICATION error/subcode pair.
func BGPErrorHint(major, minor *int) *string {
	if major == nil {
		return nil
	}
	if minor != nil {
		if h, ok := BGPErrorHints[bgpHintKey{Major: *major, Minor: *minor}]; ok {
			return &h
		}
	}
	if h, ok := BGPErrorHints[bgpHintKey{Major: *major, Minor: -1}]; ok {
		return &h
	}
	return nil
}

// OSPFTypes maps OSPFv2 packet type numbers to protocol message names.
var OSPFTypes = map[int]string{1: "Hello", 2: "DB Description", 3: "LS Request", 4: "LS Update", 5: "LS Ack"}

// EIGRPOpcodes maps EIGRP header opcode numbers to protocol message names.
var EIGRPOpcodes = map[int]string{
	1: "Update", 3: "Query", 4: "Reply", 5: "Hello", 6: "IPX SAP", 10: "SIA-Query", 11: "SIA-Reply",
}
