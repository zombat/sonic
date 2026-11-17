// Package grpc implements schemaless protobuf wire decoding for gNMI, gNOI, and gRPC health.
package grpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// MaxFields bounds decoded top-level protobuf fields per message against malformed bombs.
	MaxFields = 20000
	// MaxList bounds repeated paths, models, and subscriptions kept per decoded message.
	MaxList = 20
)

// Encodings maps gNMI Encoding enum values to canonical names.
var Encodings = map[int]string{
	0: "JSON", 1: "BYTES", 2: "PROTO", 3: "ASCII", 4: "JSON_IETF",
}

// DataTypes maps gNMI GetRequest.DataType enum values to names.
var DataTypes = map[int]string{
	0: "ALL", 1: "CONFIG", 2: "STATE", 3: "OPERATIONAL",
}

// SubscriptionListModes maps gNMI SubscriptionList.Mode enum values to names.
var SubscriptionListModes = map[int]string{
	0: "STREAM", 1: "ONCE", 2: "POLL",
}

// SubscriptionModes maps gNMI SubscriptionMode enum values to names.
var SubscriptionModes = map[int]string{
	0: "TARGET_DEFINED", 1: "ON_CHANGE", 2: "SAMPLE",
}

// UpdateOps maps gNMI UpdateResult.Operation enum values to names.
var UpdateOps = map[int]string{
	0: "INVALID", 1: "DELETE", 2: "REPLACE", 3: "UPDATE", 4: "UNION_REPLACE",
}

// HealthStatus maps grpc.health.v1.HealthCheckResponse.ServingStatus enum values to names.
var HealthStatus = map[int]string{
	0: "UNKNOWN", 1: "SERVING", 2: "NOT_SERVING", 3: "SERVICE_UNKNOWN",
}

// ProtoField holds one decoded protobuf tag-value pair without requiring .proto schemas.
type ProtoField struct {
	Num    int
	Wire   int
	Varint uint64
	Bytes  []byte
}

// GnmiError represents the deprecated in-band gnmi.Error {code, message}.
type GnmiError struct {
	Code    int     `json:"code"`
	Message *string `json:"message"`
}

// EncodingName returns the gNMI encoding name for value, or "vendor encoding N".
func EncodingName(value *int) *string {
	if value == nil {
		return nil
	}
	if name, ok := Encodings[*value]; ok {
		return &name
	}
	s := fmt.Sprintf("vendor encoding %d", *value)
	return &s
}

// ReadVarint decodes one base-128 protobuf varint starting at pos.
func ReadVarint(buf []byte, pos int) (uint64, int, error) {
	var result uint64
	for shift := uint(0); ; shift += 7 {
		if pos >= len(buf) || shift > 63 {
			return 0, pos, errors.New("truncated varint")
		}
		b := buf[pos]
		pos++
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, pos, nil
		}
	}
}

// ParseFields decodes top-level protobuf wire fields (wire types 0, 1, 2, 5).
func ParseFields(buf []byte) ([]ProtoField, error) {
	var out []ProtoField
	pos := 0
	for pos < len(buf) {
		if len(out) >= MaxFields {
			return nil, errors.New("too many fields")
		}
		key, nextPos, err := ReadVarint(buf, pos)
		if err != nil {
			return nil, err
		}
		pos = nextPos
		num := int(key >> 3)
		wire := int(key & 7)
		if num == 0 {
			return nil, errors.New("field number 0")
		}
		pf := ProtoField{Num: num, Wire: wire}
		switch wire {
		case 0:
			v, np, err := ReadVarint(buf, pos)
			if err != nil {
				return nil, err
			}
			pf.Varint = v
			pos = np
		case 1:
			if pos+8 > len(buf) {
				return nil, errors.New("truncated fixed64")
			}
			pf.Varint = binary.LittleEndian.Uint64(buf[pos : pos+8])
			pos += 8
		case 2:
			ln, np, err := ReadVarint(buf, pos)
			if err != nil {
				return nil, err
			}
			pos = np
			if ln > uint64(len(buf)-pos) {
				return nil, errors.New("truncated length-delimited field")
			}
			end := pos + int(ln)
			pf.Bytes = buf[pos:end]
			pos = end
		case 5:
			if pos+4 > len(buf) {
				return nil, errors.New("truncated fixed32")
			}
			pf.Varint = uint64(binary.LittleEndian.Uint32(buf[pos : pos+4]))
			pos += 4
		default:
			return nil, fmt.Errorf("unsupported wire type %d", wire)
		}
		out = append(out, pf)
	}
	return out, nil
}

func allFields(fields []ProtoField, num int) []ProtoField {
	var out []ProtoField
	for _, f := range fields {
		if f.Num == num {
			out = append(out, f)
		}
	}
	return out
}

func oneField(fields []ProtoField, num int) (ProtoField, bool) {
	for i := len(fields) - 1; i >= 0; i-- {
		if fields[i].Num == num {
			return fields[i], true
		}
	}
	return ProtoField{}, false
}

func oneInt(fields []ProtoField, num, def int) int {
	if f, ok := oneField(fields, num); ok && f.Wire != 2 {
		return int(f.Varint)
	}
	return def
}

func oneBytes(fields []ProtoField, num int) ([]byte, bool) {
	f, ok := oneField(fields, num)
	if !ok || f.Wire != 2 {
		return nil, false
	}
	return f.Bytes, true
}

func fieldText(f ProtoField, ok bool) *string {
	if !ok || f.Wire != 2 {
		return nil
	}
	s := strings.ToValidUTF8(string(f.Bytes), "\ufffd")
	return &s
}

func enumName(table map[int]string, val int) string {
	if s, ok := table[val]; ok {
		return s
	}
	return strconv.Itoa(val)
}
