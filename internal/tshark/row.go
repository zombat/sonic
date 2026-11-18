// Package tshark provides Row field accessors and scalar parsers for decoded
// tshark TSV lines.
package tshark

import (
	"strconv"
	"strings"
)

// Row wraps one parsed tshark TSV output row mapping logical keys to multi-occurrence values.
type Row struct {
	values map[string][]string
}

// NewRow wraps a pre-built map of field values into a Row.
func NewRow(values map[string][]string) Row {
	return Row{values: values}
}

// All returns every occurrence recorded for key in this frame.
func (r Row) All(key string) []string {
	return r.values[key]
}

// First returns the first occurrence of key and whether it was present.
func (r Row) First(key string) (string, bool) {
	vals := r.values[key]
	if len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

// FirstPtr returns a heap pointer to the first occurrence of key, or nil when absent.
func (r Row) FirstPtr(key string) *string {
	v, ok := r.First(key)
	if !ok {
		return nil
	}
	return &v
}

// At returns occurrence index of key, or empty/false when out of range.
func (r Row) At(key string, index int) (string, bool) {
	vals := r.values[key]
	if index < 0 || index >= len(vals) {
		return "", false
	}
	return vals[index], true
}

// Has reports whether key had at least one non-empty value in this row.
func (r Row) Has(key string) bool {
	return len(r.values[key]) > 0
}

// Int parses occurrence index (default 0) as a signed int pointer, or nil if absent/invalid.
func (r Row) Int(key string, index ...int) *int {
	v, ok := r.Int64(key, index...)
	if !ok {
		return nil
	}
	out := int(v)
	return &out
}

// Uint32 parses occurrence index (default 0) as a uint32 pointer, or nil if absent/invalid.
func (r Row) Uint32(key string, index ...int) *uint32 {
	v, ok := r.Int64(key, index...)
	if !ok || v < 0 {
		return nil
	}
	out := uint32(v)
	return &out
}

// Int64 parses occurrence index (default 0) supporting decimal, 0x hex, booleans, and floats.
func (r Row) Int64(key string, index ...int) (int64, bool) {
	idx := 0
	if len(index) > 0 {
		idx = index[0]
	}
	raw, ok := r.At(key, idx)
	if !ok {
		return 0, false
	}
	return ParseInt64(raw)
}

// Float64 parses the first occurrence of key as a float64, returning 0 and false when absent.
func (r Row) Float64(key string) (float64, bool) {
	raw, ok := r.First(key)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// Ints parses all valid integers from every occurrence of key.
func (r Row) Ints(key string) []int {
	vals := r.All(key)
	if len(vals) == 0 {
		return nil
	}
	out := make([]int, 0, len(vals))
	for _, raw := range vals {
		if v, ok := ParseInt64(raw); ok {
			out = append(out, int(v))
		}
	}
	return out
}

// ParseInt64 converts a tshark scalar ("12", "0x0c", "True", "12.0") into int64.
func ParseInt64(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}
	if v, err := strconv.ParseInt(value, 0, 64); err == nil {
		return v, true
	}
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		if u, err := strconv.ParseUint(value[2:], 16, 64); err == nil {
			return int64(u), true
		}
	}
	if value == "True" || value == "true" {
		return 1, true
	}
	if value == "False" || value == "false" {
		return 0, true
	}
	if f, err := strconv.ParseFloat(value, 64); err == nil {
		return int64(f), true
	}
	return 0, false
}

// HexBytes strips ':' separators from a tshark FT_BYTES string and lowercases it.
func HexBytes(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	return strings.ToLower(strings.ReplaceAll(value, ":", "")), true
}
