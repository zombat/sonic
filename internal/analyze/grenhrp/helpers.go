// Package grenhrp helper functions for formatting CIE/error names, GRE key sets, and pointer equality.
package grenhrp

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// cieCodeName maps an NHRP CIE code to its RFC label or "code N".
func cieCodeName(code *int) string {
	if code == nil {
		return "code None"
	}
	if name, ok := model.NHRPCIECodes[*code]; ok {
		return name
	}
	return fmt.Sprintf("code %d", *code)
}

// errCodeName maps an NHRP Error Indication code to its RFC label or "error N".
func errCodeName(code *int) string {
	if code == nil {
		return "error None"
	}
	if name, ok := model.NHRPErrorCodes[*code]; ok {
		return name
	}
	return fmt.Sprintf("error %d", *code)
}

// optStr returns *s when non-nil or Python's "None" representation otherwise.
func optStr(s *string) string {
	if s == nil {
		return "None"
	}
	return *s
}

// sameKeySet reports whether two GRE key frequency maps contain the exact same key set.
func sameKeySet(a, b map[tunnelKeyVal]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// pyFormatKeySet renders sorted(map(str, keys)) matching Python's str(list[str]).
func pyFormatKeySet(m map[tunnelKeyVal]int) string {
	strs := make([]string, 0, len(m))
	for kv := range m {
		if !kv.hasKey {
			strs = append(strs, "None")
		} else {
			strs = append(strs, strconv.FormatUint(uint64(kv.key), 10))
		}
	}
	slices.Sort(strs)
	quoted := make([]string, 0, len(strs))
	for _, s := range strs {
		quoted = append(quoted, "'"+s+"'")
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// nonNilInts ensures a non-nil slice so JSON marshals [] rather than null.
func nonNilInts(in []int) []int {
	if in == nil {
		return []int{}
	}
	return in
}

// ptrIntEq compares two optional integer pointers by dereferenced value.
func ptrIntEq(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// ptrStrEq compares two optional string pointers by dereferenced value.
func ptrStrEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
