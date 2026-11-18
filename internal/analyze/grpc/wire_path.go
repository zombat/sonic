// Package grpc renders gNMI protobuf paths and decodes notification/error submessages.
package grpc

import (
	"cmp"
	"errors"
	"slices"
	"strings"
)

func packedVarints(values []ProtoField) ([]int, error) {
	out := []int{}
	for _, f := range values {
		if f.Wire != 2 {
			out = append(out, int(f.Varint))
			continue
		}
		pos := 0
		for pos < len(f.Bytes) {
			v, np, err := ReadVarint(f.Bytes, pos)
			if err != nil {
				return nil, err
			}
			out = append(out, int(v))
			pos = np
		}
	}
	return out, nil
}

// RenderPath formats a serialized gnmi.Path as origin:/elem[key=value]/elem.
func RenderPath(buf []byte) (*string, error) {
	if buf == nil {
		return nil, nil
	}
	fields, err := ParseFields(buf)
	if err != nil {
		return nil, err
	}
	origin := fieldText(oneField(fields, 2))
	target := fieldText(oneField(fields, 4))

	var parts []string
	for _, elem := range allFields(fields, 3) {
		if elem.Wire != 2 {
			return nil, errors.New("expected bytes for PathElem")
		}
		efields, err := ParseFields(elem.Bytes)
		if err != nil {
			return nil, err
		}
		namePtr := fieldText(oneField(efields, 1))
		name := ""
		if namePtr != nil {
			name = *namePtr
		}
		type kv struct{ k, v string }
		var keys []kv
		for _, entry := range allFields(efields, 2) {
			if entry.Wire != 2 {
				return nil, errors.New("expected bytes for PathElem key")
			}
			kfs, err := ParseFields(entry.Bytes)
			if err != nil {
				return nil, err
			}
			kp := fieldText(oneField(kfs, 1))
			vp := fieldText(oneField(kfs, 2))
			ks, vs := "", ""
			if kp != nil {
				ks = *kp
			}
			if vp != nil {
				vs = *vp
			}
			keys = append(keys, kv{k: ks, v: vs})
		}
		slices.SortFunc(keys, func(a, b kv) int {
			if c := cmp.Compare(a.k, b.k); c != 0 {
				return c
			}
			return cmp.Compare(a.v, b.v)
		})
		var b strings.Builder
		b.WriteString(name)
		for _, pair := range keys {
			b.WriteByte('[')
			b.WriteString(pair.k)
			b.WriteByte('=')
			b.WriteString(pair.v)
			b.WriteByte(']')
		}
		parts = append(parts, b.String())
	}
	if len(parts) == 0 {
		for _, v := range allFields(fields, 1) {
			tp := fieldText(v, true)
			if tp != nil {
				parts = append(parts, *tp)
			} else {
				parts = append(parts, "")
			}
		}
	}
	text := "/"
	if len(parts) > 0 {
		text = "/" + strings.Join(parts, "/")
	}
	if origin != nil && *origin != "" {
		text = *origin + ":" + text
	}
	if target != nil && *target != "" {
		text = "<" + *target + ">" + text
	}
	return &text, nil
}

// JoinPaths combines a gNMI prefix path with a relative path.
func JoinPaths(prefix, path *string) *string {
	if prefix == nil || *prefix == "" || *prefix == "/" {
		return path
	}
	if path == nil || *path == "" || *path == "/" {
		return prefix
	}
	joined := strings.TrimRight(*prefix, "/") + *path
	return &joined
}

func parseGnmiError(fields []ProtoField, num int) (*GnmiError, error) {
	raw, ok := oneBytes(fields, num)
	if !ok {
		return nil, nil
	}
	efields, err := ParseFields(raw)
	if err != nil {
		return nil, err
	}
	return &GnmiError{
		Code:    oneInt(efields, 1, 0),
		Message: fieldText(oneField(efields, 2)),
	}, nil
}

func notificationCounts(buf []byte) (int, int, error) {
	fields, err := ParseFields(buf)
	if err != nil {
		return 0, 0, err
	}
	return len(allFields(fields, 4)), len(allFields(fields, 5)), nil
}
