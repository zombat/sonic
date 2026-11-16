// Package parity tests JSON comparison and golden file diffing.
package parity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompareJSON verifies matching and mismatching JSON cases across types.
func TestCompareJSON(t *testing.T) {
	tests := []struct {
		name      string
		got       string
		want      string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "identical nested structures",
			got:     `{"a":1,"b":[true,null,"x"],"c":{"k":1.0000001}}`,
			want:    `{"c":{"k":1.0000002},"b":[true,null,"x"],"a":1}`,
			wantErr: false,
		},
		{
			name:      "float outside tolerance",
			got:       `{"t":1.001}`,
			want:      `{"t":1.0}`,
			wantErr:   true,
			errSubstr: "$.t:",
		},
		{
			name:      "null vs empty slice",
			got:       `{"items":null}`,
			want:      `{"items":[]}`,
			wantErr:   true,
			errSubstr: "$.items:",
		},
		{
			name:      "missing key",
			got:       `{"a":1}`,
			want:      `{"a":1,"b":2}`,
			wantErr:   true,
			errSubstr: "$.b: missing key",
		},
		{
			name:      "extra key",
			got:       `{"a":1,"extra":true}`,
			want:      `{"a":1}`,
			wantErr:   true,
			errSubstr: "$.extra: unexpected extra key",
		},
		{
			name:      "slice length mismatch",
			got:       `{"list":[1]}`,
			want:      `{"list":[1,2]}`,
			wantErr:   true,
			errSubstr: "$.list: array length",
		},
		{
			name:      "slice element mismatch",
			got:       `{"list":["a","b"]}`,
			want:      `{"list":["a","c"]}`,
			wantErr:   true,
			errSubstr: "$.list[1]:",
		},
		{
			name:      "type mismatch object vs array",
			got:       `{"x":[]}`,
			want:      `{"x":{}}`,
			wantErr:   true,
			errSubstr: "$.x:",
		},
		{
			name:      "type mismatch string vs number",
			got:       `{"x":"1"}`,
			want:      `{"x":1}`,
			wantErr:   true,
			errSubstr: "$.x:",
		},
		{
			name:      "bool mismatch",
			got:       `{"ok":false}`,
			want:      `{"ok":true}`,
			wantErr:   true,
			errSubstr: "$.ok:",
		},
		{
			name:      "bool type mismatch",
			got:       `{"ok":1}`,
			want:      `{"ok":true}`,
			wantErr:   true,
			errSubstr: "$.ok:",
		},
		{
			name:      "string type mismatch",
			got:       `{"s":1}`,
			want:      `{"s":"1"}`,
			wantErr:   true,
			errSubstr: "$.s:",
		},
		{
			name:      "array type mismatch",
			got:       `{"a":{}}`,
			want:      `{"a":[]}`,
			wantErr:   true,
			errSubstr: "$.a:",
		},
		{
			name:      "invalid got json",
			got:       `{bad`,
			want:      `{}`,
			wantErr:   true,
			errSubstr: "unmarshal got json",
		},
		{
			name:      "invalid want json",
			got:       `{}`,
			want:      `{bad`,
			wantErr:   true,
			errSubstr: "unmarshal want json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CompareJSON([]byte(tc.got), []byte(tc.want))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestCompareGolden verifies CompareGolden against a temporary golden JSON file.
func TestCompareGolden(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.json")
	if err := os.WriteFile(path, []byte(`{"name":"sonic","values":[1,2,3]}`), 0o600); err != nil {
		t.Fatalf("write golden: %v", err)
	}
	got := map[string]any{
		"name":   "sonic",
		"values": []int{1, 2, 3},
	}
	CompareGolden(t, got, path)
}
