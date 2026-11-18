// Package tui provides terminal control-sequence sanitization helpers so
// untrusted capture text cannot forge escape or cursor control sequences.
package tui

import (
	"strings"
	"unicode/utf8"
)

// SanitizeTerminalText strips ANSI/OSC escape sequences and C0/C1 control
// characters from untrusted capture strings before writing them to a terminal.
func SanitizeTerminalText(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		b := s[i]
		if b == 0x1b {
			i = skipEscapeSeq(s, i)
			continue
		}
		if b == '\r' || b == '\n' {
			if b == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			sb.WriteByte(' ')
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if (r < 0x20 && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func skipEscapeSeq(s string, i int) int {
	if i+1 >= len(s) {
		return i + 1
	}
	next := s[i+1]
	if next == '[' {
		j := i + 2
		for j < len(s) && s[j] >= 0x20 && s[j] <= 0x3f {
			j++
		}
		if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
			return j + 1
		}
		return j
	}
	if next == ']' || next == 'P' || next == '_' || next == '^' || next == 'X' {
		j := i + 2
		for j < len(s) {
			if s[j] == 0x07 {
				return j + 1
			}
			if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' {
				return j + 2
			}
			if s[j] == '\r' || s[j] == '\n' {
				return j
			}
			j++
		}
		return j
	}
	if next >= 0x20 && next <= 0x7e {
		return i + 2
	}
	return i + 1
}
