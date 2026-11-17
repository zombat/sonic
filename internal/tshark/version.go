// Package tshark version lookup, binary discovery, and fragment offset normalization.
package tshark

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var (
	versionRe = regexp.MustCompile(`TShark \(Wireshark\) (\d+)`)

	versionMu         sync.Mutex
	versionMajorCache = map[string]int{}
	versionStrCache   = map[string]string{}
)

// Available reports whether the named tshark binary can be found on PATH.
func Available(binary string) bool {
	if binary == "" {
		binary = DefaultBinary
	}
	_, err := exec.LookPath(binary)
	return err == nil
}

// VersionString returns the trimmed first line of `tshark --version`, or nil if unavailable.
func VersionString(ctx context.Context, binary string) *string {
	if binary == "" {
		binary = DefaultBinary
	}
	versionMu.Lock()
	if cached, ok := versionStrCache[binary]; ok {
		versionMu.Unlock()
		v := cached
		return &v
	}
	versionMu.Unlock()

	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return nil
	}
	text := string(out)
	if text == "" {
		return nil
	}
	line := text
	if idx := strings.IndexByte(text, '\n'); idx >= 0 {
		line = text[:idx]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	versionMu.Lock()
	versionStrCache[binary] = line
	versionMu.Unlock()
	v := line
	return &v
}

// VersionMajor returns the Wireshark/TShark major version number, or 0 if unknown.
func VersionMajor(ctx context.Context, binary string) int {
	if binary == "" {
		binary = DefaultBinary
	}
	versionMu.Lock()
	if v, ok := versionMajorCache[binary]; ok {
		versionMu.Unlock()
		return v
	}
	versionMu.Unlock()

	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return 0
	}
	m := versionRe.FindSubmatch(out)
	if len(m) < 2 {
		return 0
	}
	v, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0
	}
	versionMu.Lock()
	versionMajorCache[binary] = v
	versionMu.Unlock()
	return v
}

// FragOffsetBytes normalizes ip.frag_offset into bytes across Wireshark 3.x and 4.x.
func FragOffsetBytes(raw, versionMajor int) int {
	if versionMajor >= 4 {
		return raw * 8
	}
	return raw
}
