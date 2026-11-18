// Package tshark wraps TShark field resolution, version checks, and streaming TSV extraction.
package tshark

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/zombat/sonic/internal/redact"
)

const (
	// DefaultBinary is the executable name searched on PATH for tshark.
	DefaultBinary = "tshark"
	// maxScanTokenBytes caps a single tshark output line (16 MiB) for large hex payloads.
	maxScanTokenBytes = 16 * 1024 * 1024
	// maxStderrBytes caps retained stderr output for diagnostics.
	maxStderrBytes = 2000
)

var (
	cacheMu    sync.Mutex
	fieldCache = map[string]map[string]string{}
)

// SafeCapturePath neutralizes capture filenames starting with '-' so tshark
// cannot treat a path as stdin or an option flag.
func SafeCapturePath(path string) string {
	if strings.HasPrefix(path, "-") {
		return "./" + path
	}
	return path
}

// ResolveFields resolves AllFields() against `tshark -G fields`, caching the map per binary.
func ResolveFields(ctx context.Context, binary string) map[string]string {
	if binary == "" {
		binary = DefaultBinary
	}
	cacheMu.Lock()
	if cached, ok := fieldCache[binary]; ok {
		cacheMu.Unlock()
		return cached
	}
	cacheMu.Unlock()

	specs := AllFields()
	wanted := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		for _, c := range spec.Candidates {
			wanted[c] = struct{}{}
		}
	}

	known := make(map[string]struct{}, len(wanted))
	cmd := exec.CommandContext(ctx, binary, "-G", "fields")
	out, err := cmd.Output()
	if err == nil {
		sc := bufio.NewScanner(bytes.NewReader(out))
		sc.Buffer(make([]byte, 64*1024), maxScanTokenBytes)
		for sc.Scan() {
			parts := strings.SplitN(sc.Text(), "\t", 4)
			if len(parts) > 2 && parts[0] == "F" {
				if _, ok := wanted[parts[2]]; ok {
					known[parts[2]] = struct{}{}
				}
			}
		}
	}

	resolved := make(map[string]string, len(specs))
	for _, spec := range specs {
		for _, cand := range spec.Candidates {
			if _, ok := known[cand]; ok {
				resolved[spec.Key] = cand
				break
			}
		}
	}

	// Only cache when tshark actually yielded fields so transient failures can recover.
	if len(known) > 0 {
		cacheMu.Lock()
		fieldCache[binary] = resolved
		cacheMu.Unlock()
	}
	return resolved
}

// StreamOptions configures one tshark capture extraction run.
type StreamOptions struct {
	Binary        string
	FilePath      string
	DisplayFilter string
	MaxPackets    *int
	Since         *float64
	Until         *float64
	Env           []string
}

// StreamResult carries extractor field diagnostics and process status.
type StreamResult struct {
	MissingFields []string
	ReturnCode    int
	Stderr        string
	VersionMajor  int
}

// tailBuffer keeps only the last maxStderrBytes of stderr to bound memory.
type tailBuffer struct {
	buf []byte
}

// Write appends p while keeping at most maxStderrBytes trailing bytes.
func (tb *tailBuffer) Write(p []byte) (int, error) {
	tb.buf = append(tb.buf, p...)
	if len(tb.buf) > maxStderrBytes {
		tb.buf = tb.buf[len(tb.buf)-maxStderrBytes:]
	}
	return len(p), nil
}

// String returns trimmed redacted stderr content.
func (tb *tailBuffer) String() string {
	return redact.RedactText(strings.TrimSpace(string(tb.buf)))
}

// StreamFields invokes tshark with -T fields and delivers one Row per frame to fn.
func StreamFields(ctx context.Context, opts StreamOptions, fn func(Row) error) (StreamResult, error) {
	var res StreamResult
	if opts.FilePath == "" {
		return res, errors.New("empty capture file path")
	}
	info, err := os.Stat(opts.FilePath)
	if err != nil {
		return res, fmt.Errorf("capture file stat failed: %w", err)
	}
	if info.IsDir() {
		return res, fmt.Errorf("capture path is a directory: %s", opts.FilePath)
	}

	binary := opts.Binary
	if binary == "" {
		binary = DefaultBinary
	}
	resolved := ResolveFields(ctx, binary)
	res.VersionMajor = VersionMajor(ctx, binary)

	specs := AllFields()
	keys := make([]string, 0, len(specs))
	missing := make([]string, 0)
	for _, spec := range specs {
		if _, ok := resolved[spec.Key]; ok {
			keys = append(keys, spec.Key)
		} else {
			missing = append(missing, spec.Key)
		}
	}
	res.MissingFields = missing

	// Pass ip.defragment:FALSE so IPv4 fragments stay separate rows per frame.
	args := []string{
		"-n", "-o", "ip.defragment:FALSE",
		"-r", SafeCapturePath(opts.FilePath),
		"-T", "fields",
		"-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=|", "-E", "quote=n",
	}
	for _, key := range keys {
		args = append(args, "-e", resolved[key])
	}
	if opts.DisplayFilter != "" {
		args = append(args, "-Y", opts.DisplayFilter)
	}
	if opts.MaxPackets != nil && *opts.MaxPackets > 0 {
		args = append(args, "-c", strconv.Itoa(*opts.MaxPackets))
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	if len(opts.Env) > 0 {
		cmd.Env = opts.Env
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return res, fmt.Errorf("tshark stdout pipe: %w", err)
	}
	var errTail tailBuffer
	cmd.Stderr = &errTail

	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("start tshark: %w", err)
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), maxScanTokenBytes)
	produced := 0
	var cbErr error
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		parts := strings.Split(line, "\t")
		values := make(map[string][]string, len(keys))
		for idx, key := range keys {
			if idx < len(parts) && parts[idx] != "" {
				values[key] = strings.Split(parts[idx], "|")
			}
		}
		produced++
		if err := fn(NewRow(values)); err != nil {
			cbErr = err
			// Terminate child so cmd.Wait closes pipes cleanly without blocking.
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			break
		}
	}
	scanErr := sc.Err()
	waitErr := cmd.Wait()
	res.Stderr = errTail.String()
	if cmd.ProcessState != nil {
		res.ReturnCode = cmd.ProcessState.ExitCode()
	}

	if cbErr != nil {
		return res, cbErr
	}
	if scanErr != nil {
		return res, fmt.Errorf("scan tshark output: %w", scanErr)
	}
	if waitErr != nil && produced == 0 {
		if res.Stderr != "" {
			return res, fmt.Errorf("tshark failed (exit %d): %s", res.ReturnCode, res.Stderr)
		}
		return res, fmt.Errorf("tshark failed: %w", waitErr)
	}
	return res, nil
}
