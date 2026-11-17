// Package extract provides shared helpers for running tshark field queries safely.
package extract

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/zombat/sonic/internal/redact"
	"github.com/zombat/sonic/internal/tshark"
)

const (
	// maxFieldLineBytes caps a single tshark field output line at 16 MiB.
	maxFieldLineBytes = 16 * 1024 * 1024
	// maxCmdStderrBytes retains up to 4000 bytes of trailing tshark stderr text.
	maxCmdStderrBytes = 4000
)

// limitedTailBuffer accumulates at most maxCmdStderrBytes trailing stderr bytes.
type limitedTailBuffer struct {
	buf []byte
}

// Write appends p while retaining only the trailing maxCmdStderrBytes bytes.
func (b *limitedTailBuffer) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	if len(b.buf) > maxCmdStderrBytes {
		b.buf = b.buf[len(b.buf)-maxCmdStderrBytes:]
	}
	return len(p), nil
}

// String returns redacted trimmed stderr output.
func (b *limitedTailBuffer) String() string {
	return redact.RedactText(strings.TrimSpace(string(b.buf)))
}

// rawTail returns raw trimmed trailing stderr output for table-warning inspection (no secrets live here).
func (b *limitedTailBuffer) rawTail() string {
	return strings.TrimSpace(string(bytes.Clone(b.buf)))
}

// streamTsharkFields streams tshark -T fields rows for the given filter, options, and field list.
func streamTsharkFields(
	ctx context.Context,
	filePath string,
	preArgs []string,
	filter string,
	fields []string,
	aggSep string,
	maxPackets *int,
	env []string,
	onRow func(row map[string]string) error,
) (string, error) {
	args := make([]string, 0, 16+len(preArgs)+len(fields)*2)
	args = append(args, "-n", "-r", tshark.SafeCapturePath(filePath))
	args = append(args, preArgs...)
	if filter != "" {
		args = append(args, "-Y", filter)
	}
	args = append(args, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator="+aggSep, "-E", "quote=n")
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	if maxPackets != nil && *maxPackets > 0 {
		args = append(args, "-c", strconv.Itoa(*maxPackets))
	}

	cmd := exec.CommandContext(ctx, tshark.DefaultBinary, args...)
	if len(env) > 0 {
		cmd.Env = env
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("tshark stdout pipe: %w", err)
	}
	var stderr limitedTailBuffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start tshark: %w", err)
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), maxFieldLineBytes)
	produced := 0
	var cbErr error
	for sc.Scan() {
		produced++
		line := strings.TrimSuffix(sc.Text(), "\r")
		parts := strings.Split(line, "\t")
		row := make(map[string]string, len(fields))
		for i, name := range fields {
			if i < len(parts) {
				row[name] = parts[i]
			} else {
				row[name] = ""
			}
		}
		if err := onRow(row); err != nil {
			cbErr = err
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			break
		}
	}
	scanErr := sc.Err()
	waitErr := cmd.Wait()
	rawErr := stderr.rawTail()

	if cbErr != nil {
		return rawErr, cbErr
	}
	if scanErr != nil {
		return rawErr, fmt.Errorf("scan tshark output: %w", scanErr)
	}
	if waitErr != nil && produced == 0 {
		return rawErr, fmt.Errorf("tshark failed (exit %d): %s", cmd.ProcessState.ExitCode(), stderr.String())
	}
	return rawErr, nil
}
