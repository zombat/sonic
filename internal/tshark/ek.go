// Package tshark provides streaming TShark -T ek (NDJSON) multi-field extraction
// for protocols whose multi-occurrence values can contain punctuation delimiters.
package tshark

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var ekFieldReplacer = strings.NewReplacer(".", "_")
var ekAltReplacer = strings.NewReplacer(".", "_", "-", "_")

// CustomStreamOptions configures a targeted streaming -T ek capture pass.
type CustomStreamOptions struct {
	Binary        string
	FilePath      string
	DisplayFilter string
	MaxPackets    *int
	Fields        []string
	DecodeAs      []string
	Env           []string
}

type ekLineEnvelope struct {
	Timestamp string                     `json:"timestamp"`
	Layers    map[string]json.RawMessage `json:"layers"`
}

// EKFieldKey converts a dotted Wireshark field name into its -T ek JSON layer key.
func EKFieldKey(field string) string {
	return ekFieldReplacer.Replace(field)
}

// StreamEKFields runs tshark -T ek and yields one Row per packet with canonical field keys.
func StreamEKFields(ctx context.Context, opts CustomStreamOptions, fn func(Row) error) (StreamResult, error) {
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
	if len(opts.Fields) == 0 {
		return res, errors.New("no fields specified for tshark -T ek")
	}

	binary := opts.Binary
	if binary == "" {
		binary = DefaultBinary
	}
	res.VersionMajor = VersionMajor(ctx, binary)

	capturePath, cleanupCapture := PrepareCapturePath(opts.FilePath)
	defer cleanupCapture()

	args := make([]string, 0, 14+len(opts.Fields)*2+len(opts.DecodeAs)*2)
	args = append(args, "-n", "-o", "ip.defragment:FALSE")
	for _, spec := range opts.DecodeAs {
		if strings.TrimSpace(spec) != "" {
			args = append(args, "-d", spec)
		}
	}
	args = append(args, "-r", capturePath, "-T", "ek")
	for _, f := range opts.Fields {
		args = append(args, "-e", f)
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

	ekToField := make(map[string]string, len(opts.Fields)*2)
	for _, f := range opts.Fields {
		ekToField[ekAltReplacer.Replace(f)] = f
		ekToField[EKFieldKey(f)] = f
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), maxScanTokenBytes)
	produced := 0
	var cbErr error
	for sc.Scan() {
		row, ok := parseEKLine(sc.Text(), ekToField)
		if !ok {
			continue
		}
		produced++
		if err := fn(row); err != nil {
			cbErr = err
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
		return res, fmt.Errorf("scan tshark ek output: %w", scanErr)
	}
	if waitErr != nil && produced == 0 {
		if res.Stderr != "" {
			return res, fmt.Errorf("tshark failed (exit %d): %s", res.ReturnCode, res.Stderr)
		}
		return res, fmt.Errorf("tshark failed: %w", waitErr)
	}
	return res, nil
}

func parseEKLine(line string, ekToField map[string]string) (Row, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return Row{}, false
	}
	var env ekLineEnvelope
	if json.Unmarshal([]byte(trimmed), &env) != nil || len(env.Layers) == 0 {
		return Row{}, false
	}
	return NewRow(decodeEKLayers(env.Layers, ekToField)), true
}

func decodeEKLayers(rawLayers map[string]json.RawMessage, ekToField map[string]string) map[string][]string {
	values := make(map[string][]string, len(rawLayers))
	for ekKey, raw := range rawLayers {
		canonical, ok := ekToField[ekKey]
		if !ok {
			canonical = ekKey
		}
		if strs := decodeEKValue(raw); len(strs) > 0 {
			values[canonical] = strs
		}
	}
	return values
}

func decodeEKValue(raw json.RawMessage) []string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return nil
		}
		out := make([]string, 0, len(items))
		for _, item := range items {
			if s := scalarEKString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	if s := scalarEKString(raw); s != "" {
		return []string{s}
	}
	return nil
}

func scalarEKString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		if b {
			return "1"
		}
		return "0"
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}
