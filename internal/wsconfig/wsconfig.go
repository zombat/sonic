// Package wsconfig manages ephemeral Wireshark configuration directories in
// memory-backed tmpfs (/dev/shm) so decryption keys and UAT files never appear
// on command lines or persistent disks.
package wsconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// DirPrefix is the prefix for temporary Wireshark configuration directories.
	DirPrefix = "sonic-ws-"
	shmDir    = "/dev/shm"
	mountsDoc = "/proc/self/mounts"
)

var (
	liveMu      sync.Mutex
	liveDirs    = make(map[string]struct{})
	warnOnce    sync.Once
	signalOnce  sync.Once
	sigStopFunc func()
)

// Dir represents a temporary WIRESHARK_CONFIG_DIR that holds sensitive
// preferences and UAT tables until Close removes it.
type Dir struct {
	path string
}

// Path returns the filesystem path of the temporary Wireshark config directory.
func (d *Dir) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// Close removes the temporary directory and unregisters it from active tracking.
func (d *Dir) Close() error {
	if d == nil || d.path == "" {
		return nil
	}
	err := removeDir(d.path)
	d.path = ""
	return err
}

// Env returns a copy of os.Environ with WIRESHARK_CONFIG_DIR set to dirPath.
func Env(dirPath string) []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+1)
	const prefix = "WIRESHARK_CONFIG_DIR="
	for _, entry := range base {
		if strings.HasPrefix(entry, prefix) {
			continue
		}
		out = append(out, entry)
	}
	return append(out, prefix+dirPath)
}

// SecretDirRoot returns "/dev/shm" when it is a writable memory-backed
// filesystem (tmpfs or ramfs), or "" when callers must fall back to os.TempDir.
func SecretDirRoot() string {
	return secretDirRootFrom(shmDir, mountsDoc)
}

// secretDirRootFrom inspects targetDir and mountsPath to determine whether
// targetDir is a writable tmpfs or ramfs mount.
func secretDirRootFrom(targetDir, mountsPath string) string {
	info, err := os.Stat(targetDir)
	if err != nil || !info.IsDir() {
		return ""
	}
	// Probe write and execute access without following or creating predictable names.
	probe, err := os.CreateTemp(targetDir, DirPrefix+"probe-")
	if err != nil {
		return ""
	}
	probeName := probe.Name()
	_ = probe.Close()
	_ = os.Remove(probeName)

	data, err := os.ReadFile(mountsPath)
	if err == nil {
		kind := parseMountType(string(data), targetDir)
		if kind != "" && kind != "tmpfs" && kind != "ramfs" {
			return ""
		}
	}
	return targetDir
}

// parseMountType returns the filesystem type listed in mountsText for targetDir,
// or "" if targetDir has no exact entry.
func parseMountType(mountsText, targetDir string) string {
	for _, line := range strings.Split(mountsText, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == targetDir {
			return fields[2]
		}
	}
	return ""
}

// warnOnDisk emits a one-time stderr warning when falling back to an on-disk temp dir.
func warnOnDisk() {
	warnOnce.Do(func() {
		fmt.Fprintf(
			os.Stderr,
			"S.O.N.I.C.: no tmpfs at %s, so decryption keys handed to tshark are written to %s (0700, files 0600, removed after run)\n",
			shmDir,
			os.TempDir(),
		)
	})
}

// removeDir removes path and removes it from liveDirs tracking.
func removeDir(path string) error {
	err := os.RemoveAll(path)
	liveMu.Lock()
	delete(liveDirs, path)
	liveMu.Unlock()
	return err
}

// validateUATName checks that a UAT table filename stays inside the config directory.
func validateUATName(name string) error {
	if name == "" || name == "." || name == ".." || name == "preferences" {
		return fmt.Errorf("invalid uat name: %q", name)
	}
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid uat name: %q", name)
	}
	return nil
}

// writeSecretFile creates a mode-0600 file inside dirPath and writes content.
func writeSecretFile(dirPath, name, content string) error {
	target := filepath.Join(dirPath, name)
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create secret file %s: %w", name, err)
	}
	_, writeErr := f.WriteString(content)
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("write secret file %s: %w", name, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close secret file %s: %w", name, closeErr)
	}
	return nil
}

// New creates a private 0700 Wireshark configuration directory containing the
// given preferences and UAT rows, registering it for signal cleanup.
func New(preferences map[string]string, uats map[string][]string) (*Dir, error) {
	return newInRoot(SecretDirRoot(), preferences, uats)
}

// newInRoot creates the private directory under root (falling back to os.TempDir
// with a warning when root is empty) and writes all requested files.
func newInRoot(root string, preferences map[string]string, uats map[string][]string) (*Dir, error) {
	for name := range uats {
		if err := validateUATName(name); err != nil {
			return nil, err
		}
	}
	if root == "" {
		warnOnDisk()
		root = os.TempDir()
	}
	removeOrphans(root)
	InstallSignalCleanup()

	prefix := fmt.Sprintf("%s%d-", DirPrefix, os.Getpid())
	dirPath, err := os.MkdirTemp(root, prefix)
	if err != nil {
		return nil, fmt.Errorf("create wireshark config dir: %w", err)
	}
	liveMu.Lock()
	liveDirs[dirPath] = struct{}{}
	liveMu.Unlock()

	if err := os.Chmod(dirPath, 0o700); err != nil {
		_ = removeDir(dirPath)
		return nil, fmt.Errorf("chmod wireshark config dir: %w", err)
	}

	if len(preferences) > 0 {
		var sb strings.Builder
		for k, v := range preferences {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
		if err := writeSecretFile(dirPath, "preferences", sb.String()); err != nil {
			_ = removeDir(dirPath)
			return nil, err
		}
	}

	for name, rows := range uats {
		var sb strings.Builder
		for _, row := range rows {
			sb.WriteString(strings.TrimRight(row, "\n"))
			sb.WriteByte('\n')
		}
		if err := writeSecretFile(dirPath, name, sb.String()); err != nil {
			_ = removeDir(dirPath)
			return nil, err
		}
	}
	return &Dir{path: dirPath}, nil
}

// WithConfig creates a temporary Wireshark configuration directory, invokes fn
// with its path, and guarantees removal when fn returns.
func WithConfig(preferences map[string]string, uats map[string][]string, fn func(dir string) error) error {
	dir, err := New(preferences, uats)
	if err != nil {
		return err
	}
	defer func() {
		_ = dir.Close()
	}()
	return fn(dir.Path())
}
