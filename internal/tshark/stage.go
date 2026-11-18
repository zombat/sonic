// Package tshark stages capture inputs into os.TempDir when tshark is
// confined from reading workspace or capture directories directly.
package tshark

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

var (
	stageProbeMu    sync.Mutex
	stageProbeCache = map[string]bool{}
)

// Binary returns the default tshark executable name searched on PATH.
func Binary() string {
	return DefaultBinary
}

// PrepareCapturePath returns a path to filePath that tshark can open along
// with a cleanup function. When Go can read filePath directly but tshark is
// confined from reading outside os.TempDir (for example by AppArmor), the
// file is copied into a private temporary file in os.TempDir.
func PrepareCapturePath(filePath string) (string, func()) {
	noop := func() {}
	clean := strings.TrimSpace(filePath)
	if clean == "" {
		return SafeCapturePath(filePath), noop
	}

	src, err := os.Open(clean)
	if err != nil {
		return SafeCapturePath(filePath), noop
	}
	info, statErr := src.Stat()
	if statErr != nil || info.IsDir() {
		_ = src.Close()
		return SafeCapturePath(filePath), noop
	}

	absPath, absErr := filepath.Abs(clean)
	if absErr != nil || isUnderTempDir(absPath) {
		_ = src.Close()
		return SafeCapturePath(filePath), noop
	}
	if tsharkCanReadFile(clean, filepath.Dir(absPath)) {
		_ = src.Close()
		return SafeCapturePath(filePath), noop
	}

	tmpFile, err := os.CreateTemp("", "sonic-cap-*"+filepath.Ext(clean))
	if err != nil {
		_ = src.Close()
		return SafeCapturePath(filePath), noop
	}
	staged := tmpFile.Name()
	if _, err := io.Copy(tmpFile, src); err != nil {
		_ = src.Close()
		_ = tmpFile.Close()
		_ = os.Remove(staged)
		return SafeCapturePath(filePath), noop
	}
	_ = src.Close()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(staged)
		return SafeCapturePath(filePath), noop
	}
	return SafeCapturePath(staged), func() { _ = os.Remove(staged) }
}

// isUnderTempDir reports whether absPath resolves inside os.TempDir.
func isUnderTempDir(absPath string) bool {
	tmpRoot, err := filepath.Abs(os.TempDir())
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(tmpRoot, absPath)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// tsharkCanReadFile probes whether tshark can open sampleFile directly,
// caching the result per (tshark executable path, parent directory).
func tsharkCanReadFile(sampleFile, dirPath string) bool {
	tsharkBin, err := exec.LookPath(Binary())
	if err != nil {
		return true
	}
	key := tsharkBin + "\x00" + dirPath
	stageProbeMu.Lock()
	cached, ok := stageProbeCache[key]
	stageProbeMu.Unlock()
	if ok {
		return cached
	}

	var stderr bytes.Buffer
	cmd := exec.Command(tsharkBin, "-r", SafeCapturePath(sampleFile), "-c", "1")
	cmd.Stderr = &stderr
	_ = cmd.Run()

	errText := stderr.String()
	readable := !strings.Contains(errText, "permission to read the file") &&
		!strings.Contains(errText, "Permission denied")

	stageProbeMu.Lock()
	stageProbeCache[key] = readable
	stageProbeMu.Unlock()
	return readable
}
