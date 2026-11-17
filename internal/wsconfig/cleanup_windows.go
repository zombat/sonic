//go:build windows

// Package wsconfig implements Windows orphan cleanup for temporary Wireshark directories.
package wsconfig

import (
	"os"
	"path/filepath"
	"syscall"
)

func raiseSignal(_ os.Signal) {}

// removeOrphans deletes leftover sonic-ws-<pid>-* directories whose creating process no longer runs.
func removeOrphans(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	selfPID := os.Getpid()
	for _, entry := range entries {
		pid, ok := parseDirPID(entry.Name())
		if !ok || pid == selfPID {
			continue
		}
		fullPath := filepath.Join(root, entry.Name())
		info, err := os.Lstat(fullPath)
		if err != nil || !info.IsDir() {
			continue
		}
		const queryLimited = 0x1000
		h, herr := syscall.OpenProcess(queryLimited, false, uint32(pid))
		if herr == nil {
			_ = syscall.CloseHandle(h)
			continue
		}
		_ = os.RemoveAll(fullPath)
	}
}
