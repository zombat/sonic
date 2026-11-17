//go:build unix

// Package wsconfig implements POSIX orphan detection and signal re-raising.
package wsconfig

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func raiseSignal(sig os.Signal) {
	if sysSig, ok := sig.(syscall.Signal); ok {
		_ = syscall.Kill(os.Getpid(), sysSig)
	}
}

// removeOrphans deletes leftover sonic-ws-<pid>-* directories owned by the
// current user whose creating process no longer exists.
func removeOrphans(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	uid := uint32(os.Getuid())
	selfPID := os.Getpid()
	for _, entry := range entries {
		pid, ok := parseDirPID(entry.Name())
		if !ok || pid == selfPID {
			continue
		}
		fullPath := filepath.Join(root, entry.Name())
		// Use Lstat so symlinks are never followed out of root.
		info, err := os.Lstat(fullPath)
		if err != nil || !info.IsDir() {
			continue
		}
		statT, ok := info.Sys().(*syscall.Stat_t)
		if !ok || statT.Uid != uid {
			continue
		}
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			_ = os.RemoveAll(fullPath)
		}
	}
}
