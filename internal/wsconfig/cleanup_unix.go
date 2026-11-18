//go:build unix

// Package wsconfig implements POSIX orphan detection and signal re-raising.
package wsconfig

import (
	"errors"
	"os"
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
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return
	}
	defer func() { _ = rootDir.Close() }()
	uid := uint32(os.Getuid())
	selfPID := os.Getpid()
	for _, entry := range entries {
		pid, ok := parseDirPID(entry.Name())
		if !ok || pid == selfPID {
			continue
		}
		// Use Lstat inside os.Root so symlinks are never followed out of root.
		info, err := rootDir.Lstat(entry.Name())
		if err != nil || !info.IsDir() {
			continue
		}
		statT, ok := info.Sys().(*syscall.Stat_t)
		if !ok || statT.Uid != uid {
			continue
		}
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			_ = rootDir.RemoveAll(entry.Name())
		}
	}
}
