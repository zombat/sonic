// Package wsconfig manages cleanup of active and orphaned temporary
// Wireshark configuration directories across normal teardown and signals.
package wsconfig

import (
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// CleanupAll removes every active secret directory held by this process.
func CleanupAll() {
	liveMu.Lock()
	paths := make([]string, 0, len(liveDirs))
	for p := range liveDirs {
		paths = append(paths, p)
	}
	liveMu.Unlock()

	for _, p := range paths {
		_ = removeDir(p)
	}
}

// InstallSignalCleanup arranges for SIGTERM and SIGINT to remove all active
// secret directories before restoring default signal behavior and re-raising.
func InstallSignalCleanup() {
	signalOnce.Do(func() {
		ch := make(chan os.Signal, 2)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		sigStopFunc = func() {
			signal.Stop(ch)
		}
		go func() {
			sig, ok := <-ch
			if !ok {
				return
			}
			CleanupAll()
			signal.Stop(ch)
			if sysSig, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(os.Getpid(), sysSig)
			}
		}()
	})
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

// parseDirPID extracts the PID from a directory named "sonic-ws-<pid>-...".
func parseDirPID(name string) (int, bool) {
	if !strings.HasPrefix(name, DirPrefix) {
		return 0, false
	}
	rest := strings.TrimPrefix(name, DirPrefix)
	idx := strings.IndexByte(rest, '-')
	if idx <= 0 {
		return 0, false
	}
	pid, err := strconv.Atoi(rest[:idx])
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
