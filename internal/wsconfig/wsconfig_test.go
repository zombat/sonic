// Package wsconfig tests ephemeral Wireshark configuration directories,
// permissions, orphan cleanup, and signal handling.
package wsconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSecretDirRoot verifies tmpfs detection on /dev/shm and mount filtering.
func TestSecretDirRoot(t *testing.T) {
	if got := SecretDirRoot(); got != "" {
		if got != "/dev/shm" {
			t.Fatalf("SecretDirRoot() = %q, want /dev/shm or empty", got)
		}
	}

	fakeMounts := filepath.Join(t.TempDir(), "mounts")
	tmpRoot := t.TempDir()
	if err := os.WriteFile(fakeMounts, []byte("none "+tmpRoot+" ext4 rw 0 0\n"), 0o600); err != nil {
		t.Fatalf("write fake mounts: %v", err)
	}
	if got := secretDirRootFrom(tmpRoot, fakeMounts); got != "" {
		t.Fatalf("expected empty for ext4 mount, got %q", got)
	}
	if err := os.WriteFile(fakeMounts, []byte("tmpfs "+tmpRoot+" tmpfs rw 0 0\n"), 0o600); err != nil {
		t.Fatalf("write tmpfs mounts: %v", err)
	}
	if got := secretDirRootFrom(tmpRoot, fakeMounts); got != tmpRoot {
		t.Fatalf("got %q, want %q", got, tmpRoot)
	}
}

// TestWithConfigPermissionsAndCleanup verifies 0700/0600 modes and removal.
func TestWithConfigPermissionsAndCleanup(t *testing.T) {
	var seenDir string
	err := WithConfig(
		map[string]string{"tacplus.key": "secret-tac"},
		map[string][]string{"esp_sa": {`"IPv4","10.0.0.1","10.0.0.2","0x100","AES-CBC","0xaa","HMAC-SHA-256-128","0xbb"`}},
		func(dir string) error {
			seenDir = dir
			info, err := os.Stat(dir)
			if err != nil {
				return err
			}
			if info.Mode().Perm() != 0o700 {
				t.Fatalf("dir perm = %o, want 0700", info.Mode().Perm())
			}
			for _, name := range []string{"preferences", "esp_sa"} {
				p := filepath.Join(dir, name)
				finfo, err := os.Stat(p)
				if err != nil {
					t.Fatalf("stat %s: %v", name, err)
				}
				if finfo.Mode().Perm() != 0o600 {
					t.Fatalf("%s perm = %o, want 0600", name, finfo.Mode().Perm())
				}
			}
			env := Env(dir)
			found := false
			for _, entry := range env {
				if entry == "WIRESHARK_CONFIG_DIR="+dir {
					found = true
				}
			}
			if !found {
				t.Fatalf("WIRESHARK_CONFIG_DIR=%s missing from Env", dir)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("WithConfig failed: %v", err)
	}
	if seenDir == "" {
		t.Fatal("callback was not called")
	}
	if _, err := os.Stat(seenDir); !os.IsNotExist(err) {
		t.Fatalf("expected dir %s to be removed, stat err = %v", seenDir, err)
	}
}

// TestRemoveOrphans verifies stale PID directories are cleaned while symlinks and live PIDs remain.
func TestRemoveOrphans(t *testing.T) {
	root := t.TempDir()
	deadDir := filepath.Join(root, "sonic-ws-9999999-old")
	if err := os.Mkdir(deadDir, 0o700); err != nil {
		t.Fatalf("mkdir deadDir: %v", err)
	}
	keepDir := filepath.Join(root, "other-dir")
	if err := os.Mkdir(keepDir, 0o700); err != nil {
		t.Fatalf("mkdir keepDir: %v", err)
	}
	targetDir := filepath.Join(root, "real-target")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatalf("mkdir targetDir: %v", err)
	}
	symlinkDir := filepath.Join(root, "sonic-ws-9999998-link")
	if err := os.Symlink(targetDir, symlinkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	removeOrphans(root)

	if _, err := os.Stat(deadDir); !os.IsNotExist(err) {
		t.Fatalf("deadDir should be removed, err = %v", err)
	}
	if _, err := os.Stat(keepDir); err != nil {
		t.Fatalf("keepDir should remain, err = %v", err)
	}
	if _, err := os.Stat(targetDir); err != nil {
		t.Fatalf("symlink target should remain, err = %v", err)
	}
}

// TestInvalidUATName verifies path traversal and reserved filenames are rejected.
func TestInvalidUATName(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "preferences", "../escape", "sub/dir"} {
		err := WithConfig(nil, map[string][]string{bad: {"row"}}, func(string) error {
			return nil
		})
		if err == nil {
			t.Fatalf("expected error for uat name %q", bad)
		}
	}
}

// TestFallbackWarning verifies newInRoot with empty root falls back to temp dir cleanly.
func TestFallbackWarning(t *testing.T) {
	dir, err := newInRoot("", map[string]string{"radius.shared_secret": "s3cr3t"}, nil)
	if err != nil {
		t.Fatalf("newInRoot fallback: %v", err)
	}
	defer func() { _ = dir.Close() }()
	if !strings.HasPrefix(dir.Path(), os.TempDir()) {
		t.Fatalf("fallback path %q not under %q", dir.Path(), os.TempDir())
	}
}

// TestSignalCleanupSubprocess validates SIGTERM and SIGINT clean up the directory
// in a real child process.
func TestSignalCleanupSubprocess(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			markerDir := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestSignalCleanupHelper$")
			cmd.Env = append(os.Environ(),
				"SONIC_WS_HELPER=1",
				"SONIC_WS_MARKER="+markerDir,
			)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatalf("stdout pipe: %v", err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatalf("start helper: %v", err)
			}

			buf := make([]byte, 512)
			n, err := stdout.Read(buf)
			if err != nil {
				_ = cmd.Process.Kill()
				t.Fatalf("read helper dir path: %v", err)
			}
			createdDir := strings.TrimSpace(string(buf[:n]))
			if createdDir == "" {
				_ = cmd.Process.Kill()
				t.Fatal("helper printed empty dir path")
			}

			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatalf("send signal %v: %v", sig, err)
			}
			done := make(chan error, 1)
			go func() {
				done <- cmd.Wait()
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatalf("helper did not exit on %v", sig)
			}
			if _, err := os.Stat(createdDir); !os.IsNotExist(err) {
				t.Fatalf("createdDir %q still exists after %v", createdDir, sig)
			}
		})
	}
}

// TestSignalCleanupHelper is the child entrypoint used by TestSignalCleanupSubprocess.
func TestSignalCleanupHelper(t *testing.T) {
	if os.Getenv("SONIC_WS_HELPER") != "1" {
		return
	}
	dir, err := New(map[string]string{"tacplus.key": "helper-secret"}, nil)
	if err != nil {
		t.Fatalf("helper New: %v", err)
	}
	_, _ = os.Stdout.WriteString(dir.Path() + "\n")
	time.Sleep(10 * time.Second)
}

// TestNilAndCleanupBranches exercises nil receivers, CleanupAll, mount parsing, and write errors.
func TestNilAndCleanupBranches(t *testing.T) {
	var nilDir *Dir
	if nilDir.Path() != "" {
		t.Fatalf("nil Dir.Path() = %q", nilDir.Path())
	}
	if err := nilDir.Close(); err != nil {
		t.Fatalf("nil Dir.Close() = %v", err)
	}

	d, err := newInRoot(t.TempDir(), map[string]string{"k": "v"}, map[string][]string{"esp_sa": {"row1"}})
	if err != nil {
		t.Fatal(err)
	}
	created := d.Path()
	CleanupAll()
	if _, err := os.Stat(created); !os.IsNotExist(err) {
		t.Fatalf("CleanupAll did not remove %q", created)
	}

	t.Setenv("WIRESHARK_CONFIG_DIR", "/stale/path")
	env := Env("/fresh/path")
	found := false
	for _, e := range env {
		if e == "WIRESHARK_CONFIG_DIR=/fresh/path" {
			found = true
		}
		if e == "WIRESHARK_CONFIG_DIR=/stale/path" {
			t.Fatal("Env kept stale WIRESHARK_CONFIG_DIR")
		}
	}
	if !found {
		t.Fatal("Env missing WIRESHARK_CONFIG_DIR=/fresh/path")
	}

	if parseMountType("badline\nfoo /other ext4 rw 0 0\n", "/dev/shm") != "" {
		t.Fatal("parseMountType should return empty when targetDir absent")
	}
	if _, ok := parseDirPID("sonic-ws-notapid-xyz"); ok {
		t.Fatal("parseDirPID should reject non-numeric pid")
	}
	if _, ok := parseDirPID("sonic-ws-"); ok {
		t.Fatal("parseDirPID should reject empty pid")
	}
	if err := writeSecretFile(filepath.Join(t.TempDir(), "missing"), "f", "x"); err == nil {
		t.Fatal("writeSecretFile into nonexistent dir should fail")
	}
	// os.Root confines writeSecretFile strictly inside dirPath even against traversal or symlink targets.
	secretDir := t.TempDir()
	outsideSecret := filepath.Join(t.TempDir(), "outside-secret")
	_ = os.Symlink(outsideSecret, filepath.Join(secretDir, "sym"))
	if err := writeSecretFile(secretDir, "../escape", "x"); err == nil {
		t.Fatal("writeSecretFile should reject path traversal under os.Root")
	}
	if err := writeSecretFile(secretDir, "sym", "x"); err == nil {
		t.Fatal("writeSecretFile should reject escaping symlink under os.Root")
	}
}

// TestSecretDirRootAndOrphanEdgeCases covers non-dir roots, missing mount info, and orphan symlinks.
func TestSecretDirRootAndOrphanEdgeCases(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "plainfile")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if secretDirRootFrom(notADir, "/proc/self/mounts") != "" {
		t.Fatal("secretDirRootFrom should reject non-directory paths")
	}
	if secretDirRootFrom(dir, filepath.Join(dir, "no-mounts-file")) != dir {
		t.Fatal("secretDirRootFrom should allow writable dir when mounts file cannot be read")
	}

	// Ensure removeOrphans handles missing roots and non-directory / symlink entries safely.
	removeOrphans(filepath.Join(dir, "no-such-root"))
	symlinkName := filepath.Join(dir, DirPrefix+"999999-sym")
	_ = os.Symlink(notADir, symlinkName)
	fileOrphan := filepath.Join(dir, DirPrefix+"999998-file")
	_ = os.WriteFile(fileOrphan, []byte("x"), 0o600)
	removeOrphans(dir)

	if _, err := newInRoot(notADir, nil, nil); err == nil {
		t.Fatal("newInRoot on file path should fail")
	}
	fallbackDir, err := newInRoot("", nil, nil)
	if err != nil {
		t.Fatalf("newInRoot fallback failed: %v", err)
	}
	if err := fallbackDir.Close(); err != nil {
		t.Fatalf("close fallbackDir: %v", err)
	}
	if err := WithConfig(nil, map[string][]string{"../bad": {"x"}}, func(string) error { return nil }); err == nil {
		t.Fatal("WithConfig should reject invalid UAT name")
	}
	if err := validateUATName("a/b"); err == nil {
		t.Fatal("validateUATName should reject slash")
	}
	roDir := filepath.Join(dir, "ro")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })
	if secretDirRootFrom(roDir, "/proc/self/mounts") != "" {
		t.Fatal("secretDirRootFrom should reject read-only dir")
	}
	InstallSignalCleanup()
	if sigStopFunc != nil {
		sigStopFunc()
	}
}
