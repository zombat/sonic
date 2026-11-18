//go:build ignore

// Tool pack_release bundles cross-compiled S.O.N.I.C. binary directories into
// platform .tar.gz or .zip release archives and writes a sorted SHA256SUMS manifest.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// deterministicTime keeps release archives reproducible across runs on the same commit.
var deterministicTime = time.Unix(1700000000, 0).UTC()

func main() {
	stageDir := flag.String("stage", "build/release/stage", "directory containing staged platform folders")
	outDir := flag.String("out", "build/release", "destination directory for archives and SHA256SUMS")
	flag.Parse()

	if err := run(*stageDir, *outDir); err != nil {
		fmt.Fprintf(os.Stderr, "pack_release: %v\n", err)
		os.Exit(1)
	}
}

func run(stageDir, outDir string) error {
	entries, err := os.ReadDir(stageDir)
	if err != nil {
		return fmt.Errorf("read stage directory %s: %w", stageDir, err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output directory %s: %w", outDir, err)
	}

	var archives []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		srcDir := filepath.Join(stageDir, name)
		files, err := collectFiles(srcDir)
		if err != nil {
			return err
		}
		if strings.Contains(name, "windows-") {
			archiveName := name + ".zip"
			if err := writeZip(filepath.Join(outDir, archiveName), name, srcDir, files); err != nil {
				return err
			}
			archives = append(archives, archiveName)
			continue
		}
		archiveName := name + ".tar.gz"
		if err := writeTarGz(filepath.Join(outDir, archiveName), name, srcDir, files); err != nil {
			return err
		}
		archives = append(archives, archiveName)
	}
	if len(archives) == 0 {
		return fmt.Errorf("no staged platform directories found in %s", stageDir)
	}
	sort.Strings(archives)
	return writeChecksums(outDir, archives)
}

func collectFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", dir, err)
	}
	sort.Strings(files)
	return files, nil
}

func writeTarGz(dst, rootPrefix, srcDir string, files []string) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	for _, rel := range files {
		full := filepath.Join(srcDir, filepath.FromSlash(rel))
		info, err := os.Stat(full)
		if err != nil {
			_ = tw.Close()
			_ = gw.Close()
			_ = f.Close()
			return fmt.Errorf("stat %s: %w", full, err)
		}
		mode := int64(0o644)
		if info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		hdr := &tar.Header{
			Name:    rootPrefix + "/" + rel,
			Mode:    mode,
			Size:    info.Size(),
			ModTime: deterministicTime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gw.Close()
			_ = f.Close()
			return fmt.Errorf("write tar header %s: %w", rel, err)
		}
		if err := copyInto(tw, full); err != nil {
			_ = tw.Close()
			_ = gw.Close()
			_ = f.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		_ = gw.Close()
		_ = f.Close()
		return fmt.Errorf("close tar %s: %w", dst, err)
	}
	if err := gw.Close(); err != nil {
		_ = f.Close()
		return fmt.Errorf("close gzip %s: %w", dst, err)
	}
	return f.Close()
}

func writeZip(dst, rootPrefix, srcDir string, files []string) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	zw := zip.NewWriter(f)

	for _, rel := range files {
		full := filepath.Join(srcDir, filepath.FromSlash(rel))
		info, err := os.Stat(full)
		if err != nil {
			_ = zw.Close()
			_ = f.Close()
			return fmt.Errorf("stat %s: %w", full, err)
		}
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			_ = zw.Close()
			_ = f.Close()
			return err
		}
		hdr.Name = rootPrefix + "/" + rel
		hdr.Method = zip.Deflate
		hdr.Modified = deterministicTime
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			_ = zw.Close()
			_ = f.Close()
			return fmt.Errorf("create zip entry %s: %w", rel, err)
		}
		if err := copyInto(w, full); err != nil {
			_ = zw.Close()
			_ = f.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		return fmt.Errorf("close zip %s: %w", dst, err)
	}
	return f.Close()
}

func copyInto(w io.Writer, srcPath string) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", srcPath, err)
	}
	defer func() { _ = in.Close() }()
	if _, err := io.Copy(w, in); err != nil {
		return fmt.Errorf("copy %s: %w", srcPath, err)
	}
	return nil
}

func writeChecksums(outDir string, archives []string) error {
	var lines strings.Builder
	for _, name := range archives {
		sum, err := sha256File(filepath.Join(outDir, name))
		if err != nil {
			return err
		}
		fmt.Fprintf(&lines, "%s  %s\n", sum, name)
	}
	return os.WriteFile(filepath.Join(outDir, "SHA256SUMS"), []byte(lines.String()), 0o644)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open for checksum %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
