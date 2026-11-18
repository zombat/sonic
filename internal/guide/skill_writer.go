// Package guide writes, updates, and prunes S.O.N.I.C. Agent Skill files
// atomically under os.Root confinement while refusing to overwrite non-S.O.N.I.C. files.
package guide

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
)

var atomicTmpSeq atomic.Uint64

func hasSkillMarker(r io.Reader) bool {
	scanner := bufio.NewScanner(r)
	for i := 0; i < SkillMarkerWithin && scanner.Scan(); i++ {
		if strings.HasPrefix(scanner.Text(), SkillMarker) {
			return true
		}
	}
	return false
}

// WrittenBySonic reports whether path begins with SkillMarker within its first SkillMarkerWithin lines.
func WrittenBySonic(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	root, err := os.OpenRoot(filepath.Dir(absPath))
	if err != nil {
		return false
	}
	defer func() { _ = root.Close() }()
	return writtenBySonicInRoot(root, filepath.Base(absPath))
}

func writtenBySonicInRoot(root *os.Root, rel string) bool {
	f, err := root.Open(filepath.FromSlash(rel))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	return hasSkillMarker(f)
}

// WriteAtomic writes content to path via a temp file inside os.Root with fsync and 0644 mode.
func WriteAtomic(path, content string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve skill path %s: %w", path, err)
	}
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create skill directory %s: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open skill directory root %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()
	return writeAtomicInRoot(root, filepath.Base(absPath), content)
}

func writeAtomicInRoot(root *os.Root, rel, content string) error {
	nativeRel := filepath.FromSlash(rel)
	dirRel := filepath.Dir(nativeRel)
	if dirRel != "." {
		if err := root.MkdirAll(dirRel, 0o755); err != nil {
			return fmt.Errorf("create skill subdirectory %s: %w", dirRel, err)
		}
	}
	seq := atomicTmpSeq.Add(1)
	tmpName := ".sonic-skill-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(seq, 10)
	tmpRel := tmpName
	if dirRel != "." {
		tmpRel = dirRel + string(filepath.Separator) + tmpName
	}

	tmp, err := root.OpenFile(tmpRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create temp skill file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = root.Remove(tmpRel)
		}
	}()

	if _, err := io.WriteString(tmp, content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp skill file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp skill file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp skill file: %w", err)
	}
	if err := root.Chmod(tmpRel, 0o644); err != nil {
		return fmt.Errorf("chmod temp skill file: %w", err)
	}
	if err := root.Rename(tmpRel, nativeRel); err != nil {
		return fmt.Errorf("replace skill file %s: %w", rel, err)
	}
	cleanup = false
	return nil
}

// WriteSkill atomically writes files under targetDir confined via os.Root, preserving
// non-S.O.N.I.C. files and removing stale reference/*.md files that carry SkillMarker.
func WriteSkill(targetDir string, files map[string]string) (SkillWriteResult, error) {
	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		return SkillWriteResult{}, fmt.Errorf("resolve skill dir %s: %w", targetDir, err)
	}
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return SkillWriteResult{}, fmt.Errorf("create skill dir %s: %w", absDir, err)
	}
	root, err := os.OpenRoot(absDir)
	if err != nil {
		return SkillWriteResult{}, fmt.Errorf("open skill dir %s: %w", absDir, err)
	}
	defer func() { _ = root.Close() }()

	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	slices.Sort(rels)

	var foreign []string
	for _, rel := range rels {
		nativeRel := filepath.FromSlash(rel)
		if linfo, lerr := root.Lstat(nativeRel); lerr == nil && (linfo.Mode()&os.ModeSymlink) != 0 {
			return SkillWriteResult{}, fmt.Errorf("refusing symlink path inside skill dir: %s", rel)
		}
		if _, err := root.Stat(nativeRel); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return SkillWriteResult{}, fmt.Errorf("stat skill file %s: %w", rel, err)
			}
		} else if !writtenBySonicInRoot(root, rel) {
			foreign = append(foreign, filepath.Join(absDir, nativeRel))
		}
	}
	if len(foreign) > 0 {
		return SkillWriteResult{}, &SkillWriteRefusedError{Paths: foreign}
	}

	out := SkillWriteResult{
		Written:   []string{},
		Unchanged: []string{},
		Removed:   []string{},
	}
	for _, rel := range rels {
		content := files[rel]
		nativeRel := filepath.FromSlash(rel)
		if existing, err := root.ReadFile(nativeRel); err == nil && string(existing) == content {
			out.Unchanged = append(out.Unchanged, rel)
			continue
		}
		if err := writeAtomicInRoot(root, rel, content); err != nil {
			return SkillWriteResult{}, err
		}
		out.Written = append(out.Written, rel)
	}

	if d, err := root.Open("reference"); err == nil {
		entries, rerr := d.ReadDir(-1)
		_ = d.Close()
		if rerr == nil {
			for _, ent := range entries {
				name := ent.Name()
				if ent.IsDir() || !strings.HasSuffix(name, ".md") {
					continue
				}
				rel := "reference/" + name
				if _, expected := files[rel]; !expected && writtenBySonicInRoot(root, rel) {
					if err := root.Remove(filepath.FromSlash(rel)); err != nil {
						return SkillWriteResult{}, fmt.Errorf("remove stale skill reference %s: %w", rel, err)
					}
					out.Removed = append(out.Removed, rel)
				}
			}
		}
	}
	return out, nil
}

// CreateSkill renders the S.O.N.I.C. skill from tools/CLI flags and writes it to targetDir.
func CreateSkill(targetDir string, tools []ToolSpec, cliCommand string, flags []CLIOptionSpec) (SkillWriteResult, error) {
	files, err := RenderSkill(tools, cliCommand, flags)
	if err != nil {
		return SkillWriteResult{}, err
	}
	return WriteSkill(targetDir, files)
}

// CreateSkillCommand executes --create-skill for CLI binaries and reports status on out/errOut.
func CreateSkillCommand(targetDir string, tools []ToolSpec, cliCommand string, flags []CLIOptionSpec, out, errOut io.Writer) int {
	if targetDir == "" {
		targetDir = DefaultSkillDir()
	}
	res, err := CreateSkill(targetDir, tools, cliCommand, flags)
	if err != nil {
		switch e := err.(type) {
		case *SkillWriteRefusedError:
			fmt.Fprintf(errOut, "sonic: %s\n", e.Error())
		default:
			fmt.Fprintf(errOut, "sonic: cannot write the skill: %s\n", err.Error())
		}
		return 1
	}
	absDir, _ := filepath.Abs(targetDir)
	fmt.Fprintf(out, "Skill '%s' in %s: %d written, %d unchanged, %d removed.\n",
		SkillName, absDir, len(res.Written), len(res.Unchanged), len(res.Removed))
	return 0
}
