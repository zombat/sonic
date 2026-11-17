// Package guide writes, updates, and prunes S.O.N.I.C. Agent Skill files
// atomically while refusing to overwrite non-S.O.N.I.C. files.
package guide

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// WrittenBySonic reports whether path begins with SkillMarker within its first SkillMarkerWithin lines.
func WrittenBySonic(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for i := 0; i < SkillMarkerWithin && scanner.Scan(); i++ {
		if strings.HasPrefix(scanner.Text(), SkillMarker) {
			return true
		}
	}
	return false
}

// WriteAtomic writes content to path via a temp file in the same directory with fsync and 0644 mode.
func WriteAtomic(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create skill directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".sonic-skill-*")
	if err != nil {
		return fmt.Errorf("create temp skill file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
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
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod temp skill file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace skill file %s: %w", path, err)
	}
	cleanup = false
	return nil
}

// WriteSkill atomically writes files under targetDir, preserving non-S.O.N.I.C. files
// and removing stale reference/*.md files that carry SkillMarker.
func WriteSkill(targetDir string, files map[string]string) (SkillWriteResult, error) {
	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		return SkillWriteResult{}, fmt.Errorf("resolve skill dir %s: %w", targetDir, err)
	}

	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	slices.Sort(rels)

	var foreign []string
	for _, rel := range rels {
		full := filepath.Join(absDir, filepath.FromSlash(rel))
		if _, err := os.Stat(full); err == nil && !WrittenBySonic(full) {
			foreign = append(foreign, full)
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
		full := filepath.Join(absDir, filepath.FromSlash(rel))
		if existing, err := os.ReadFile(full); err == nil && string(existing) == content {
			out.Unchanged = append(out.Unchanged, rel)
			continue
		}
		if err := WriteAtomic(full, content); err != nil {
			return SkillWriteResult{}, err
		}
		out.Written = append(out.Written, rel)
	}

	refDir := filepath.Join(absDir, "reference")
	entries, err := os.ReadDir(refDir)
	if err == nil {
		for _, ent := range entries {
			name := ent.Name()
			if ent.IsDir() || !strings.HasSuffix(name, ".md") {
				continue
			}
			rel := "reference/" + name
			full := filepath.Join(refDir, name)
			if _, expected := files[rel]; !expected && WrittenBySonic(full) {
				if err := os.Remove(full); err != nil {
					return SkillWriteResult{}, fmt.Errorf("remove stale skill reference %s: %w", full, err)
				}
				out.Removed = append(out.Removed, rel)
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
