package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompiledBinariesVersionSkillAndModelOptions(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoRoot)
	tmp := t.TempDir()
	cliBin := filepath.Join(tmp, "sonic")
	mcpBin := filepath.Join(tmp, "sonic-mcp")
	ldflags := "-X main.version=v4.0.0-e2e -X main.commit=1234abcd"

	for _, build := range []struct {
		out string
		pkg string
	}{
		{cliBin, "./cmd/sonic"},
		{mcpBin, "./cmd/sonic-mcp"},
	} {
		cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", build.out, build.pkg)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", build.pkg, err, out)
		}
	}

	// --version reports ldflags version and commit on both binaries.
	for _, tc := range []struct {
		bin  string
		want string
	}{
		{cliBin, "sonic v4.0.0-e2e (1234abcd)"},
		{mcpBin, "sonic-mcp v4.0.0-e2e (1234abcd)"},
	} {
		out, err := exec.Command(tc.bin, "--version").CombinedOutput()
		if err != nil || !strings.Contains(string(out), tc.want) {
			t.Fatalf("%s --version failed (%v): %s", tc.bin, err, out)
		}
	}

	// Both entry points produce byte-identical --create-skill trees.
	cliSkill := filepath.Join(tmp, "skill-cli")
	mcpSkill := filepath.Join(tmp, "skill-mcp")
	if out, err := exec.Command(cliBin, "--create-skill", cliSkill).CombinedOutput(); err != nil || !strings.Contains(string(out), "Skill 'sonic'") {
		t.Fatalf("sonic --create-skill failed (%v): %s", err, out)
	}
	if out, err := exec.Command(mcpBin, "--create-skill", mcpSkill).CombinedOutput(); err != nil {
		t.Fatalf("sonic-mcp --create-skill failed (%v): %s", err, out)
	}
	cliDoc, err := os.ReadFile(filepath.Join(cliSkill, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	mcpDoc, err := os.ReadFile(filepath.Join(mcpSkill, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cliDoc) != string(mcpDoc) {
		t.Fatal("SKILL.md differs between sonic --create-skill and sonic-mcp --create-skill")
	}

	// Refuses foreign SKILL.md cleanly.
	foreign := filepath.Join(tmp, "foreign")
	if err := os.MkdirAll(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "SKILL.md"), []byte("foreign\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	refCmd := exec.Command(cliBin, "--create-skill", foreign)
	refOut, refErr := refCmd.CombinedOutput()
	if refErr == nil || !strings.Contains(string(refOut), "not written by sonic --create-skill") {
		t.Fatalf("expected refusal on foreign skill dir, err=%v out=%s", refErr, refOut)
	}

	// Missing --file, rejected --api-key, and --model all --model-name conflict all exit 2.
	for _, tc := range []struct {
		args []string
		sub  string
	}{
		{nil, "--file"},
		{[]string{"--file", "x.pcap", "--api-key", "abc"}, "not defined"},
		{[]string{"--file", "x.pcap", "--model", "all", "--model-name", "llama3:8b"}, "--model-name cannot be used with --model all"},
	} {
		cmd := exec.Command(cliBin, tc.args...)
		out, err := cmd.CombinedOutput()
		if err == nil || cmd.ProcessState.ExitCode() != 2 || !strings.Contains(string(out), tc.sub) {
			t.Fatalf("sonic %v: expected exit 2 with %q, err=%v out=%s", tc.args, tc.sub, err, out)
		}
	}
}
