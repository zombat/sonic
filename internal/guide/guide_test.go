package guide_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/zombat/sonic/internal/analyze/netorch"
	"github.com/zombat/sonic/internal/guide"
	"github.com/zombat/sonic/internal/mcpserver"
)

func liveSpecs(t *testing.T) []guide.ToolSpec {
	t.Helper()
	specs, err := mcpserver.DefaultToolSpecs()
	if err != nil {
		t.Fatalf("DefaultToolSpecs: %v", err)
	}
	return specs
}

func TestInstructionsShortCompleteAndNoEmDash(t *testing.T) {
	specs := liveSpecs(t)
	text := guide.Instructions(specs)
	if len(text) == 0 || len(text) >= 2048 {
		t.Fatalf("instructions length %d out of bounds (1..2047)", len(text))
	}
	if strings.ContainsRune(text, '\u2014') {
		t.Fatal("em-dash found in instructions")
	}
	for _, s := range specs {
		if !strings.Contains(text, s.Name) {
			t.Fatalf("instructions missing registered tool %s", s.Name)
		}
	}
	for _, kw := range []string{"absolute", "[LLM]", "max_items", "status", "capture point", "SONIC_LLM_PROVIDER"} {
		if !strings.Contains(text, kw) {
			t.Fatalf("instructions missing keyword %q", kw)
		}
	}

	// Verify extra non-guide tools and LLM entries also format cleanly.
	withLLM := append([]guide.ToolSpec{}, specs...)
	withLLM = append(withLLM,
		guide.ToolSpec{Name: "analyze_pcap", Title: "LLM"},
		guide.ToolSpec{Name: "custom_extra_tool", Title: "Custom Extra"},
	)
	full := guide.Instructions(withLLM)
	if !strings.Contains(full, "analyze_pcap [LLM]") || !strings.Contains(full, "custom_extra_tool: Custom Extra") {
		t.Fatalf("unexpected instructions with extra tools: %s", full)
	}
}

func TestToolOptionsAndWorkflowTextFormatting(t *testing.T) {
	for _, entry := range guide.AllToolGuide {
		title, notes, ok := guide.ToolOptions(entry.Name)
		if !ok || title == "" || !notes.ReadOnlyHint || notes.DestructiveHint || notes.IdempotentHint == entry.LLM || notes.OpenWorldHint != entry.LLM {
			t.Fatalf("unexpected ToolOptions for %s: title=%q notes=%+v ok=%v", entry.Name, title, notes, ok)
		}
	}
	if _, _, ok := guide.ToolOptions("no_such_tool"); ok {
		t.Fatal("expected false for unknown ToolOptions")
	}

	filled, err := guide.WorkflowText("check_vpn_encryption", map[string]string{
		"file_path": "/c/wan.pcap",
		"peers":     "192.0.2.1, 198.51.100.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filled, "analyze_vpn_pcap(file_path='/c/wan.pcap', peers=['192.0.2.1', '198.51.100.2'])") {
		t.Fatalf("unexpected peers substitution: %s", filled)
	}

	emptyPeers, err := guide.WorkflowText("check_vpn_encryption", map[string]string{"file_path": "", "peers": " "})
	if err != nil || !strings.Contains(emptyPeers, "file_path=None, peers=None") {
		t.Fatalf("unexpected empty substitution: %s, err=%v", emptyPeers, err)
	}

	placeholder, err := guide.WorkflowText("diagnose_capture", nil)
	if err != nil || !strings.Contains(placeholder, "<file_path>") {
		t.Fatalf("expected <file_path> placeholder: %s, err=%v", placeholder, err)
	}

	if _, err := guide.WorkflowText("nope", nil); err == nil {
		t.Fatal("expected error for unknown workflow")
	}
}

func TestPromptAndResourceListsAndRendering(t *testing.T) {
	specs := liveSpecs(t)
	prompts := guide.Prompts()
	if len(prompts) != len(guide.Workflows) {
		t.Fatalf("expected %d prompts, got %d", len(guide.Workflows), len(prompts))
	}
	resources := guide.Resources()
	if len(resources) != len(guide.Topics)+1 {
		t.Fatalf("expected %d resources, got %d", len(guide.Topics)+1, len(resources))
	}

	overview, err := guide.ReadResource("sonic://guide/overview", specs, "sonic", nil)
	if err != nil || !strings.Contains(overview, "name: sonic") {
		t.Fatalf("overview resource error: %v", err)
	}
	for _, top := range guide.Topics {
		body, err := guide.ReadResource("sonic://guide/"+top.Slug, specs, "sonic", nil)
		if err != nil {
			t.Fatalf("topic %s failed: %v", top.Slug, err)
		}
		if strings.ContainsRune(body, '\u2014') {
			t.Fatalf("em-dash in topic %s", top.Slug)
		}
	}
	if _, err := guide.ReadResource("bad://uri", specs, "", nil); err == nil {
		t.Fatal("expected error for invalid URI scheme")
	}
	if _, err := guide.RenderTopic("unknown-topic", specs, "", nil); err == nil {
		t.Fatal("expected error for unknown topic")
	}

	detBody, err := guide.RenderTopic("network-detectors", specs, "sonic", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, det := range netorch.AllDetectors {
		if !strings.Contains(detBody, "`"+det+"`") {
			t.Fatalf("network-detectors.md missing detector %s", det)
		}
	}
	if strings.Contains(detBody, "<computed>") {
		t.Fatal("network-detectors.md contains <computed>")
	}
	for _, code := range []string{
		"IKE_NO_RESPONSE", "CLEARTEXT_BETWEEN_PEERS", "NHRP_REGISTRATION_REFUSED",
		"OSPF_HELLO_INTERVAL_MISMATCH", "BGP_TCP_REFUSED", "EIGRP_K_VALUE_MISMATCH",
		"ICMP_LOSS", "CLEARTEXT_OUTSIDE_ALLOWLIST", "IKE_NAT_T_MISSING",
		"IKE_LIVENESS_UNANSWERED", "ESP_STALE_SPI", "NHRP_RESOLUTION_THRASHING",
		"PHASE3_NO_REDIRECT", "PHASE3_MISSING_<...>", "BGP_MSS_NOT_CLAMPED",
		"OSPF_<...>_STUCK", "CONVERGENCE_NOT_SEEN", "PMTU_BLACK_HOLE",
		"ESP_OUTER_FRAGMENTED", "TCP_ZERO_WINDOW", "TLS_BASELINE_VERSION",
		"QOS_RTP_NOT_EF", "OSPF_AREA_MISMATCH", "IKE_<...>",
	} {
		if !strings.Contains(detBody, "`"+code+"`") {
			t.Fatalf("network-detectors.md missing code %s", code)
		}
	}

	sipBody, _ := guide.RenderTopic("sip-rtp", specs, "sonic", nil)
	if !strings.Contains(sipBody, "`anthropic`") || !strings.Contains(sipBody, "`network_score`") || !strings.Contains(sipBody, "`average_mos`") {
		t.Fatalf("sip-rtp.md missing expected fields/providers: %s", sipBody)
	}

	toolsBody, _ := guide.RenderTopic("mcp-tools", specs, "sonic", nil)
	for _, s := range specs {
		if !strings.Contains(toolsBody, "## `"+s.Name+"`") {
			t.Fatalf("mcp-tools.md missing tool %s", s.Name)
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if json.Unmarshal(s.InputSchema, &schema) == nil {
			for p := range schema.Properties {
				if !strings.Contains(toolsBody, "`"+p+"`") {
					t.Fatalf("mcp-tools.md missing param %s.%s", s.Name, p)
				}
			}
		}
	}
}

func TestSkillWriteRefusalRerunAndStalePruning(t *testing.T) {
	specs := liveSpecs(t)
	tmp := t.TempDir()
	skillDir := filepath.Join(tmp, "sonic")

	// First write creates SKILL.md + 6 reference pages, valid frontmatter, <150 body lines.
	res1, err := guide.CreateSkill(skillDir, specs, "sonic", guide.DefaultCLIFlags())
	if err != nil {
		t.Fatalf("CreateSkill first run: %v", err)
	}
	if len(res1.Written) != 1+len(guide.Topics) {
		t.Fatalf("expected %d written files, got %v", 1+len(guide.Topics), res1.Written)
	}
	rawSkill, err := os.ReadFile(filepath.Join(skillDir, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	reFM := regexp.MustCompile(`(?s)^---\n(.*?)\n---\n(.*)$`)
	parts := reFM.FindStringSubmatch(string(rawSkill))
	if parts == nil || !strings.Contains(parts[1], "name: sonic") || len(strings.Split(parts[2], "\n")) >= 150 {
		t.Fatalf("unexpected SKILL.md frontmatter/length:\n%s", rawSkill)
	}
	for _, top := range guide.Topics {
		rel := filepath.Join("reference", top.Slug+".md")
		if !strings.Contains(parts[2], "(reference/"+top.Slug+".md)") {
			t.Fatalf("SKILL.md missing link to %s", rel)
		}
		full := filepath.Join(skillDir, rel)
		if !guide.WrittenBySonic(full) {
			t.Fatalf("WrittenBySonic false for %s", rel)
		}
		rawRef, err := os.ReadFile(full)
		if err != nil || strings.ContainsRune(string(rawRef), '\u2014') {
			t.Fatalf("invalid reference file %s (err=%v)", rel, err)
		}
	}

	// Second run is a no-op: 0 written, all unchanged.
	res2, err := guide.CreateSkill(skillDir, specs, "sonic", guide.DefaultCLIFlags())
	if err != nil {
		t.Fatalf("CreateSkill second run: %v", err)
	}
	if len(res2.Written) != 0 || len(res2.Unchanged) != len(res1.Written) {
		t.Fatalf("rerun not idempotent: %+v", res2)
	}

	// Stale marked file removed; unmarked user file preserved.
	stale := filepath.Join(skillDir, "reference", "old-topic.md")
	userNotes := filepath.Join(skillDir, "reference", "my-notes.md")
	if err := os.WriteFile(stale, []byte(guide.SkillMarker+"; stale -->\nold\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userNotes, []byte("keep me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res3, err := guide.CreateSkill(skillDir, specs, "sonic", guide.DefaultCLIFlags())
	if err != nil {
		t.Fatalf("CreateSkill prune run: %v", err)
	}
	if len(res3.Removed) != 1 || res3.Removed[0] != "reference/old-topic.md" {
		t.Fatalf("expected old-topic removed, got %+v", res3.Removed)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale marked file should be deleted")
	}
	if _, err := os.Stat(userNotes); err != nil {
		t.Fatal("unmarked user file should be kept")
	}

	// Refuses to overwrite foreign SKILL.md without modifying reference/.
	foreignDir := filepath.Join(tmp, "foreign1")
	if err := os.MkdirAll(foreignDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreignDir, "SKILL.md"), []byte("user skill\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = guide.CreateSkill(foreignDir, specs, "sonic", guide.DefaultCLIFlags())
	var refErr *guide.SkillWriteRefusedError
	if !errors.As(err, &refErr) {
		t.Fatalf("expected SkillWriteRefusedError, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(foreignDir, "reference")); !os.IsNotExist(statErr) {
		t.Fatal("reference/ should not be created after refusal")
	}

	// Refuses to overwrite foreign reference file without touching SKILL.md.
	foreignRef := filepath.Join(tmp, "foreign2")
	if err := os.MkdirAll(filepath.Join(foreignRef, "reference"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreignRef, "reference", "cli.md"), []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := guide.CreateSkillCommand(foreignRef, specs, "sonic", guide.DefaultCLIFlags(), &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "not written by sonic --create-skill") {
		t.Fatalf("expected refusal exit 1, got code=%d err=%s", code, errOut.String())
	}
	if _, statErr := os.Stat(filepath.Join(foreignRef, "SKILL.md")); !os.IsNotExist(statErr) {
		t.Fatal("SKILL.md should not be written when reference file refused")
	}

	// CreateSkillCommand succeeds with clean summary on stdout.
	okDir := filepath.Join(tmp, "ok-cmd")
	out.Reset()
	errOut.Reset()
	if code := guide.CreateSkillCommand(okDir, specs, "sonic", guide.DefaultCLIFlags(), &out, &errOut); code != 0 || !strings.Contains(out.String(), "Skill 'sonic'") {
		t.Fatalf("expected exit 0 summary, got code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
}

func TestExtractCreateSkillFlagVariants(t *testing.T) {
	if guide.DefaultSkillDir() != filepath.Join(".claude", "skills", "sonic") {
		t.Fatalf("unexpected DefaultSkillDir: %s", guide.DefaultSkillDir())
	}
	for _, tc := range []struct {
		args    []string
		wantDir string
		wantEn  bool
		wantRem int
	}{
		{[]string{"--create-skill"}, guide.DefaultSkillDir(), true, 0},
		{[]string{"--create-skill", "/tmp/out", "--json"}, "/tmp/out", true, 1},
		{[]string{"--create-skill=/tmp/eq"}, "/tmp/eq", true, 0},
		{[]string{"--create-skill="}, guide.DefaultSkillDir(), true, 0},
		{[]string{"--create-skill", "--env-file", "/tmp/e"}, guide.DefaultSkillDir(), true, 2},
		{[]string{"--file", "a.pcap", "--", "--create-skill"}, "", false, 4},
	} {
		dir, en, rem := guide.ExtractCreateSkillFlag(tc.args)
		if dir != tc.wantDir || en != tc.wantEn || len(rem) != tc.wantRem {
			t.Fatalf("ExtractCreateSkillFlag(%v) = (%q, %v, %v)", tc.args, dir, en, rem)
		}
	}

	protoDir, protoEn, rem := guide.ExtractOptionalFlag([]string{"--fetch-grpc-protos", "/tmp/p", "--verbose"}, "--fetch-grpc-protos", "/default/p")
	if protoDir != "/tmp/p" || !protoEn || len(rem) != 1 || rem[0] != "--verbose" {
		t.Fatalf("unexpected ExtractOptionalFlag: dir=%q en=%v rem=%v", protoDir, protoEn, rem)
	}
	flags := guide.DefaultCLIFlags()
	seenFlags := make(map[string]bool, len(flags))
	for _, f := range flags {
		seenFlags[f.Flags] = true
	}
	for _, want := range []string{"--model", "--provider", "--model-name", "--quality", "--mos", "--stream", "--partial", "--batch-dir", "--batch-mode", "--batch-workers", "--fetch-grpc-protos", "--verbose"} {
		if !seenFlags[want] {
			t.Fatalf("DefaultCLIFlags missing %s", want)
		}
	}
}

func TestDetectorMetadataMatchesSourceAST(t *testing.T) {
	metas, err := guide.DetectorMeta()
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]guide.PackageMeta, len(metas))
	for _, m := range metas {
		seen[m.Key] = m
		if m.Doc == "" {
			t.Fatalf("empty Doc for %s", m.Key)
		}
	}
	for _, det := range netorch.AllDetectors {
		if _, ok := seen[det]; !ok {
			t.Fatalf("detector_meta.json missing detector %s", det)
		}
	}
	if _, ok := seen["grpc_inspect"]; !ok {
		t.Fatal("detector_meta.json missing grpc_inspect")
	}
	if len(seen["conversations"].Codes) != 0 {
		t.Fatalf("expected 0 codes for conversations, got %v", seen["conversations"].Codes)
	}
}
