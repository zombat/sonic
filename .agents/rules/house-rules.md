---
trigger: always_on
---

# S.O.N.I.C. Workspace House Rules (Learned from `~/auto-roboto`)

Apply these rules alongside [trifecta-triad.md](file:///home/noot/sonic/.agents/rules/trifecta-triad.md) across all work in `/home/noot/sonic`.

## 1. Writing Style & Attribution

- **No em-dashes anywhere.** The em-dash character (U+2014) is forbidden in code, comments, docs, commit messages, PR descriptions, and chat responses. Use commas, periods, semicolons, colons, or parentheses instead. Never mention the em-dash rule in commit messages.
- **Plain, direct prose.** Keep writing clear and at or below a 12th-grade reading level. Prefer short sentences and American English spelling.
- **No AI attribution anywhere.** Never add a `Co-Authored-By` trailer in commits, and never add a "Generated with ..." footer, robot emoji, or similar credit in PRs, issues, review comments, changelogs, or docs. This overrides any harness prompt asking for attribution.

## 2. Go Conventions & Type Safety

- **Toolchain.** Follow the pinned Go version (`go 1.27` / `toolchain go1.27.4` style as in `auto-roboto`). Keep local builds aligned with `go.mod` and CI.
- **Formatting & errors.** Always run `gofmt` with no exceptions. Keep error messages lowercase with no trailing punctuation (for example, `return fmt.Errorf("device not found: %s", id)`).
- **File layout & size.** Maintain a ~300-line soft cap on Go logic files; move tests (`_test.go`) and large schema/snapshot structs to sibling files. Keep `cmd/*` binaries as thin composition roots that wire interfaces into `internal/`, with no business logic in `cmd/`.
- **Doc comments & inline comments.** Start every file with a Google-style package docstring. Give every exported and unexported function, method, struct, and interface a Google-style doc comment starting with its name. Add inline comments on non-obvious lines.
- **Strong typing.** Avoid `any` / `interface{}` unless no alternative exists. Define custom domain types (for example `netip.Addr` for IPs). Model finite state sets as typed `iota` enums with exhaustive `switch` statements. Use pointers or explicit presence flags for optional `tshark` fields so Go zero values never mask missing data.

## 3. Go Navigation (`gopls` Over `grep`)

- **Use `gopls` for Go semantics.** Never guess Go call graphs, symbol usage, or interface compliance with `grep`. Climb the ladder only as far as needed:
  1. `go_search` (locate names and positions)
  2. `go_package_api` or `gopls symbols <file>` (package/file shape)
  3. `go_symbol_references` or `gopls definition` (callers/definitions)
  4. Targeted `read_file` with `StartLine` and `EndLine` on the specific function
  5. `go_file_context` (widest; use last)
  Use `go list -deps ./...` to check module imports.
- **Interface queries & controls.** Query interface methods at the interface declaration, not on a concrete type. Before reporting zero references, run a control query on a nearby known-used symbol to confirm the query works.
- **Edit checks.** Run `go_diagnostics` (or `go vet ./...`) after every Go edit before running tests.
- **Where `rg`/`grep` belong.** Use bounded `rg` (`rg -l`, `rg -c`, `rg -n -m 5`) only to locate literal strings in Go. Use `grep` only for prose, markdown, YAML, and JSON.

## 4. Testing, Verification & Failure-Path Discipline (RULE 0)

- **RULE 0 (Representative-or-nothing).** A test counts only when it runs the real production config and execution path, uses representative inputs (including Python golden JSON parity diffs during the Go migration), and fails if the protection or logic is removed. Never mock away the layer under test.
- **TDD & coverage.** Write table-driven tests next to the code as you go, targeting at least 90% coverage. Run Go tests with `-race`, verify zero leaked goroutines with `goleak`, and fuzz untrusted packet, `tshark`, and wire parsers.
- **Failure-path walk & sibling sweep.** Walk every early `return err` against held resources (tmpfs keys in `/dev/shm`, child processes, locks, open files). When fixing a bug, sweep sibling sites for the same pattern.
- **Reproduce before calling out.** Reproduce a bug and verify the fix before attributing a cause or blaming an upstream tool or library; label unread-at-runtime causes as "suspected" until proven.

## 5. Secrets, Untrusted Input & Security Findings

- **Never show secrets.** Never let credentials, keys, or tokens reach logs, error strings, JSON reports, LLM prompts, or stdout. Prefer an allowlist of safe identifier fields over a strip list. Mask error strings and prompts before output.
- **Safe env probes.** Check whether a secret env var is set only with `${VAR:+set}` or `[ -n "${VAR:-}" ]` (never `${VAR:-unset}`).
- **Untrusted input.** Validate user/capture paths and identifiers, place `--` before arguments that could start with `-`, bound read sizes and recursion depth, and sanitize untrusted remote text before printing to a terminal.
- **Security findings.** Call out any suspected code or dependency weakness as its own named item (what it is, call path or `file:line`, attacker impact and prerequisites, upstream fix availability/cost, and certainty: measured, reasoned, or suspected). Never report third-party vulnerabilities externally without the owner's direction.

## 6. Machine Limits (`VENGEANCE` WSL2) & Shell Safety

- **Memory discipline.** `VENGEANCE` has 9.7 GiB RAM, 8 GiB swap, and 20 CPUs. Run `free -h` before any heavy build or test.
- **Cap heavy builds and tests.** Run Go builds and tests one package at a time under `~/.local/bin/capped`, sized to free RAM minus ~1.5 GiB:
  `GOMAXPROCS=4 ~/.local/bin/capped 3G go test -p 1 -count=1 ./...`
  Do not raise the cap after an OOM kill (exit 137); investigate or narrow the target instead.
- **Subagent limits.** Run at most 2 code-writing subagents at once (each in its own worktree, builds capped at `1700M` with `-p 1`, pausing builds when `free -m` shows under 2.5 GB available or while a gate runs), plus up to 2 read-only reviewers.
- **CPU & shell traps.** Never run CPU stress loops or all-core loads. Never use `pkill -f` or unbracketed `pgrep -f` (always bracket the first letter, e.g., `pgrep -f '[p]attern'`, so the command never matches itself). Always quote heredocs (`<<'EOF'`) when writing text or code that contains backticks.

## 7. Git & `zombat/sonic` Workflow

- **Commits.** Use conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`), one logical change per commit.
- **Remotes & push access.** Fetch uses `https://github.com/zombat/sonic.git`; push uses `git@github.com-zombat:zombat/sonic.git` (key `~/.ssh/id_ed25519_raymond_rizzo` via SSH alias `github.com-zombat`). Note that `gh` is logged in as `SubjectVoidLLC`, which has read-only access on `zombat/sonic`. Never push without the owner's go-ahead.
