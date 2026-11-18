//go:build ignore

// Tool gen_guide_meta parses internal/analyze Go packages with go/ast and writes
// internal/guide/detector_meta.json with live docstrings and MakeIssue codes.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type metaTarget struct {
	Key          string   `json:"key"`
	PackageDir   string   `json:"package_dir"`
	IncludeFiles []string `json:"-"`
	ExcludeFiles []string `json:"-"`
}

type packageMeta struct {
	Key        string   `json:"key"`
	PackageDir string   `json:"package_dir"`
	Doc        string   `json:"doc"`
	Codes      []string `json:"codes"`
}

var targets = []metaTarget{
	{Key: "ipsec", PackageDir: "internal/analyze/ipsec"},
	{Key: "gre_nhrp", PackageDir: "internal/analyze/grenhrp"},
	{Key: "dmvpn_phase3", PackageDir: "internal/analyze/dmvpn"},
	{Key: "routing", PackageDir: "internal/analyze/routing"},
	{Key: "reachability", PackageDir: "internal/analyze/reach", ExcludeFiles: []string{"conversations.go"}},
	{Key: "conversations", PackageDir: "internal/analyze/reach", IncludeFiles: []string{"conversations.go"}},
	{Key: "path_mtu", PackageDir: "internal/analyze/pathmtu"},
	{Key: "esp_overhead", PackageDir: "internal/analyze/espoverhead"},
	{Key: "tcp", PackageDir: "internal/analyze/tcphealth"},
	{Key: "tls", PackageDir: "internal/analyze/tlsinspect"},
	{Key: "qos", PackageDir: "internal/analyze/qos"},
	{Key: "cleartext_audit", PackageDir: "internal/analyze/audit"},
	{Key: "convergence", PackageDir: "internal/analyze/convergence"},
	{Key: "grpc_inspect", PackageDir: "internal/analyze/grpc"},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gen_guide_meta: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	out := make([]packageMeta, 0, len(targets))
	for _, t := range targets {
		parsed, err := inspectTarget(t)
		if err != nil {
			return err
		}
		out = append(out, parsed)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join("internal", "guide", "detector_meta.json"), buf.Bytes(), 0o644)
}

func inspectTarget(t metaTarget) (packageMeta, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, t.PackageDir, func(info os.FileInfo) bool {
		name := info.Name()
		if strings.HasSuffix(name, "_test.go") {
			return false
		}
		if len(t.IncludeFiles) > 0 && !slices.Contains(t.IncludeFiles, name) {
			return false
		}
		if slices.Contains(t.ExcludeFiles, name) {
			return false
		}
		return true
	}, parser.ParseComments)
	if err != nil {
		return packageMeta{}, fmt.Errorf("parse %s: %w", t.PackageDir, err)
	}
	codeSet := make(map[string]bool)
	var chosenDoc, firstDoc string
	pkgBase := filepath.Base(t.PackageDir)
	for _, pkg := range pkgs {
		names := make([]string, 0, len(pkg.Files))
		for name := range pkg.Files {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			file := pkg.Files[name]
			if file.Doc != nil {
				if d := cleanPackageDoc(file.Doc.Text(), pkg.Name); d != "" {
					if firstDoc == "" {
						firstDoc = d
					}
					base := filepath.Base(name)
					if chosenDoc == "" && (base == pkgBase+".go" || base == "detector.go" || base == t.Key+".go") {
						chosenDoc = d
					}
				}
			}
			for _, c := range extractFileIssueCodes(file) {
				codeSet[c] = true
			}
		}
	}
	if chosenDoc == "" {
		chosenDoc = firstDoc
	}
	codes := make([]string, 0, len(codeSet))
	for c := range codeSet {
		codes = append(codes, c)
	}
	slices.Sort(codes)
	return packageMeta{Key: t.Key, PackageDir: t.PackageDir, Doc: chosenDoc, Codes: codes}, nil
}

func cleanPackageDoc(raw, pkgName string) string {
	trimmed := strings.TrimSpace(raw)
	prefix := "Package " + pkgName + " "
	if strings.HasPrefix(trimmed, prefix) {
		rest := strings.TrimSpace(trimmed[len(prefix):])
		if len(rest) > 0 {
			return strings.ToUpper(rest[:1]) + rest[1:]
		}
	}
	return trimmed
}

func extractFileIssueCodes(file *ast.File) []string {
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		codeStrings := collectLocalStringTables(fn.Body)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && (ident.Name == "checkStr" || ident.Name == "checkInt") && len(call.Args) >= 2 {
				if lit, ok := unquoteExpr(call.Args[1]); ok {
					out = append(out, lit)
				}
			}
			if !isMakeIssueCall(call.Fun) || len(call.Args) < 2 {
				return true
			}
			out = append(out, resolveCodeExpr(call.Args[1], codeStrings)...)
			return true
		})
	}
	return out
}

func isMakeIssueCall(fun ast.Expr) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "model" && sel.Sel.Name == "MakeIssue"
}

func unquoteExpr(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

func collectLocalStringTables(body *ast.BlockStmt) map[string][]string {
	tables := make(map[string][]string)
	ast.Inspect(body, func(n ast.Node) bool {
		if node, ok := n.(*ast.AssignStmt); ok && len(node.Lhs) == 1 && len(node.Rhs) == 1 {
			if id, ok := node.Lhs[0].(*ast.Ident); ok {
				if bin, isAdd := node.Rhs[0].(*ast.BinaryExpr); isAdd && bin.Op == token.ADD {
					pat := renderPattern(bin)
					if pat != "" && pat != "<...>" {
						tables[id.Name] = []string{pat}
					}
					return true
				}
				if vals := extractUpperCodeLiterals(node.Rhs[0]); len(vals) > 0 {
					tables[id.Name] = vals
				}
			}
		}
		return true
	})
	return tables
}

func extractUpperCodeLiterals(expr ast.Expr) []string {
	var vals []string
	ast.Inspect(expr, func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if k, ok := kv.Key.(*ast.Ident); ok && strings.EqualFold(k.Name, "code") {
				if s, ok := unquoteExpr(kv.Value); ok {
					vals = append(vals, s)
				}
			}
			return true
		}
		if ex, ok := n.(ast.Expr); ok {
			if s, ok := unquoteExpr(ex); ok && looksLikeIssueCode(s) {
				vals = append(vals, s)
			}
		}
		return true
	})
	return vals
}

func looksLikeIssueCode(s string) bool {
	if len(s) < 3 || !strings.Contains(s, "_") {
		return false
	}
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func resolveCodeExpr(expr ast.Expr, tables map[string][]string) []string {
	if s, ok := unquoteExpr(expr); ok {
		return []string{s}
	}
	if bin, ok := expr.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		joined := renderPattern(bin)
		if joined != "" && joined != "<...>" {
			return []string{joined}
		}
	}
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		if strings.EqualFold(sel.Sel.Name, "code") {
			var collected []string
			for _, vals := range tables {
				collected = append(collected, vals...)
			}
			return collected
		}
	}
	if id, ok := expr.(*ast.Ident); ok {
		if vals := tables[id.Name]; len(vals) > 0 {
			return vals
		}
		return nil
	}
	return nil
}

func renderPattern(expr ast.Expr) string {
	if s, ok := unquoteExpr(expr); ok {
		return s
	}
	if bin, ok := expr.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		return collapsePlaceholders(renderPattern(bin.X) + renderPattern(bin.Y))
	}
	return "<...>"
}

func collapsePlaceholders(s string) string {
	for strings.Contains(s, "<...><...>") {
		s = strings.ReplaceAll(s, "<...><...>", "<...>")
	}
	return s
}
