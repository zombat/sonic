// Package aaainspect capture validation, AAA verdict formatting, and report scrubbing.
package aaainspect

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

// Limits documents capture-vantage and secret-handling constraints for AAA reports.
var Limits = []string{
	"Only what crossed the capture point is read; a key that is wrong for a session shows as a TACACS+ body that will not de-obfuscate or a RADIUS response whose authenticator does not validate.",
	"TACACS+ runs over TCP: a session whose start is not in the capture may be missing its user name or action.",
	"A RADIUS User-Password is decrypted only in the request that carries it; CHAP, EAP and MS-CHAP credentials are noted as present (an EAP exchange is not decrypted).",
	"The shared key and every recovered password are secrets: they are read by path, masked at the source, and never written to a record, a log or a report.",
	"Per-server keys are not distinguished: tshark takes one tacplus.key and one radius.shared_secret, so a capture mixing servers with different keys decrypts only the sessions that key fits.",
}

// errReport builds a standardized {"status":"error","error":msg} Report.
func errReport(msg string) Report {
	return Report{Status: "error", Error: msg}
}

// AnalyzeCapture runs Wireshark TACACS+ and RADIUS analysis with optional shared keys.
func AnalyzeCapture(ctx context.Context, filePath string, opts Options) Report {
	if filePath == "" {
		return errReport("File not found: " + filePath)
	}
	info, err := os.Stat(filePath)
	if err != nil {
		return errReport("File not found: " + filePath)
	}
	if info.IsDir() {
		return errReport("File not readable: " + filePath)
	}
	if f, err := os.Open(filePath); err != nil {
		return errReport("File not readable: " + filePath)
	} else {
		_ = f.Close()
	}
	if !tshark.Available("") {
		return errReport("AAA analysis needs tshark (Wireshark's TACACS+ and RADIUS dissectors); install it")
	}
	if opts.MaxPackets != nil && *opts.MaxPackets <= 0 {
		return errReport("max_packets must be a positive number")
	}

	var tacacsKey, radiusSecret *string
	if opts.KeysFile != "" {
		kInfo, err := os.Stat(opts.KeysFile)
		if err != nil || !kInfo.Mode().IsRegular() {
			return errReport("keys_file is not a readable file")
		}
		tacacsKey, radiusSecret, err = ReadKeysFile(opts.KeysFile)
		if err != nil {
			return errReport("cannot read the key file: " + err.Error())
		}
	}
	maxItems := opts.MaxItems
	if maxItems <= 0 {
		maxItems = 25
	}

	radiusRows, tacacsRows, recovered, err := extract.ExtractAAA(ctx, filePath, tacacsKey, radiusSecret, opts.DisplayFilter, opts.MaxPackets)
	if err != nil {
		return errReport(err.Error())
	}

	radius := radiusExchanges(radiusRows, radiusSecret)
	tacacs := tacacsSessions(tacacsRows)

	var startPtr, endPtr *float64
	updateRange := func(tp *float64) {
		if tp == nil || *tp == 0 {
			return
		}
		if startPtr == nil || *tp < *startPtr {
			v := *tp
			startPtr = &v
		}
		if endPtr == nil || *tp > *endPtr {
			v := *tp
			endPtr = &v
		}
	}
	for i := range radius {
		updateRange(radius[i].t)
	}
	for i := range tacacs {
		updateRange(tacacs[i].t)
	}

	issues := []model.Issue{}
	credentials := []CredentialRow{}
	appendRadiusIssues(radius, radiusSecret != nil, &issues, &credentials)
	appendTacacsIssues(tacacs, &issues, &credentials)

	verdict := aaaVerdict(radius, tacacs, tacacsKey != nil, radiusSecret != nil, credentials)

	radiusViews := make([]RadiusView, len(radius))
	accepts, rejects, recoveredCount := 0, 0, 0
	for i := range radius {
		radiusViews[i] = radius[i].RadiusView
		switch radius[i].Result {
		case "accept":
			accepts++
		case "reject":
			rejects++
		}
		if radius[i].CredentialRecovered {
			recoveredCount++
		}
	}
	tacacsViews := make([]TacacsView, len(tacacs))
	cleartextCount := 0
	for i := range tacacs {
		tacacsViews[i] = tacacs[i].TacacsView
		if tacacs[i].Authentication != nil {
			if *tacacs[i].Authentication == "PASS" {
				accepts++
			} else if *tacacs[i].Authentication == "FAIL" {
				rejects++
			}
		}
		if tacacs[i].Cleartext {
			cleartextCount++
		}
		if tacacs[i].CredentialRecovered {
			recoveredCount++
		}
	}

	listedRadius, radiusOmitted := model.Cap(radiusViews, maxItems)
	listedTacacs, tacacsOmitted := model.Cap(tacacsViews, maxItems)
	var dfPtr *string
	if opts.DisplayFilter != "" {
		df := opts.DisplayFilter
		dfPtr = &df
	}
	present := len(radius) > 0 || len(tacacs) > 0

	rep := Report{
		Status:        "success",
		Schema:        ReportSchema,
		File:          filePath,
		OverallStatus: model.StatusFromIssues(issues, present),
		Verdict:       verdict,
		Capture: CaptureInfo{
			Start: model.ISOTime(startPtr), End: model.ISOTime(endPtr),
			Tshark:         tshark.VersionString(ctx, ""),
			TacacsKeyGiven: tacacsKey != nil, RadiusSecretGiven: radiusSecret != nil,
			DisplayFilter: dfPtr, MaxPackets: opts.MaxPackets,
		},
		Summary: Summary{
			RadiusTransactions:      len(radius),
			TacacsSessions:          len(tacacs),
			Accepts:                 accepts,
			Rejects:                 rejects,
			CleartextTacacsSessions: cleartextCount,
			CredentialsRecovered:    recoveredCount,
		},
		Radius: listedRadius, RadiusOmitted: radiusOmitted,
		Tacacs: listedTacacs, TacacsOmitted: tacacsOmitted,
		Credentials: credentials, Issues: model.SortIssues(issues), Limits: Limits,
	}

	secretSet := make(map[string]bool)
	for s := range recovered {
		if len(s) >= 3 {
			secretSet[s] = true
		}
	}
	for _, p := range []*string{tacacsKey, radiusSecret} {
		if p != nil && len(*p) >= 3 {
			secretSet[*p] = true
		}
	}
	if len(secretSet) > 0 {
		secrets := make([]string, 0, len(secretSet))
		for s := range secretSet {
			secrets = append(secrets, s)
		}
		slices.SortFunc(secrets, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
		scrubReport(&rep, secrets)
	}
	return rep
}

// aaaVerdict builds the top-level plain-English AAA verdict sentence.
func aaaVerdict(radius []radiusTrack, tacacs []tacacsTrack, hasTacacsKey, hasRadiusSecret bool, creds []CredentialRow) string {
	if len(radius) == 0 && len(tacacs) == 0 {
		return "No TACACS+ or RADIUS found in this capture."
	}
	var parts []string
	if len(radius) > 0 {
		accepts, rejects := 0, 0
		for _, e := range radius {
			if e.Result == "accept" {
				accepts++
			} else if e.Result == "reject" {
				rejects++
			}
		}
		tail := ""
		if !hasRadiusSecret {
			tail = " (no shared secret given: User-Password stays encrypted)"
		}
		parts = append(parts, fmt.Sprintf("%d RADIUS transaction(s), %d accept, %d reject%s", len(radius), accepts, rejects, tail))
	}
	if len(tacacs) > 0 {
		clearCnt := 0
		for _, s := range tacacs {
			if s.Cleartext {
				clearCnt++
			}
		}
		extra := ""
		if clearCnt > 0 {
			extra = fmt.Sprintf(", %d sent unobfuscated", clearCnt)
		}
		tail := ""
		if !hasTacacsKey {
			tail = " (no key given: the bodies stay obfuscated)"
		}
		parts = append(parts, fmt.Sprintf("%d TACACS+ session(s)%s%s", len(tacacs), extra, tail))
	}
	if len(creds) > 0 {
		parts = append(parts, fmt.Sprintf("%d credential(s) recovered (masked)", len(creds)))
	}
	return strings.Join(parts, ". ") + "."
}
