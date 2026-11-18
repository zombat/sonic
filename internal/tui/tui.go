// Package tui implements a zero-dependency interactive ANSI terminal viewer
// for browsing S.O.N.I.C. verdicts, issues, timelines, and redacted JSON reports.
package tui

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/zombat/sonic/internal/report"
)

const totalTabs = 5

type viewState struct {
	digest report.ReportDigest
	tab    int
	scroll int
	filter string
	query  bool
}

// Run launches the interactive ANSI terminal viewer over in and out.
func Run(digest report.ReportDigest, in io.Reader, out io.Writer) error {
	restore := enableRawInput(in)
	defer restore()

	st := &viewState{digest: digest, tab: 0}
	if err := st.render(out); err != nil {
		return err
	}

	var buf [64]byte
	for {
		n, err := in.Read(buf[:])
		if n > 0 {
			quit := false
			for _, tok := range parseInputTokens(buf[:n]) {
				if st.handleToken(tok) {
					quit = true
					break
				}
			}
			if quit {
				_, _ = io.WriteString(out, "\r\n")
				return nil
			}
			if rerr := st.render(out); rerr != nil {
				return rerr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (st *viewState) handleToken(tok string) bool {
	if st.query {
		switch tok {
		case "\r", "\n", "ESC":
			st.query = false
			st.scroll = 0
		case "\x7f", "\b":
			if len(st.filter) > 0 {
				st.filter = st.filter[:len(st.filter)-1]
			}
		default:
			if len(tok) == 1 && tok[0] >= 32 && tok[0] < 127 {
				st.filter += tok
			}
		}
		return false
	}

	switch tok {
	case "q", "Q", "\x03":
		return true
	case "1", "2", "3", "4", "5":
		st.tab = int(tok[0]-'1') % totalTabs
		st.scroll = 0
	case "j", "DOWN":
		st.scroll++
	case "k", "UP":
		if st.scroll > 0 {
			st.scroll--
		}
	case "n", " ":
		st.scroll += 10
	case "p":
		st.scroll = max(st.scroll-10, 0)
	case "/":
		st.query = true
		st.filter = ""
	case "c":
		st.filter = ""
		st.scroll = 0
	}
	return false
}

func (st *viewState) activeLines() []string {
	d := st.digest
	var lines []string
	switch st.tab {
	case 0:
		lines = append(lines,
			fmt.Sprintf("Title:     %s", d.Title),
			fmt.Sprintf("File:      %s", d.File),
			fmt.Sprintf("Status:    %s (overall: %s)", d.Status, d.OverallStatus),
			fmt.Sprintf("Protocols: %s", strings.Join(d.Protocols, ", ")),
			fmt.Sprintf("Verdict:   %s", d.Verdict),
			"",
			"--- Section & Rule Verdicts ---",
		)
		for _, vr := range d.Verdicts {
			lines = append(lines, fmt.Sprintf("[%-18s] %s", vr.Name, vr.Text))
		}
		if len(d.Highlights) > 0 {
			lines = append(lines, "", "--- Highlights ---")
			for _, h := range d.Highlights {
				lines = append(lines, " * "+h)
			}
		}
	case 1:
		for _, iss := range d.Issues {
			lines = append(lines, fmt.Sprintf("[%-7s] %-14s %-28s %s (frames %s)",
				strings.ToUpper(iss.Severity), iss.Detector, iss.Code, iss.Message, report.FormatInts(iss.Frames)))
		}
		if len(lines) == 0 {
			lines = append(lines, "No issues reported.")
		}
	case 2:
		for _, ev := range d.Timeline {
			lines = append(lines, fmt.Sprintf("%10s  %-8s  %-22s  %s",
				string(ev.T), ev.Protocol, ev.Event, ev.Detail))
		}
		if len(lines) == 0 {
			lines = append(lines, "No timeline events recorded.")
		}
	case 3:
		for _, h := range d.Highlights {
			lines = append(lines, " * "+h)
		}
		for _, vr := range d.Verdicts {
			lines = append(lines, fmt.Sprintf("[%-18s] %s", vr.Name, vr.Text))
		}
		if len(lines) == 0 {
			lines = append(lines, "No VoIP/policy highlights available for this report.")
		}
	case 4:
		if d.Audit != nil {
			lines = append(lines, fmt.Sprintf("Redaction Audit: total=%d known=%d auth=%d pem=%d jwt=%d tokens=%d bearer=%d basic=%d assign=%d sdp=%d",
				d.Audit.Total, d.Audit.KnownSecrets, d.Audit.AuthHeaders, d.Audit.PEMBlocks,
				d.Audit.JWTs, d.Audit.ProviderTokens, d.Audit.BearerTokens, d.Audit.BasicAuth,
				d.Audit.Assignments, d.Audit.SDPKeys), "")
		}
		lines = append(lines, strings.Split(d.PrettyJSON, "\n")...)
	}

	if st.filter != "" {
		q := strings.ToLower(st.filter)
		filtered := make([]string, 0, len(lines))
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), q) {
				filtered = append(filtered, line)
			}
		}
		if len(filtered) == 0 {
			return []string{fmt.Sprintf("(no rows match filter %q; press 'c' to clear)", st.filter)}
		}
		return filtered
	}
	return lines
}

func (st *viewState) render(out io.Writer) error {
	lines := st.activeLines()
	maxScroll := max(len(lines)-18, 0)
	if st.scroll > maxScroll {
		st.scroll = maxScroll
	}
	end := min(st.scroll+18, len(lines))
	visible := lines[st.scroll:end]

	tabNames := []string{"1:Overview", "2:Issues", "3:Ladder", "4:Highlights", "5:JSON/Audit"}
	var headerTabs strings.Builder
	for i, name := range tabNames {
		if i == st.tab {
			fmt.Fprintf(&headerTabs, "\x1b[7m %s \x1b[0m ", name)
		} else {
			fmt.Fprintf(&headerTabs, " %s  ", name)
		}
	}

	var sb strings.Builder
	sb.WriteString("\x1b[2J\x1b[H")
	writeTermLine(&sb, "S.O.N.I.C. TUI | "+st.digest.Title)
	sb.WriteString(headerTabs.String())
	sb.WriteByte('\r')
	sb.WriteByte('\n')
	writeTermLine(&sb, strings.Repeat("-", 78))
	for _, line := range visible {
		writeTermLine(&sb, line)
	}
	writeTermLine(&sb, strings.Repeat("-", 78))
	if st.query {
		writeTermLine(&sb, fmt.Sprintf("Filter: /%s_  (Enter apply, Esc cancel)", st.filter))
	} else {
		writeTermLine(&sb, fmt.Sprintf("Keys: [1-5] tabs  [j/k/arrows] scroll  [n/p] page  [/] filter (%q)  [c] clear  [q] quit  (lines %d-%d/%d)",
			st.filter, st.scroll+1, end, len(lines)))
	}
	_, err := io.WriteString(out, sb.String())
	return err
}

func writeTermLine(sb *strings.Builder, line string) {
	sb.WriteString(SanitizeTerminalText(line))
	sb.WriteByte('\r')
	sb.WriteByte('\n')
}

func parseInputTokens(raw []byte) []string {
	var tokens []string
	for i := 0; i < len(raw); i++ {
		if raw[i] == 0x1b {
			if i+2 < len(raw) && raw[i+1] == '[' {
				switch raw[i+2] {
				case 'A':
					tokens = append(tokens, "UP")
					i += 2
					continue
				case 'B':
					tokens = append(tokens, "DOWN")
					i += 2
					continue
				}
			}
			tokens = append(tokens, "ESC")
			continue
		}
		tokens = append(tokens, string(raw[i:i+1]))
	}
	return slices.Clip(tokens)
}
