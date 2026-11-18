// Package sip extracts DTMF, function-key, special-key, NOTIFY, and Request-URI
// digit events for SIP overlap dialing analysis.
package sip

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var (
	dtmfSignalRe    = regexp.MustCompile(`(?i)Signal\s*=\s*([0-9*#ABCD])`)
	funcKeyRe       = regexp.MustCompile(`(?i)(?:Signal|Key|Event)\s*=\s*(F[0-9]{1,2})`)
	notifyDigitRe   = regexp.MustCompile(`(?i)digitkey["\s]*[:=]\s*([0-9*#ABCD])`)
	inviteDigitRe   = regexp.MustCompile(`INVITE\s+sip:([0-9*#+]+)@`)
	overlapSpecials = []string{
		"HOLD", "TRANSFER", "CONFERENCE", "MUTE", "SPEAKER", "HEADSET",
		"VOLUME_UP", "VOLUME_DOWN", "REDIAL", "FLASH", "HOOK", "SOFTKEY",
	}
)

// ExtractDigitKeysFromSIPData scans SIP JSON or raw text for DTMF, function, and URI digits.
func ExtractDigitKeysFromSIPData(sipData string) DigitKeysResult {
	var events []DigitEvent
	setup := "en-bloc"
	overlap := false

	var texts []string
	var callIDs []string
	var parsed struct {
		SIPPackets []json.RawMessage `json:"sip_packets"`
	}
	if json.Unmarshal([]byte(sipData), &parsed) == nil && len(parsed.SIPPackets) > 0 {
		for _, raw := range parsed.SIPPackets {
			var p struct {
				CallID     string `json:"call_id"`
				PacketData string `json:"packet_data"`
			}
			_ = json.Unmarshal(raw, &p)
			if p.PacketData != "" {
				texts = append(texts, p.PacketData)
			} else {
				texts = append(texts, string(raw))
			}
			callIDs = append(callIDs, p.CallID)
		}
	} else if sipData != "" {
		texts = append(texts, sipData)
		callIDs = append(callIDs, "")
	}

	for idx, pktStr := range texts {
		cid := callIDs[idx]
		for _, m := range dtmfSignalRe.FindAllStringSubmatch(pktStr, -1) {
			events = append(events, DigitEvent{CallID: cid, Digit: m[1], Packet: idx, Pattern: "info_dtmf", KeyType: "dtmf"})
			setup, overlap = "overlap", true
		}
		for _, m := range funcKeyRe.FindAllStringSubmatch(pktStr, -1) {
			events = append(events, DigitEvent{CallID: cid, Digit: strings.ToUpper(m[1]), Packet: idx, Pattern: "info_function", KeyType: "function"})
			overlap = true
		}
		low := strings.ToLower(pktStr)
		for _, sk := range overlapSpecials {
			if strings.Contains(low, strings.ToLower(sk)) {
				events = append(events, DigitEvent{CallID: cid, Digit: sk, Packet: idx, Pattern: "info_special", KeyType: "special"})
				overlap = true
			}
		}
		if strings.Contains(strings.ToUpper(pktStr), "NOTIFY") {
			for _, m := range notifyDigitRe.FindAllStringSubmatch(pktStr, -1) {
				events = append(events, DigitEvent{CallID: cid, Digit: m[1], Packet: idx, Pattern: "notify_digit", KeyType: "dtmf", Legacy: true})
				setup, overlap = "overlap", true
			}
		}
		for _, m := range inviteDigitRe.FindAllStringSubmatch(pktStr, -1) {
			events = append(events, DigitEvent{CallID: cid, DigitSequence: m[1], Packet: idx, Pattern: "progressive_digits", KeyType: "uri_digits"})
		}
	}

	if len(events) > 1 {
		setup, overlap = "overlap", true
	} else {
		for _, e := range events {
			if e.Pattern == "progressive_digits" {
				setup, overlap = "overlap", true
				break
			}
		}
	}
	if events == nil {
		events = []DigitEvent{}
	}
	return DigitKeysResult{
		OverlapDialingDetected: overlap,
		DigitEvents:            events,
		CallSetupMethod:        setup,
		TotalEvents:            len(events),
	}
}

func evalOverlapPatterns(d *CallOverlapDetail) {
	if len(d.DigitProgression) >= 2 {
		nums := make([]string, len(d.DigitProgression))
		for i, e := range d.DigitProgression {
			nums[i] = e.Number
		}
		lengthening := true
		for i := 1; i < len(nums); i++ {
			if !(len(nums[i]) > len(nums[i-1]) && strings.HasPrefix(nums[i], nums[i-1])) {
				lengthening = false
				break
			}
		}
		if lengthening {
			d.OverlapDetected = true
			setPattern(&d.PatternType, "progressive_digits")
			d.Evidence = append(d.Evidence, "Progressive digit addition: "+strings.Join(nums, " → "))
		}
		if d.ReinviteCount > 0 {
			uniq := make(map[string]bool)
			var uniqList []string
			for _, n := range nums {
				if !uniq[n] {
					uniq[n] = true
					uniqList = append(uniqList, n)
				}
			}
			if len(uniqList) > 1 {
				d.OverlapDetected = true
				setPattern(&d.PatternType, "reinvite_based")
				d.Evidence = append(d.Evidence, fmt.Sprintf("Multiple numbers via re-INVITE: %q", uniqList))
			}
		}
	}
	if len(d.DigitProgression) >= 2 && d.InfoCount > 0 {
		d.OverlapDetected = true
		setPattern(&d.PatternType, "info_based")
		d.Evidence = append(d.Evidence, fmt.Sprintf("INFO messages for additional digits: %d messages", d.InfoCount))
	}
	if len(d.DigitProgression) >= 2 && d.NotifyCount > 0 {
		d.OverlapDetected = true
		setPattern(&d.PatternType, "notify_based")
		d.Evidence = append(d.Evidence, fmt.Sprintf("NOTIFY messages for digit events: %d messages", d.NotifyCount))
	}
	for _, e := range d.DigitProgression {
		low := strings.ToLower(e.Number)
		if strings.Contains(low, "overlap") || strings.Contains(low, "digit") || strings.Contains(low, "collection") {
			d.OverlapDetected = true
			setPattern(&d.PatternType, "uri_based")
			d.Evidence = append(d.Evidence, "Overlap indicator in URI: "+e.Number)
		}
	}
}

func applyCallDigits(d *CallOverlapDetail, callDigits []DigitEvent) {
	d.CollectedDigits = callDigits
	var seq strings.Builder
	dtmfN, funcN, specN := 0, 0, 0
	for _, ev := range callDigits {
		kt := defaultStr(ev.KeyType, "dtmf")
		switch kt {
		case "dtmf":
			dtmfN++
			seq.WriteString(ev.Digit)
		case "function":
			funcN++
		case "special":
			specN++
		}
	}
	d.DigitSequence = seq.String()
	if !d.OverlapDetected {
		d.OverlapDetected = true
		pat := defaultStr(callDigits[0].Pattern, "unknown") + "_extracted"
		d.PatternType = &pat
	}
	var parts []string
	if dtmfN > 0 {
		parts = append(parts, fmt.Sprintf("%d DTMF", dtmfN))
	}
	if funcN > 0 {
		parts = append(parts, fmt.Sprintf("%d function", funcN))
	}
	if specN > 0 {
		parts = append(parts, fmt.Sprintf("%d special", specN))
	}
	summary := fmt.Sprintf("%d keys", len(callDigits))
	if len(parts) > 0 {
		summary = strings.Join(parts, " + ") + " keys"
	}
	if d.DigitSequence != "" {
		d.Evidence = append(d.Evidence, fmt.Sprintf("Dialed number: %s (%s)", d.DigitSequence, summary))
	} else {
		d.Evidence = append(d.Evidence, fmt.Sprintf("Keypresses detected: %s", summary))
	}
}

func setPattern(dst **string, val string) {
	if *dst == nil {
		v := val
		*dst = &v
	}
}
