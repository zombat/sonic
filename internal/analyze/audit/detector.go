// Package audit implements the CleartextAuditDetector frame ingestion
// and TCP session routing.
package audit

import (
	"encoding/hex"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

const maxSessions = 100000

var sshPorts = map[int]bool{22: true, 830: true}

type sessionKey struct {
	a endpointAddr
	b endpointAddr
}

func makeSessionKey(a, b endpointAddr) sessionKey {
	if a.ip < b.ip || (a.ip == b.ip && a.port <= b.port) {
		return sessionKey{a: a, b: b}
	}
	return sessionKey{a: b, b: a}
}

type datagramKey struct {
	src string
	dst string
	id  int
}

type violationKey struct {
	protocol string
	hasAddr  bool
	src      string
	dst      string
}

type violationAgg struct {
	protocol   string
	category   string
	hasAddr    bool
	src        string
	dst        string
	packets    int
	bytes      int
	firstFrame int
	firstT     float64
	lastFrame  int
	lastT      float64
	frames     []int
	protection map[string]int
	reasons    []string
}

// Detector audits every frame in a capture against a compiled allowlist.
type Detector struct {
	allowText        []string
	rules            []Rule
	frames           int
	allowed          int
	allowedBy        map[string]int
	violations       map[violationKey]*violationAgg
	violationOrder   []violationKey
	allowedDatagrams map[datagramKey]string
	sessions         map[sessionKey]*tcpSession
	sessionOrder     []sessionKey
	protection       map[string]int
	sessionsDropped  int
}

// NewDetector validates allow (defaulting to ["encrypted"]) and returns an initialized Detector.
func NewDetector(allow []string) (*Detector, error) {
	texts, rules, err := ParseAllowlist(allow)
	if err != nil {
		return nil, err
	}
	return &Detector{
		allowText:        texts,
		rules:            rules,
		allowedBy:        make(map[string]int),
		violations:       make(map[violationKey]*violationAgg),
		allowedDatagrams: make(map[datagramKey]string),
		sessions:         make(map[sessionKey]*tcpSession),
		protection:       make(map[string]int),
	}, nil
}

func (d *Detector) protect(cls string, count int) {
	d.protection[cls] += count
}

func (d *Detector) routeTCP(rec *model.Record) bool {
	if rec.IP == nil || rec.TCP == nil || rec.GRE != nil || model.IsFragment(rec) {
		return false
	}
	if rec.TCP.Sport == nil || rec.TCP.Dport == nil {
		return false
	}
	src := endpointAddr{ip: rec.IP.Src, port: *rec.TCP.Sport}
	dst := endpointAddr{ip: rec.IP.Dst, port: *rec.TCP.Dport}
	key := makeSessionKey(src, dst)
	sess, ok := d.sessions[key]
	if !ok {
		if len(d.sessions) >= maxSessions {
			d.sessionsDropped++
			return false
		}
		sess = newTCPSession(sshPorts[src.port] || sshPorts[dst.port])
		d.sessions[key] = sess
		d.sessionOrder = append(d.sessionOrder, key)
	}

	flags := rec.TCP.Flags
	if (flags&0x02) != 0 && (flags&0x10) == 0 {
		sess.hasServer = true
		sess.server, sess.client = dst, src
	} else if (flags&0x02) != 0 && (flags&0x10) != 0 && !sess.hasServer {
		sess.hasServer = true
		sess.server, sess.client = src, dst
	}

	var payload []byte
	if rec.DP != nil && rec.DP.PL != "" {
		if b, err := hex.DecodeString(rec.DP.PL); err == nil {
			payload = b
		}
	}
	hasSeq := rec.DP != nil && rec.DP.TCP != nil
	cls := "pending"
	if len(payload) > 0 && hasSeq {
		seq := rec.DP.TCP.Seq
		if sess.kind == "" {
			switch {
			case len(payload) >= 4 && string(payload[:4]) == "SSH-":
				sess.kind = "ssh"
			case len(payload) >= len(http2Preface) && string(payload[:len(http2Preface)]) == string(http2Preface):
				sess.kind = "http2"
				if !sess.hasServer {
					sess.hasServer = true
					sess.server, sess.client = dst, src
				}
			case isTLSRecord(payload) && payload[0] == 22:
				sess.kind = "tls"
				if !sess.hasServer && len(payload) > 5 && payload[5] == 1 {
					sess.hasServer = true
					sess.server, sess.client = dst, src
				}
			case tlsMidstream(payload):
				sess.kind = "tls"
				sess.midstream = true
			default:
				sess.sample(payload)
				sess.spoke[src] = true
				if len(sess.spoke) == 2 {
					sess.kind = "other"
				}
			}
		} else if sess.kind == "other" {
			sess.sample(payload)
		}

		dir := sess.dirs[src]
		if dir == nil && (sess.kind == "ssh" || sess.kind == "tls") {
			dir = newDirection(seq, sess.kind == "tls" && !sess.midstream)
			sess.dirs[src] = dir
		}
		rel := 0
		if dir != nil {
			rel = int(model.SeqDelta(seq, dir.base))
		}
		segLen := rec.TCP.Len
		switch sess.kind {
		case "ssh":
			cls = dir.sshClassify(rel, payload, rec.N)
		case "tls":
			cls = dir.tlsClassify(rel, payload, segLen)
			dir.readHello(rel, payload, len(payload) >= segLen, rec.N)
		case "http2":
			cls = "cleartext"
		}
	} else if sess.kind == "ssh" || sess.kind == "tls" {
		dir := sess.dirs[src]
		if dir != nil && (dir.hasKeXEnd || (dir.hasLastType && dir.lastType == 23)) {
			cls = "encrypted"
		}
	} else if sess.kind == "http2" || sess.kind == "other" {
		cls = "cleartext"
	}

	sess.add(src, cls, rec)
	return true
}

// Feed consumes one normalized record into either TCP session tracking or the per-frame allowlist path.
func (d *Detector) Feed(rec *model.Record) {
	d.frames++
	if d.routeTCP(rec) {
		return
	}
	tokens, name, category := TokensFor(rec)
	prot := ProtectionOf(rec, category)
	d.protect(prot, 1)

	var hasAddr bool
	var src, dst string
	if rec.IP != nil {
		hasAddr = true
		src, dst = rec.IP.Src, rec.IP.Dst
	} else if rec.ARP != nil && rec.ARP.SPA != nil && rec.ARP.TPA != nil {
		hasAddr = true
		src, dst = *rec.ARP.SPA, *rec.ARP.TPA
	}

	var dg datagramKey
	hasDG := false
	if rec.IP != nil && rec.DP != nil && rec.DP.ID != nil {
		hasDG = true
		dg = datagramKey{src: src, dst: dst, id: *rec.DP.ID}
	}
	if hasDG && rec.DP.Off > 0 {
		if ruleText, ok := d.allowedDatagrams[dg]; ok {
			d.allowed++
			d.allowedBy[ruleText]++
			return
		}
	}

	var addrs []string
	if hasAddr {
		addrs = []string{src, dst}
	}
	for _, rule := range d.rules {
		if rule.Matches(tokens, addrs) {
			d.allowed++
			d.allowedBy[rule.Text]++
			if hasDG && rec.DP.MF != nil && *rec.DP.MF != 0 && rec.DP.Off == 0 && len(d.allowedDatagrams) < 65536 {
				d.allowedDatagrams[dg] = rule.Text
			}
			return
		}
	}

	d.violate(name, category, hasAddr, src, dst, &frameBucket{
		packets: 1, bytes: rec.Len, firstFrame: rec.N, firstT: rec.T,
		lastFrame: rec.N, lastT: rec.T, frames: []int{rec.N},
	}, prot, "")
}

func (d *Detector) violate(name, category string, hasAddr bool, src, dst string, bucket *frameBucket, protection, reason string) {
	key := violationKey{protocol: name, hasAddr: hasAddr, src: src, dst: dst}
	entry, ok := d.violations[key]
	if !ok {
		entry = &violationAgg{
			protocol:   name,
			category:   category,
			hasAddr:    hasAddr,
			src:        src,
			dst:        dst,
			firstFrame: bucket.firstFrame,
			firstT:     bucket.firstT,
			lastFrame:  bucket.lastFrame,
			lastT:      bucket.lastT,
			protection: make(map[string]int),
		}
		d.violations[key] = entry
		d.violationOrder = append(d.violationOrder, key)
	}
	if reason != "" && category == "unencrypted_session" && !slices.Contains(entry.reasons, reason) && len(entry.reasons) < 3 {
		entry.reasons = append(entry.reasons, reason)
	}
	entry.packets += bucket.packets
	entry.bytes += bucket.bytes
	if bucket.firstFrame < entry.firstFrame {
		entry.firstFrame, entry.firstT = bucket.firstFrame, bucket.firstT
	}
	if bucket.lastFrame >= entry.lastFrame {
		entry.lastFrame, entry.lastT = bucket.lastFrame, bucket.lastT
	}
	frameSet := make(map[int]bool, len(entry.frames)+len(bucket.frames))
	for _, f := range entry.frames {
		frameSet[f] = true
	}
	for _, f := range bucket.frames {
		frameSet[f] = true
	}
	merged := make([]int, 0, len(frameSet))
	for f := range frameSet {
		merged = append(merged, f)
	}
	slices.Sort(merged)
	if len(merged) > model.MaxFrames {
		merged = merged[:model.MaxFrames]
	}
	entry.frames = merged
	entry.protection[protection] += bucket.packets
}
