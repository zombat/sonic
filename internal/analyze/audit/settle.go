// Package audit settles classified TCP sessions against the allowlist and
// evaluates negotiated SSH/TLS cipher security.
package audit

import (
	"fmt"
	"slices"

	"github.com/zombat/sonic/internal/model"
)

func (d *Detector) settleSessions() []model.TCPSession {
	summaries := make([]model.TCPSession, 0, len(d.sessions))
	for _, key := range d.sessionOrder {
		sess := d.sessions[key]
		endA, endB := key.a, key.b
		kind := sess.kind
		if kind == "" {
			kind = "other"
		}
		var svcPtr *int
		if sess.hasServer {
			p := sess.server.port
			svcPtr = &p
		} else {
			pA, pB := endA.port, endB.port
			svcPtr = model.ServicePort(&pA, &pB)
		}
		svc := 0
		if svcPtr != nil {
			svc = *svcPtr
		}
		server := sess.server
		if !sess.hasServer {
			if endA.port == svc {
				server = endA
			} else {
				server = endB
			}
		}
		client := endA
		if server == endA {
			client = endB
		}
		if kind == "other" && sshPorts[svc] && sess.looksLikeCiphertext() {
			kind = "ssh"
			sess.midstream = true
		}

		name, category, kindTokens := SessionLabel(kind, svcPtr)
		ports := map[string]bool{
			fmt.Sprintf("tcp:%d", endA.port): true,
			fmt.Sprintf("tcp:%d", endB.port): true,
			"proto:6":                        true,
		}
		for _, p := range []int{endA.port, endB.port} {
			if pn, ok := PortNames[p]; ok {
				ports[pn] = true
			}
		}
		if kind == "other" {
			var routing []string
			for tok := range ports {
				if routingSet[tok] {
					routing = append(routing, tok)
				}
			}
			if len(routing) > 0 {
				slices.Sort(routing)
				name = routing[0]
				category = "routing"
			}
		}

		// Sort buckets stably by first_frame so violation order matches Python.
		sortedKeys := slices.Clone(sess.bucketOrder)
		slices.SortStableFunc(sortedKeys, func(ak, bk bucketKey) int {
			return sess.buckets[ak].firstFrame - sess.buckets[bk].firstFrame
		})

		type classBucket struct {
			src    endpointAddr
			cls    string
			bucket *frameBucket
		}
		classes := make([]classBucket, 0, len(sortedKeys))
		hasEncrypted := false
		for _, bk := range sortedKeys {
			cls := bk.cls
			if sess.midstream && (cls == "pending" || cls == "cleartext") {
				cls = "encrypted"
			} else if cls == "pending" {
				if kind == "ssh" || kind == "tls" {
					cls = "key_exchange"
				} else {
					cls = "cleartext"
				}
			}
			if category == "routing" {
				cls = "cleartext"
			}
			if cls == "encrypted" {
				hasEncrypted = true
			}
			classes = append(classes, classBucket{src: bk.src, cls: cls, bucket: sess.buckets[bk]})
		}

		var enc *model.SessionEncryption
		var readable []endpointAddr
		if kind == "ssh" || kind == "tls" {
			enc, readable = computeEncryption(kind, sess, client, server, hasEncrypted)
			if enc.State == "cleartext" {
				name += " without encryption"
				category = "unencrypted_session"
				kindTokens = map[string]bool{}
			}
		}

		tokens := make(map[string]bool, len(ports)+len(kindTokens))
		for k := range ports {
			tokens[k] = true
		}
		for k := range kindTokens {
			tokens[k] = true
		}
		if kind == "ssh" && svc != 830 {
			delete(tokens, "netconf")
		}

		totals := make(map[string]int)
		packets := 0
		byTransport := false
		for _, cb := range classes {
			cls := cb.cls
			if cls == "encrypted" && slices.Contains(readable, cb.src) {
				cls = "cleartext"
			}
			dst := endA
			if cb.src == endA {
				dst = endB
			}
			d.protect(cls, cb.bucket.packets)
			totals[cls] += cb.bucket.packets
			packets += cb.bucket.packets
			matched := false
			for _, rule := range d.rules {
				if rule.Matches(tokens, []string{cb.src.ip, dst.ip}) {
					d.allowed += cb.bucket.packets
					d.allowedBy[rule.Text] += cb.bucket.packets
					if rule.Tokens["ssh"] || rule.Tokens["tls"] || rule.Tokens["netconf"] {
						byTransport = true
					}
					matched = true
					break
				}
			}
			if !matched {
				reason := ""
				if enc != nil && enc.Reason != nil {
					reason = *enc.Reason
				}
				d.violate(name, category, true, cb.src.ip, dst.ip, cb.bucket, cls, reason)
			}
		}

		firstFrame := 0
		for _, bk := range sess.bucketOrder {
			ff := sess.buckets[bk].firstFrame
			if firstFrame == 0 || ff < firstFrame {
				firstFrame = ff
			}
		}
		knownBy := "port"
		if sess.hasServer {
			knownBy = "syn"
		}
		summary := model.TCPSession{
			Service:       fmt.Sprintf("tcp/%d", svc),
			Protocol:      name,
			Category:      category,
			Client:        fmt.Sprintf("%s:%d", client.ip, client.port),
			Server:        fmt.Sprintf("%s:%d", server.ip, server.port),
			ServerKnownBy: &knownBy,
			Packets:       packets,
			FirstFrame:    firstFrame,
			Protection:    totals,
		}
		if enc != nil {
			summary.Encryption = enc
			b := byTransport
			summary.AllowedAsEncrypted = &b
		}
		summaries = append(summaries, summary)
	}

	d.sessions = make(map[sessionKey]*tcpSession)
	d.sessionOrder = nil
	slices.SortStableFunc(summaries, func(a, b model.TCPSession) int {
		return a.FirstFrame - b.FirstFrame
	})
	return summaries
}
