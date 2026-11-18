// Package audit handles TLS ServerHello stream reading, midstream record checks,
// and TLS/overall session encryption classification.
package audit

import (
	"encoding/binary"

	"github.com/zombat/sonic/internal/analyze/tlsinspect"
	"github.com/zombat/sonic/internal/model"
)

type serverHelloInfo struct {
	version     string
	cipherSuite string
	code        *uint16
}

type helloReader struct {
	buf []byte
	pos int
	hs  []byte
}

func (hr *helloReader) parse() (stop bool, parsed *serverHelloInfo) {
	for hr.pos+5 <= len(hr.buf) {
		ctype := hr.buf[hr.pos]
		length := int(binary.BigEndian.Uint16(hr.buf[hr.pos+3 : hr.pos+5]))
		if (ctype != 20 && ctype != 22) || hr.buf[hr.pos+1] != 3 || length > 18432 {
			return true, nil
		}
		if hr.pos+5+length > len(hr.buf) {
			return false, nil
		}
		body := hr.buf[hr.pos+5 : hr.pos+5+length]
		hr.pos += 5 + length
		if ctype == 20 {
			continue
		}
		hr.hs = append(hr.hs, body...)
		for len(hr.hs) >= 4 {
			if hr.hs[0] != 2 {
				return true, nil
			}
			msgLen := int(hr.hs[1])<<16 | int(hr.hs[2])<<8 | int(hr.hs[3])
			if len(hr.hs) < 4+msgLen {
				break
			}
			msg := hr.hs[4 : 4+msgLen]
			hr.hs = hr.hs[4+msgLen:]
			sh := tlsinspect.ParseServerHello(msg)
			if sh == nil {
				return true, nil
			}
			if sh.HelloRetryRequest {
				continue
			}
			var codePtr *uint16
			if code, ok := tlsinspect.ServerHelloSuite(msg); ok {
				codePtr = &code
			}
			version := sh.Version
			if codePtr != nil && tlsinspect.TLS13Suites[*codePtr] {
				version = "TLS1.3"
			}
			return true, &serverHelloInfo{
				version:     version,
				cipherSuite: sh.CipherSuite,
				code:        codePtr,
			}
		}
	}
	return false, nil
}

func (d *direction) readHello(rel int, payload []byte, complete bool, frame int) {
	if d.hello == nil {
		return
	}
	if rel > len(d.hello.buf) {
		d.hello = nil
		return
	}
	if rel+len(payload) > len(d.hello.buf) {
		d.hello.buf = append(d.hello.buf, payload[len(d.hello.buf)-rel:]...)
	}
	stop, info := d.hello.parse()
	if info != nil {
		d.serverHello = info
		f := frame
		d.helloFrame = &f
	}
	if stop || !complete || len(d.hello.buf) >= maxHelloBytes {
		d.hello = nil
	}
}

func isTLSRecord(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	ctype := data[0]
	return (ctype >= 20 && ctype <= 23) &&
		data[1] == 3 && data[2] <= 4 &&
		binary.BigEndian.Uint16(data[3:5]) <= 18432
}

func tlsMidstream(payload []byte) bool {
	if len(payload) < 5 || (payload[0] != 21 && payload[0] != 23) || payload[1] != 3 || payload[2] < 1 || payload[2] > 3 {
		return false
	}
	minor := payload[2]
	pos := 0
	for pos+5 <= len(payload) {
		ctype := payload[pos]
		length := binary.BigEndian.Uint16(payload[pos+3 : pos+5])
		if ctype < 20 || ctype > 23 || payload[pos+1] != 3 || payload[pos+2] != minor || length == 0 || length > 18432 {
			return false
		}
		pos += 5 + int(length)
	}
	return true
}

func evaluateTLSEncryption(session *tcpSession, client, server endpointAddr) (*model.SessionEncryption, []endpointAddr) {
	if session.midstream {
		r := "the session began before the capture: its records look encrypted, but without the ServerHello a NULL cipher cannot be told from a real one"
		return &model.SessionEncryption{
			State:             tlsinspect.StateUnverified.String(),
			HandshakeCaptured: false,
			Reason:            &r,
		}, nil
	}
	var helloSide *direction
	for _, d := range session.dirs {
		if d.serverHello != nil {
			helloSide = d
			break
		}
	}
	if helloSide == nil {
		r := "no ServerHello in the capture (or one S.O.N.I.C. could not read), so the cipher suite is not known"
		return &model.SessionEncryption{
			State:             tlsinspect.StateUnverified.String(),
			HandshakeCaptured: false,
			Reason:            &r,
		}, nil
	}

	chosen := helloSide.serverHello
	state := tlsinspect.StateUnverified
	why := "the ServerHello is truncated"
	var suitePtr *string
	if chosen.code != nil {
		state, why = tlsinspect.SuiteEncryption(*chosen.code)
		sn := tlsinspect.SuiteName(*chosen.code)
		suitePtr = &sn
	}
	if tlsinspect.VersionIsWeak(chosen.version) && (state == tlsinspect.StateEncrypted || state == tlsinspect.StateWeak) {
		msg := chosen.version + " is deprecated (RFC 8996)"
		if why != "" {
			why = msg + "; " + why
		} else {
			why = msg
		}
		state = tlsinspect.StateWeak
	}
	var reasonPtr *string
	if why != "" {
		reasonPtr = &why
	}
	var readable []endpointAddr
	if state == tlsinspect.StateCleartext {
		readable = []endpointAddr{client, server}
	}
	ver := chosen.version
	return &model.SessionEncryption{
		State:             state.String(),
		HandshakeCaptured: true,
		Version:           &ver,
		CipherSuite:       suitePtr,
		ServerHelloFrame:  helloSide.helloFrame,
		Reason:            reasonPtr,
	}, readable
}

func computeEncryption(kind string, session *tcpSession, client, server endpointAddr, hasEncrypted bool) (*model.SessionEncryption, []endpointAddr) {
	var enc *model.SessionEncryption
	var readable []endpointAddr
	if kind == "ssh" && session.midstream {
		r := "no SSH banner or key exchange in the capture (the session began before it): recognised by its port and by payload that looks like ciphertext, so the cipher cannot be read"
		enc = &model.SessionEncryption{
			State:             tlsinspect.StateUnverified.String(),
			HandshakeCaptured: false,
			Reason:            &r,
		}
	} else if kind == "ssh" {
		enc, readable = evaluateSSHEncryption(session, client, server)
	} else {
		enc, readable = evaluateTLSEncryption(session, client, server)
	}
	if enc.State == tlsinspect.StateUnverified.String() && !hasEncrypted {
		enc.State = tlsinspect.StateNotStarted.String()
		r := "nothing was sent past the handshake, so there is no encrypted traffic to judge"
		enc.Reason = &r
	}
	return enc, readable
}
