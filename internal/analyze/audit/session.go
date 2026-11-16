// Package audit tracks per-direction byte streams and TCP session buckets.
package audit

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/bits"

	"github.com/zombat/sonic/internal/model"
)

const (
	maxSSHKeXBytes = 65536
	maxHelloBytes  = 8192
	minProbeBytes  = 128
	maxProbeBytes  = 65536
)

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

type endpointAddr struct {
	ip   string
	port int
}

type direction struct {
	base         uint32
	buf          []byte
	lost         bool
	hasKeXEnd    bool
	kexEnd       int
	nextRecord   int
	hasLastType  bool
	lastType     byte
	kexinit      map[string][]string
	kexinitFrame *int
	hello        *helloReader
	serverHello  *serverHelloInfo
	helloFrame   *int
}

func newDirection(base uint32, readHello bool) *direction {
	var hr *helloReader
	if readHello {
		hr = &helloReader{}
	}
	return &direction{base: base, hello: hr}
}

func (d *direction) sshClassify(rel int, payload []byte, frame int) string {
	if d.hasKeXEnd {
		if rel >= d.kexEnd {
			return "encrypted"
		}
		return "key_exchange"
	}
	if d.lost {
		return "encrypted"
	}
	if rel != len(d.buf) {
		if rel < len(d.buf) {
			return "key_exchange"
		}
		d.lost = true
		return "encrypted"
	}
	d.buf = append(d.buf, payload...)
	pos := 0
	if bytes.HasPrefix(d.buf, []byte("SSH-")) {
		nl := bytes.IndexByte(d.buf, '\n')
		if nl < 0 {
			return "key_exchange"
		}
		pos = nl + 1
	}
	for pos+6 <= len(d.buf) {
		length := int(binary.BigEndian.Uint32(d.buf[pos : pos+4]))
		if length < 2 || length > 35000 {
			d.lost = true
			break
		}
		code := d.buf[pos+5]
		if code == 20 && d.kexinit == nil && pos+4+length <= len(d.buf) {
			padding := int(d.buf[pos+4])
			if padding < length {
				d.kexinit = ParseKexInit(d.buf[pos+5 : pos+4+length-padding])
				f := frame
				d.kexinitFrame = &f
			}
		}
		if code == 21 {
			d.hasKeXEnd = true
			d.kexEnd = pos + 4 + length
			d.buf = nil
			break
		}
		pos += 4 + length
	}
	if len(d.buf) > maxSSHKeXBytes {
		d.lost = true
		d.buf = nil
	}
	return "key_exchange"
}

func (d *direction) tlsClassify(rel int, payload []byte, length int) string {
	if d.lost {
		return "encrypted"
	}
	end := rel + length
	if end <= d.nextRecord {
		return d.continuing()
	}
	var types []byte
	carry := d.buf
	for d.nextRecord < end {
		offset := d.nextRecord - rel
		if offset < 0 && len(carry) == 0 {
			d.lost = true
			break
		}
		var header []byte
		if len(carry) > 0 {
			need := min(5-len(carry), len(payload))
			header = make([]byte, len(carry)+need)
			copy(header, carry)
			copy(header[len(carry):], payload[:need])
			carry = nil
			d.buf = nil
		} else {
			if offset < 0 || offset >= len(payload) {
				d.lost = true
				break
			}
			header = payload[offset:min(offset+5, len(payload))]
		}
		if len(header) < 5 {
			if offset+5 <= length {
				d.lost = true
			} else {
				d.buf = append([]byte(nil), header...)
			}
			break
		}
		if !isTLSRecord(header) {
			d.lost = true
			break
		}
		types = append(types, header[0])
		d.hasLastType = true
		d.lastType = header[0]
		d.nextRecord += 5 + int(binary.BigEndian.Uint16(header[3:5]))
	}
	if d.lost {
		return "encrypted"
	}
	for _, t := range types {
		if t == 23 {
			return "encrypted"
		}
	}
	if len(types) > 0 {
		return "key_exchange"
	}
	return d.continuing()
}

func (d *direction) continuing() string {
	if d.hasLastType && d.lastType == 23 {
		return "encrypted"
	}
	return "key_exchange"
}

type bucketKey struct {
	src endpointAddr
	cls string
}

type frameBucket struct {
	packets    int
	bytes      int
	firstFrame int
	firstT     float64
	lastFrame  int
	lastT      float64
	frames     []int
}

type tcpSession struct {
	hasServer   bool
	server      endpointAddr
	client      endpointAddr
	kind        string
	spoke       map[endpointAddr]bool
	dirs        map[endpointAddr]*direction
	buckets     map[bucketKey]*frameBucket
	bucketOrder []bucketKey
	midstream   bool
	hasProbe    bool
	probeTotal  int
	probePrint  int
	probeMask   [4]uint64
}

func newTCPSession(sshPort bool) *tcpSession {
	return &tcpSession{
		spoke:    make(map[endpointAddr]bool),
		dirs:     make(map[endpointAddr]*direction),
		buckets:  make(map[bucketKey]*frameBucket),
		hasProbe: sshPort,
	}
}

func (s *tcpSession) sample(payload []byte) {
	if !s.hasProbe || s.probeTotal >= maxProbeBytes {
		return
	}
	s.probeTotal += len(payload)
	for _, b := range payload {
		if (b >= 0x20 && b < 0x7F) || b == '\t' || b == '\r' || b == '\n' {
			s.probePrint++
		}
		s.probeMask[b>>6] |= 1 << (b & 63)
	}
}

func (s *tcpSession) looksLikeCiphertext() bool {
	if !s.hasProbe || s.probeTotal < minProbeBytes {
		return false
	}
	uniqueBytes := 0
	for _, w := range s.probeMask {
		uniqueBytes += bits.OnesCount64(w)
	}
	expected := 256.0 * (1.0 - math.Pow(255.0/256.0, float64(s.probeTotal)))
	return float64(s.probePrint)/float64(s.probeTotal) <= 0.6 && float64(uniqueBytes) >= 0.6*expected
}

func (s *tcpSession) add(src endpointAddr, cls string, rec *model.Record) {
	k := bucketKey{src: src, cls: cls}
	b, ok := s.buckets[k]
	if !ok {
		b = &frameBucket{
			firstFrame: rec.N,
			firstT:     rec.T,
			lastFrame:  rec.N,
			lastT:      rec.T,
		}
		s.buckets[k] = b
		s.bucketOrder = append(s.bucketOrder, k)
	}
	b.packets++
	b.bytes += rec.Len
	b.lastFrame = rec.N
	b.lastT = rec.T
	model.AddFrame(&b.frames, rec.N)
}
