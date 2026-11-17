// Package grpc implements length-prefixed gRPC message framing and per-stream state tracking.
package grpc

import (
	"encoding/binary"
	"strings"

	"github.com/zombat/sonic/internal/extract"
)

type framedMsg struct {
	size       int
	compressed bool
	frame      int
	t          float64
	endFrame   int
	endT       float64
	open       bool
	partial    []byte
	hasPartial bool
}

type framer struct {
	buf        []byte
	skip       int
	lost       bool
	messages   []framedMsg
	count      int
	total      int
	maxSize    int
	compressed int
}

func (f *framer) feed(data []byte, length, frame int, t float64) {
	if f.lost {
		return
	}
	pos := 0
	for pos < len(data) {
		if f.skip > 0 {
			take := min(f.skip, len(data)-pos)
			var msg *framedMsg
			if len(f.messages) > 0 {
				msg = &f.messages[len(f.messages)-1]
			}
			if msg != nil && msg.hasPartial && msg.open {
				room := maxDecodeBytes - len(msg.partial)
				if room > 0 {
					copyLen := min(take, room)
					msg.partial = append(msg.partial, data[pos:pos+copyLen]...)
				}
			}
			f.skip -= take
			pos += take
			if f.skip == 0 && msg != nil && msg.open {
				msg.open = false
				msg.endFrame = frame
				msg.endT = t
			}
			continue
		}
		need := 5 - len(f.buf)
		take := min(need, len(data)-pos)
		f.buf = append(f.buf, data[pos:pos+take]...)
		pos += take
		if len(f.buf) < 5 {
			break
		}
		flag := f.buf[0]
		size := int(binary.BigEndian.Uint32(f.buf[1:5]))
		f.buf = f.buf[:0]
		if flag != 0 && flag != 1 {
			f.lost = true
			return
		}
		f.count++
		f.total += size
		if size > f.maxSize {
			f.maxSize = size
		}
		f.compressed += int(flag)
		if len(f.messages) < maxMessagesDecoded {
			entry := framedMsg{
				size:       size,
				compressed: flag != 0,
				frame:      frame,
				t:          t,
				open:       size > 0,
				hasPartial: flag == 0,
			}
			if flag == 0 {
				entry.partial = []byte{}
			}
			if size == 0 {
				entry.endFrame = frame
				entry.endT = t
			}
			f.messages = append(f.messages, entry)
		} else if len(f.messages) > 0 {
			f.messages[len(f.messages)-1].open = false
		}
		f.skip = size
	}
	hidden := length - len(data)
	if hidden > 0 {
		if f.skip >= hidden && len(f.buf) == 0 {
			f.skip -= hidden
		} else {
			f.lost = true
		}
	}
}

func (f *framer) summary() FramerSummary {
	var largest *int
	if f.count > 0 {
		v := f.maxSize
		largest = &v
	}
	return FramerSummary{
		Messages:    f.count,
		Bytes:       f.total,
		Largest:     largest,
		Compressed:  f.compressed,
		FramingLost: f.lost,
	}
}

type rpcTrack struct {
	conn                   *connTrack
	streamID               int
	frames                 map[string]int
	tRequest               *float64
	requestHeaders         []extract.HTTP2Header
	responseHeaders        []extract.HTTP2Header
	trailers               []extract.HTTP2Header
	tFirstResponse         *float64
	tEnd                   *float64
	clientEnded            bool
	serverEnded            bool
	reset                  *ResetInfo
	serverEndedBeforeReset bool
	clientFramer           framer
	serverFramer           framer
	headerBlocksClient     int
	headerBlocksServer     int
	decodeFailed           bool
	protobuf               []ProtobufView
}

func (r *rpcTrack) header(name, block string) *string {
	var src []extract.HTTP2Header
	switch block {
	case "request":
		src = r.requestHeaders
	case "response":
		src = r.responseHeaders
	case "trailers":
		src = r.trailers
	}
	for _, h := range src {
		if strings.ToLower(h.Name) == name {
			return h.Value
		}
	}
	return nil
}

func (r *rpcTrack) method() *string {
	return r.header(":path", "request")
}

func (r *rpcTrack) isOpen() bool {
	return r.reset == nil && !(r.clientEnded && r.serverEnded)
}

type stallKey struct {
	sender   string
	streamID int
}

type pingKey struct {
	side   string
	opaque string
}

type pingTrack struct {
	sent       int
	acked      int
	rttMS      []float64
	idle       int
	firstFrame *int
	times      []float64
}

type stallTrack struct {
	sender        string
	streamID      int
	window        string
	frame         int
	t             float64
	reopenedT     *float64
	reopenedFrame *int
	dataWaiting   bool
	method        *string
	endedBy       *string
	endedT        *float64
}

type credTrack struct {
	requests   int
	frames     []int
	firstFrame int
	firstT     float64
}

type connTrack struct {
	index            int
	disc             *extract.TCPConnection
	client           *extract.Endpoint
	server           *extract.Endpoint
	serverKnownBy    string
	firstFrame       *int
	firstT           *float64
	lastT            *float64
	tlsSeen          bool
	magicFrame       *int
	packetsClient    int
	packetsServer    int
	packetsUnknown   int
	framesByType     map[string]int
	settingsClient   map[string]*int
	settingsServer   map[string]*int
	settingsFrameCli *int
	settingsFrameSrv *int
	rpcs             map[int]*rpcTrack
	rstStreams       []ResetInfo
	goaways          []GoawayRow
	pingsClient      pingTrack
	pingsServer      pingTrack
	pendingPings     map[pingKey]float64
	connWindowClient int
	connWindowServer int
	streamWindow     map[stallKey]int
	stalls           []*stallTrack
	openStall        map[stallKey]*stallTrack
	trackFlow        bool
	oversizeFrames   []OversizeFrameRow
	oversizeHeaders  []OversizeHeaderRow
	maxOpen          int
	maxOpenFrame     *int
	credentials      map[string]*credTrack
	metadataKeys     map[string]int
	hpackFailures    []int
	capabilities     *DecodedResponse
}
