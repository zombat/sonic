// Package grpc decodes gNMI request protobuf messages without .proto schemas.
package grpc

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/zombat/sonic/internal/model"
)

// SetOpSummary counts and samples paths for one gNMI Set operation type.
type SetOpSummary struct {
	Count int       `json:"count"`
	Paths []*string `json:"paths"`
}

// SubscriptionItem summarizes one gNMI Subscribe entry without exposing payload values.
type SubscriptionItem struct {
	Path               *string  `json:"path"`
	Mode               string   `json:"mode"`
	SampleIntervalS    *float64 `json:"sample_interval_s,omitempty"`
	HeartbeatIntervalS *float64 `json:"heartbeat_interval_s,omitempty"`
}

// GetRequestDecoded holds decoded fields for gnmi.gNMI/Get requests.
type GetRequestDecoded struct {
	Paths                []*string `json:"paths"`
	Type                 string    `json:"type"`
	Encoding             *string   `json:"encoding"`
	EncodingFieldPresent bool      `json:"encoding_field_present"`
}

// SetRequestDecoded holds decoded counts and paths for gnmi.gNMI/Set requests.
type SetRequestDecoded struct {
	Delete       SetOpSummary `json:"delete"`
	Replace      SetOpSummary `json:"replace"`
	Update       SetOpSummary `json:"update"`
	UnionReplace SetOpSummary `json:"union_replace"`
}

// SubscribeRequestDecoded holds decoded mode, encoding, and subscription list metadata.
type SubscribeRequestDecoded struct {
	Mode                 string             `json:"mode"`
	Encoding             *string            `json:"encoding"`
	EncodingFieldPresent bool               `json:"encoding_field_present"`
	UpdatesOnly          bool               `json:"updates_only"`
	Subscriptions        []SubscriptionItem `json:"subscriptions"`
	SubscriptionCount    int                `json:"subscription_count"`
}

// DecodedRequest represents a decoded gNMI request variant.
type DecodedRequest struct {
	Get       *GetRequestDecoded
	Set       *SetRequestDecoded
	Subscribe *SubscribeRequestDecoded
	Poll      bool
}

// Empty reports whether DecodedRequest holds any decoded fields.
func (d *DecodedRequest) Empty() bool {
	return d == nil || (d.Get == nil && d.Set == nil && d.Subscribe == nil && !d.Poll)
}

// MarshalJSON encodes the populated request variant directly matching gnmi_decode.py.
func (d DecodedRequest) MarshalJSON() ([]byte, error) {
	switch {
	case d.Get != nil:
		return json.Marshal(d.Get)
	case d.Set != nil:
		return json.Marshal(d.Set)
	case d.Poll:
		return json.Marshal(struct {
			Poll bool `json:"poll"`
		}{Poll: true})
	case d.Subscribe != nil:
		return json.Marshal(d.Subscribe)
	default:
		return []byte("{}"), nil
	}
}

func splitMethod(method string) (string, string) {
	trimmed := strings.TrimLeft(method, "/")
	parts := strings.SplitN(trimmed, "/", 2)
	service := parts[0]
	rpc := method
	if idx := strings.LastIndexByte(method, '/'); idx >= 0 {
		rpc = method[idx+1:]
	}
	return service, rpc
}

// DecodeRequest extracts troubleshooting fields from one gNMI request protobuf payload.
func DecodeRequest(method string, message []byte) (*DecodedRequest, error) {
	service, rpc := splitMethod(method)
	fields, err := ParseFields(message)
	if err != nil {
		return nil, err
	}
	if service != "gnmi.gNMI" {
		return &DecodedRequest{}, nil
	}
	switch rpc {
	case "Get":
		return decodeGetReq(fields)
	case "Set":
		return decodeSetReq(fields)
	case "Subscribe":
		return decodeSubReq(fields)
	default:
		return &DecodedRequest{}, nil
	}
}

func decodeGetReq(fields []ProtoField) (*DecodedRequest, error) {
	prefixBytes, _ := oneBytes(fields, 1)
	prefix, err := RenderPath(prefixBytes)
	if err != nil {
		return nil, err
	}
	encF, encPresent := oneField(fields, 5)
	encVal := 0
	if encPresent {
		encVal = int(encF.Varint)
	}
	rawPaths := allFields(fields, 2)
	paths := make([]*string, 0, min(len(rawPaths), MaxList))
	for i := 0; i < len(rawPaths) && i < MaxList; i++ {
		if rawPaths[i].Wire != 2 {
			return nil, errors.New("expected bytes for Get path")
		}
		p, err := RenderPath(rawPaths[i].Bytes)
		if err != nil {
			return nil, err
		}
		paths = append(paths, JoinPaths(prefix, p))
	}
	return &DecodedRequest{
		Get: &GetRequestDecoded{
			Paths:                paths,
			Type:                 enumName(DataTypes, oneInt(fields, 3, 0)),
			Encoding:             EncodingName(&encVal),
			EncodingFieldPresent: encPresent && encF.Wire != 2,
		},
	}, nil
}

func decodeSetReq(fields []ProtoField) (*DecodedRequest, error) {
	prefixBytes, _ := oneBytes(fields, 1)
	prefix, err := RenderPath(prefixBytes)
	if err != nil {
		return nil, err
	}
	extractOp := func(num int, directPath bool) (SetOpSummary, error) {
		vals := allFields(fields, num)
		paths := make([]*string, 0, min(len(vals), MaxList))
		for _, v := range vals {
			if v.Wire != 2 {
				return SetOpSummary{}, errors.New("expected bytes in Set operation")
			}
			var rawPath []byte
			if directPath {
				rawPath = v.Bytes
			} else {
				ufields, err := ParseFields(v.Bytes)
				if err != nil {
					return SetOpSummary{}, err
				}
				rawPath, _ = oneBytes(ufields, 1)
			}
			p, err := RenderPath(rawPath)
			if err != nil {
				return SetOpSummary{}, err
			}
			if len(paths) < MaxList {
				paths = append(paths, JoinPaths(prefix, p))
			}
		}
		return SetOpSummary{Count: len(vals), Paths: paths}, nil
	}
	delOp, err := extractOp(2, true)
	if err != nil {
		return nil, err
	}
	repOp, err := extractOp(3, false)
	if err != nil {
		return nil, err
	}
	updOp, err := extractOp(4, false)
	if err != nil {
		return nil, err
	}
	uniOp, err := extractOp(6, false)
	if err != nil {
		return nil, err
	}
	return &DecodedRequest{
		Set: &SetRequestDecoded{
			Delete:       delOp,
			Replace:      repOp,
			Update:       updOp,
			UnionReplace: uniOp,
		},
	}, nil
}

func decodeSubReq(fields []ProtoField) (*DecodedRequest, error) {
	if _, ok := oneField(fields, 3); ok {
		return &DecodedRequest{Poll: true}, nil
	}
	subBytes, ok := oneBytes(fields, 1)
	if !ok {
		return &DecodedRequest{}, nil
	}
	sfields, err := ParseFields(subBytes)
	if err != nil {
		return nil, err
	}
	pBytes, _ := oneBytes(sfields, 1)
	prefix, err := RenderPath(pBytes)
	if err != nil {
		return nil, err
	}
	rawSubs := allFields(sfields, 2)
	subs := make([]SubscriptionItem, 0, min(len(rawSubs), MaxList))
	for i := 0; i < len(rawSubs) && i < MaxList; i++ {
		if rawSubs[i].Wire != 2 {
			return nil, errors.New("expected bytes for Subscription")
		}
		ifields, err := ParseFields(rawSubs[i].Bytes)
		if err != nil {
			return nil, err
		}
		pb, _ := oneBytes(ifields, 1)
		rp, err := RenderPath(pb)
		if err != nil {
			return nil, err
		}
		item := SubscriptionItem{
			Path: JoinPaths(prefix, rp),
			Mode: enumName(SubscriptionModes, oneInt(ifields, 2, 0)),
		}
		if si := oneInt(ifields, 3, 0); si != 0 {
			sec := model.Round(float64(si)/1e9, 3)
			item.SampleIntervalS = &sec
		}
		if hb := oneInt(ifields, 5, 0); hb != 0 {
			sec := model.Round(float64(hb)/1e9, 3)
			item.HeartbeatIntervalS = &sec
		}
		subs = append(subs, item)
	}
	encF, encPresent := oneField(sfields, 8)
	encVal := 0
	if encPresent {
		encVal = int(encF.Varint)
	}
	return &DecodedRequest{
		Subscribe: &SubscribeRequestDecoded{
			Mode:                 enumName(SubscriptionListModes, oneInt(sfields, 5, 0)),
			Encoding:             EncodingName(&encVal),
			EncodingFieldPresent: encPresent && encF.Wire != 2,
			UpdatesOnly:          oneInt(sfields, 9, 0) != 0,
			Subscriptions:        subs,
			SubscriptionCount:    len(rawSubs),
		},
	}, nil
}
