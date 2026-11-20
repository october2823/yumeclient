package main

// HTTP/3 fingerprints of real browsers (native/h3profiles.json, built from
// captures by scripts/h3_profiles.py): the QUIC ClientHello, transport
// parameters, packet layout, SETTINGS, control stream and QPACK streams.

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	quic "github.com/bogdanfinn/quic-go-utls"
	"github.com/bogdanfinn/quic-go-utls/http3"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

//go:embed h3profiles.json
var h3ProfilesJSON []byte

type h3TransportParameter struct {
	ID     uint64 `json:"id"`
	Kind   string `json:"kind"`
	Value  uint64 `json:"value"`
	Hex    string `json:"hex"`
	MaxLen int    `json:"max_len"`
}

type h3Capture struct {
	QUIC struct {
		ClientHello                string                 `json:"client_hello"`
		ECHGreasePayloadLens       []uint16               `json:"ech_grease_payload_lens"`
		ShuffleExtensions          bool                   `json:"shuffle_extensions"`
		TransportParameters        []h3TransportParameter `json:"transport_parameters"`
		ShuffleTransportParameters bool                   `json:"shuffle_transport_parameters"`
		InitialPacketSize          uint16                 `json:"initial_packet_size"`
		DestConnIDLen              int                    `json:"dcid_len"`
		SrcConnIDLen               int                    `json:"scid_len"`
		FirstPacketNumber          int64                  `json:"first_packet_number"`
		Chaos                      string                 `json:"chaos"`
		PadWithZeros               bool                   `json:"pad_with_zeros"`
	} `json:"quic"`
	H3 struct {
		Settings          [][]json.RawMessage `json:"settings"`
		GreaseFrame       bool                `json:"grease_frame"`
		GreaseFrameMaxLen int                 `json:"grease_frame_max_len"`
		PriorityUpdates   bool                `json:"priority_updates"`
		Priority          string              `json:"priority"`
		PriorityHeader    bool                `json:"priority_header"`
		PseudoHeaderOrder []string            `json:"pseudo_header_order"`
		QPACK             *struct {
			Open         bool `json:"open"`
			DecoderFirst bool `json:"decoder_first"`
			Eager        bool `json:"eager"`
			ZeroCapacity bool `json:"zero_capacity"`
		} `json:"qpack"`
	} `json:"h3"`
}

type h3Profiles struct {
	Captures map[string]*h3Capture `json:"captures"`
	Profiles map[string]struct {
		Capture string `json:"capture"`
	} `json:"profiles"`
}

var (
	h3Once sync.Once
	h3Data h3Profiles
	h3Err  error
)

func loadH3Profiles() (*h3Profiles, error) {
	h3Once.Do(func() { h3Err = json.Unmarshal(h3ProfilesJSON, &h3Data) })
	return &h3Data, h3Err
}

// h3Capture returns the captured HTTP/3 fingerprint for a profile name, nil if
// there is none.
func h3CaptureFor(name string) *h3Capture {
	data, err := loadH3Profiles()
	if err != nil {
		return nil
	}
	p, ok := data.Profiles[name]
	if !ok {
		return nil
	}
	return data.Captures[p.Capture]
}

var chaosModes = map[string]quic.ChaosMode{
	"off": quic.ChaosOff, "single_packet": quic.ChaosSinglePacket,
	"last_packet": quic.ChaosLastPacket, "multi_packet": quic.ChaosMultiPacket,
	"sni_slice": quic.ChaosSNISlice,
}

// applyH3Capture gives a profile the HTTP/3 layer of a real browser.
func applyH3Capture(p profiles.ClientProfile, c *h3Capture) (profiles.ClientProfile, error) {
	hs, err := hex.DecodeString(c.QUIC.ClientHello)
	if err != nil {
		return p, fmt.Errorf("h3 profile: client hello: %w", err)
	}
	// uTLS parses a ClientHello in a TLS record
	raw := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	shuffle := c.QUIC.ShuffleExtensions
	echLens := c.QUIC.ECHGreasePayloadLens
	hello := func() (*tls.ClientHelloSpec, error) {
		spec := &tls.ClientHelloSpec{}
		if err := spec.FromRaw(raw, true); err != nil {
			return nil, err
		}
		for _, e := range spec.Extensions {
			if g, ok := e.(*tls.GREASEEncryptedClientHelloExtension); ok && len(echLens) > 0 {
				g.CandidatePayloadLens = echLens
			}
		}
		if shuffle {
			spec.Extensions = tls.ShuffleChromeTLSExtensions(spec.Extensions)
		}
		return spec, nil
	}
	if _, err := hello(); err != nil {
		return p, fmt.Errorf("h3 profile: client hello: %w", err)
	}

	fp := &profiles.HTTP3Fingerprint{
		InitialPacketSize:     c.QUIC.InitialPacketSize,
		SrcConnIDLen:          c.QUIC.SrcConnIDLen,
		MaxIncomingStreams:    -1,
		MaxIncomingUniStreams: -1,
	}
	var tps []quic.TransportParameter
	for _, t := range c.QUIC.TransportParameters {
		tp := quic.TransportParameter{ID: t.ID}
		switch t.Kind {
		case "varint":
			tp.Kind, tp.Value = quic.TransportParameterVarint, t.Value
			switch t.ID {
			case 0x01:
				fp.MaxIdleTimeout = time.Duration(t.Value) * time.Millisecond
			case 0x04:
				fp.ConnectionReceiveWindow = t.Value
			case 0x05:
				fp.StreamReceiveWindow = t.Value
			case 0x08:
				fp.MaxIncomingStreams = int64(t.Value)
			case 0x09:
				fp.MaxIncomingUniStreams = int64(t.Value)
			}
		case "initial_rtt":
			tp.Kind, tp.Optional = quic.TransportParameterVarint, true
		case "bytes":
			b, err := hex.DecodeString(t.Hex)
			if err != nil {
				return p, fmt.Errorf("h3 profile: transport parameter %#x: %w", t.ID, err)
			}
			tp.Kind, tp.Bytes = quic.TransportParameterBytes, b
		case "scid":
			tp.Kind = quic.TransportParameterSourceConnectionID
		case "grease":
			tp.Kind, tp.Len = quic.TransportParameterGrease, -t.MaxLen
		case "version_information":
			b, err := hex.DecodeString(t.Hex)
			if err != nil {
				return p, fmt.Errorf("h3 profile: version information: %w", err)
			}
			tp.Kind, tp.Bytes, tp.Shuffle = quic.TransportParameterVersionInformation, b, true
		default:
			return p, fmt.Errorf("h3 profile: unknown transport parameter kind %q", t.Kind)
		}
		if t.ID == 0x20 {
			fp.Datagrams = true
		}
		tps = append(tps, tp)
	}
	fp.QUIC = &quic.Fingerprint{
		ClientHello:                hello,
		TransportParameters:        tps,
		ShuffleTransportParameters: c.QUIC.ShuffleTransportParameters,
		DestConnIDLen:              c.QUIC.DestConnIDLen,
		FirstPacketNumber:          c.QUIC.FirstPacketNumber,
		Chaos:                      chaosModes[c.QUIC.Chaos],
		PadWithZeros:               c.QUIC.PadWithZeros,
	}
	if _, ok := chaosModes[c.QUIC.Chaos]; !ok {
		return p, fmt.Errorf("h3 profile: unknown chaos mode %q", c.QUIC.Chaos)
	}

	settings := map[uint64]uint64{}
	var order []uint64
	h3Datagram := false
	for _, s := range c.H3.Settings {
		var name string
		if len(s) == 1 && json.Unmarshal(s[0], &name) == nil && name == "GREASE" {
			fp.GreaseSetting = true
			continue
		}
		if len(s) != 2 {
			return p, fmt.Errorf("h3 profile: bad setting %s", s)
		}
		var id, value uint64
		if err := json.Unmarshal(s[0], &id); err != nil {
			return p, fmt.Errorf("h3 profile: setting id: %w", err)
		}
		if err := json.Unmarshal(s[1], &value); err != nil {
			return p, fmt.Errorf("h3 profile: setting value: %w", err)
		}
		order = append(order, id)
		if id == 0x33 {
			h3Datagram = value == 1
			continue // sent by the transport's datagram support
		}
		settings[id] = value
	}
	fp.H3Datagram = h3Datagram
	fp.Control = &http3.ClientFingerprint{
		GreaseFrame:       c.H3.GreaseFrame,
		GreaseFrameMaxLen: c.H3.GreaseFrameMaxLen,
		PriorityUpdates:   c.H3.PriorityUpdates,
		DefaultPriority:   c.H3.Priority,
		PriorityHeader:    c.H3.PriorityHeader,
	}
	if q := c.H3.QPACK; q != nil {
		fp.QPACK = &http3.QPACKStreams{Open: q.Open, DecoderFirst: q.DecoderFirst, Eager: q.Eager, ZeroCapacity: q.ZeroCapacity}
	}
	pseudo := c.H3.PseudoHeaderOrder
	if len(pseudo) == 0 {
		pseudo = p.GetHttp3PseudoHeaderOrder()
	}
	np := profiles.NewClientProfile(p.GetClientHelloId(), p.GetSettings(), p.GetSettingsOrder(), p.GetPseudoHeaderOrder(),
		p.GetConnectionFlow(), p.GetPriorities(), p.GetHeaderPriority(), p.GetStreamID(), p.GetAllowHTTP(),
		settings, order, 0, pseudo, false)
	return np.WithHTTP3Fingerprint(fp), nil
}
