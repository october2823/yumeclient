package main

// Custom-JA3 profiles: what the JA3 string cannot express (extension contents,
// HTTP/2 and HTTP/3 parameters) and the caller did not pass.
//
// fill_custom_with_chrome_defaults=True (default): taken from the Chrome
// profile the Python side names (Profiles.LATEST_CHROME). False: no Chrome
// values; only the generic values in main.go (ensure*) and the 0.6 HTTP/2
// defaults that keep the ClientHello valid.

import (
	"strconv"
	"strings"

	http2 "github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// ja3Extensions: extension ids of the JA3 string (third field).
func ja3Extensions(ja3 string) map[uint16]bool {
	out := map[uint16]bool{}
	parts := strings.Split(ja3, ",")
	if len(parts) < 3 {
		return out
	}
	for _, e := range strings.Split(parts[2], "-") {
		if v, err := strconv.ParseUint(e, 10, 16); err == nil {
			out[uint16(v)] = true
		}
	}
	return out
}

// chromeReference: the profile whose values fill a custom JA3 (nil: no fill).
type chromeReference struct {
	profile profiles.ClientProfile
	spec    tls.ClientHelloSpec
}

func newChromeReference(name string) *chromeReference {
	if name == "" {
		return nil
	}
	p := resolveProfile(name)
	spec, err := p.GetClientHelloSpec()
	if err != nil {
		return nil
	}
	return &chromeReference{profile: p, spec: spec}
}

// fillSpec copies extension contents from Chrome into empty extensions of spec.
func (r *chromeReference) fillSpec(spec *tls.ClientHelloSpec) {
	declared := map[tls.CurveID]bool{}
	for _, e := range spec.Extensions {
		if sc, ok := e.(*tls.SupportedCurvesExtension); ok {
			for _, c := range sc.Curves {
				declared[c] = true
			}
		}
	}
	for _, e := range spec.Extensions {
		switch ext := e.(type) {
		case *tls.SignatureAlgorithmsExtension:
			if len(ext.SupportedSignatureAlgorithms) == 0 {
				if ref := findExt[*tls.SignatureAlgorithmsExtension](r.spec); ref != nil {
					ext.SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), ref.SupportedSignatureAlgorithms...)
				}
			}
		case *tls.SupportedVersionsExtension:
			if len(ext.Versions) == 0 {
				if ref := findExt[*tls.SupportedVersionsExtension](r.spec); ref != nil {
					ext.Versions = append([]uint16(nil), ref.Versions...)
				}
			}
		case *tls.SupportedCurvesExtension:
			if len(ext.Curves) == 0 {
				if ref := findExt[*tls.SupportedCurvesExtension](r.spec); ref != nil {
					ext.Curves = append([]tls.CurveID(nil), ref.Curves...)
					for _, c := range ext.Curves {
						declared[c] = true
					}
				}
			}
		case *tls.ALPNExtension:
			if len(ext.AlpnProtocols) == 0 {
				if ref := findExt[*tls.ALPNExtension](r.spec); ref != nil {
					ext.AlpnProtocols = append([]string(nil), ref.AlpnProtocols...)
				}
			}
		case *tls.ApplicationSettingsExtension:
			if len(ext.SupportedProtocols) == 0 {
				ext.SupportedProtocols = r.alps()
			}
		case *tls.ApplicationSettingsExtensionNew:
			if len(ext.SupportedProtocols) == 0 {
				ext.SupportedProtocols = r.alps()
			}
		case *tls.GenericExtension:
			// trust_anchors: Chrome's list of trust anchor ids (the extension is
			// built with an empty list)
			if ext.Id == extTrustAnchors {
				for _, re := range r.spec.Extensions {
					if g, ok := re.(*tls.GenericExtension); ok && g.Id == extTrustAnchors {
						ext.Data = append([]byte(nil), g.Data...)
					}
				}
			}
		case *tls.GREASEEncryptedClientHelloExtension:
			if len(ext.CandidateCipherSuites) == 0 && len(ext.CandidatePayloadLens) == 0 {
				if ref := findExt[*tls.GREASEEncryptedClientHelloExtension](r.spec); ref != nil {
					ext.CandidateCipherSuites = append([]tls.HPKESymmetricCipherSuite(nil), ref.CandidateCipherSuites...)
					ext.CandidatePayloadLens = append([]uint16(nil), ref.CandidatePayloadLens...)
				}
			}
		}
	}
	// key shares after the curves are known: Chrome's shares for offered groups only
	// (a share for a group missing from supported_groups is illegal, RFC 8446 4.2.8)
	if ks := findExt[*tls.KeyShareExtension](*spec); ks != nil && len(ks.KeyShares) == 0 {
		if ref := findExt[*tls.KeyShareExtension](r.spec); ref != nil {
			for _, share := range ref.KeyShares {
				greaseOK := isGREASEU16(uint16(share.Group)) && hasGREASECurve(declared)
				hybridOK := (share.Group != tls.X25519MLKEM768 && share.Group != tls.X25519Kyber768Draft00) || declared[tls.X25519]
				if (declared[share.Group] && hybridOK) || greaseOK {
					ks.KeyShares = append(ks.KeyShares, tls.KeyShare{Group: share.Group, Data: append([]byte(nil), share.Data...)})
				}
			}
			if onlyGREASE(ks.KeyShares) {
				ks.KeyShares = nil // ensureKeyShare picks real groups
			}
		}
	}
}

func (r *chromeReference) alps() []string {
	if ref := findExt[*tls.ApplicationSettingsExtensionNew](r.spec); ref != nil {
		return append([]string(nil), ref.SupportedProtocols...)
	}
	if ref := findExt[*tls.ApplicationSettingsExtension](r.spec); ref != nil {
		return append([]string(nil), ref.SupportedProtocols...)
	}
	return []string{"h2"}
}

func hasGREASECurve(declared map[tls.CurveID]bool) bool {
	for c := range declared {
		if isGREASEU16(uint16(c)) {
			return true
		}
	}
	return false
}

func onlyGREASE(shares []tls.KeyShare) bool {
	for _, s := range shares {
		if !isGREASEU16(uint16(s.Group)) {
			return false
		}
	}
	return true
}

func findExt[T tls.TLSExtension](spec tls.ClientHelloSpec) T {
	var zero T
	for _, e := range spec.Extensions {
		if v, ok := e.(T); ok {
			return v
		}
	}
	return zero
}

// customH2 resolves the HTTP/2 and HTTP/3 parameters of a custom profile:
// explicit values first, then Chrome's (ref != nil), then the generic defaults.
type customH2 struct {
	settings       map[http2.SettingID]uint32
	order          []http2.SettingID
	pseudo         []string
	flow           uint32
	priorities     []http2.Priority
	headerPriority *http2.PriorityParam
	h3Settings     map[uint64]uint64
	h3Order        []uint64
	h3Priority     uint32
	h3Pseudo       []string
	h3Grease       bool
}

func resolveCustomH2(ct customH2Input, ref *chromeReference) customH2 {
	out := customH2{settings: ct.settings, order: ct.order}
	if !ct.explicitSettings && ref != nil {
		out.settings, out.order = ref.profile.GetSettings(), ref.profile.GetSettingsOrder()
	}
	out.pseudo = ct.pseudo
	if len(out.pseudo) == 0 {
		if ref != nil {
			out.pseudo = ref.profile.GetPseudoHeaderOrder()
		} else {
			out.pseudo = []string{":method", ":authority", ":scheme", ":path"}
		}
	}
	out.flow = ct.flow
	if out.flow == 0 {
		if ref != nil {
			out.flow = ref.profile.GetConnectionFlow()
		} else {
			out.flow = 15663105
		}
	}
	out.priorities = ct.priorities
	if len(out.priorities) == 0 && ref != nil {
		out.priorities = ref.profile.GetPriorities()
	}
	out.headerPriority = ct.headerPriority
	if out.headerPriority == nil && ref != nil {
		out.headerPriority = ref.profile.GetHeaderPriority()
	}
	if ref != nil {
		out.h3Settings, out.h3Order = ref.profile.GetHttp3Settings(), ref.profile.GetHttp3SettingsOrder()
		out.h3Priority, out.h3Pseudo = ref.profile.GetHttp3PriorityParam(), ref.profile.GetHttp3PseudoHeaderOrder()
		out.h3Grease = ref.profile.GetHttp3SendGreaseFrames()
	}
	return out
}

// customH2Input: the caller's HTTP/2 values; settings are the mapped explicit
// ones or, when none were given (explicitSettings=false), the generic defaults.
type customH2Input struct {
	explicitSettings bool
	settings         map[http2.SettingID]uint32
	order            []http2.SettingID
	pseudo           []string
	flow             uint32
	priorities       []http2.Priority
	headerPriority   *http2.PriorityParam
}

// extTrustAnchors is the trust_anchors extension (draft-ietf-tls-trust-anchor-ids)
// that Chrome sends from version 146.
const extTrustAnchors uint16 = 0xca34
