package main

/*
#include <stdlib.h>
*/
import "C"

import (
 "bufio"
 "context"
 crandtls "crypto/tls"
 "encoding/base64"
 "encoding/json"
 "fmt"
 "net"
 "net/url"
 "sort"
 "strconv"
 "crypto/sha256"
 "encoding/hex"
 "strings"
 "sync"
 "time"
 "unsafe"

 http2 "github.com/bogdanfinn/fhttp/http2"
 http "github.com/bogdanfinn/fhttp"
 "github.com/bogdanfinn/tls-client/profiles"
 src "github.com/bogdanfinn/tls-client/cffi_src"
 tls_client "github.com/bogdanfinn/tls-client"
 tls "github.com/bogdanfinn/utls"
 proxy "golang.org/x/net/proxy"
)

// ---------------------------------------------------------------------------
// https-proxy patch: upstream connect.go hardcodes proxy-TLS verification
// (no InsecureSkipVerify), so verify=false could never disable certificate
// checks against https:// proxies. We build the client ourselves with a
// dialer that honors InsecureSkipVerify for the proxy leg.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// extra TLS profiles absent from upstream MappedTLSClients (macOS Safari 17+,
// Edge, Tor). Built through the public NewClientProfile API with utls
// ClientHelloIDs; headers baselines live in the Python layer (profiles.py).
// ---------------------------------------------------------------------------

// h2Chromium: the HTTP/2 SETTINGS of a Chromium major version (captures of Chrome
// 99-152 and Opera 89-91 with --disable-field-trial-config, 2026-11-20):
// ENABLE_PUSH=0 from 107, MAX_CONCURRENT_STREAMS=1000 until 116.
func h2Chromium(major int) (map[http2.SettingID]uint32, []http2.SettingID, []string, uint32) {
 settings := map[http2.SettingID]uint32{
  http2.SettingHeaderTableSize:    65536,
  http2.SettingInitialWindowSize:  6291456,
  http2.SettingMaxHeaderListSize:  262144,
 }
 order := []http2.SettingID{http2.SettingHeaderTableSize}
 if major >= 107 {
  settings[http2.SettingEnablePush] = 0
  order = append(order, http2.SettingEnablePush)
 }
 if major < 117 {
  settings[http2.SettingMaxConcurrentStreams] = 1000
  order = append(order, http2.SettingMaxConcurrentStreams)
 }
 order = append(order, http2.SettingInitialWindowSize, http2.SettingMaxHeaderListSize)
 pseudo := []string{":method", ":authority", ":scheme", ":path"}
 return settings, order, pseudo, 15663105
}

func h2Safari() (map[http2.SettingID]uint32, []http2.SettingID, []string, uint32) {
 settings := map[http2.SettingID]uint32{
  http2.SettingInitialWindowSize:    4194304,
  http2.SettingMaxConcurrentStreams: 100,
 }
 order := []http2.SettingID{
  http2.SettingInitialWindowSize,
  http2.SettingMaxConcurrentStreams,
 }
 pseudo := []string{":method", ":scheme", ":path", ":authority"}
 return settings, order, pseudo, 10485760
}

func h2Firefox() (map[http2.SettingID]uint32, []http2.SettingID, []string, uint32) {
 settings := map[http2.SettingID]uint32{
  http2.SettingHeaderTableSize:      65536,
  http2.SettingEnablePush:           0,
  http2.SettingInitialWindowSize:    131072,
  http2.SettingMaxFrameSize:         16384,
 }
 order := []http2.SettingID{
  http2.SettingHeaderTableSize,
  http2.SettingEnablePush,
  http2.SettingInitialWindowSize,
  http2.SettingMaxFrameSize,
 }
 pseudo := []string{":method", ":path", ":authority", ":scheme"}
 return settings, order, pseudo, 12517377
}

func profileFromH2(id tls.ClientHelloID, family string) profiles.ClientProfile {
 var settings map[http2.SettingID]uint32
 var order []http2.SettingID
 var pseudo []string
 var flow uint32
 switch family {
 case "safari":
  settings, order, pseudo, flow = h2Safari()
 default:
  settings, order, pseudo, flow = h2Firefox()
 }
 return profiles.NewClientProfile(id, settings, order, pseudo, flow, nil, nil, 0, false, nil, nil, 0, nil, false)
}

// firefoxESR128Profile: Tor Browser 14 = Firefox ESR 128, whose HTTP/2 preface
// (capture of Firefox 128.0, 2026-11-20) has NO_RFC7540_PRIORITIES and no
// ENABLE_PUSH, and HEADERS with a non-exclusive weight-42 dependency on stream 0.
func firefoxESR128Profile(id tls.ClientHelloID) profiles.ClientProfile {
 settings := map[http2.SettingID]uint32{
  http2.SettingHeaderTableSize:      65536,
  http2.SettingInitialWindowSize:    131072,
  http2.SettingMaxFrameSize:         16384,
  http2.SettingNoRFC7540Priorities:  1,
 }
 order := []http2.SettingID{http2.SettingHeaderTableSize, http2.SettingInitialWindowSize,
  http2.SettingMaxFrameSize, http2.SettingNoRFC7540Priorities}
 return profiles.NewClientProfile(id, settings, order, []string{":method", ":path", ":authority", ":scheme"},
  12517377, nil, &http2.PriorityParam{StreamDep: 0, Exclusive: false, Weight: 41}, 0, false, nil, nil, 0, nil, false)
}

// firefoxHeaderPriority: Firefox 128+ sends HEADERS with a non-exclusive weight-42
// dependency on stream 0 (captures of Firefox 128-148); upstream's firefox_132,
// _133 and _135 send Chrome's exclusive weight 256.
var firefoxHeaderPriority = map[string]bool{"firefox_132": true, "firefox_133": true, "firefox_135": true}

// chromiumProfile: a Chromium-based browser (Edge) of the given major version.
// HEADERS carry Chrome's priority (exclusive, weight 256) as in the captures.
func chromiumProfile(id tls.ClientHelloID, major int) profiles.ClientProfile {
 settings, order, pseudo, flow := h2Chromium(major)
 return profiles.NewClientProfile(id, settings, order, pseudo, flow, nil,
  &http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 255}, 0, false, nil, nil, 0, nil, false)
}

// conscryptOkhttpProfile: wire-accurate Android app hello (okhttp over
// platform Conscrypt, TLS 1.3). 15 ciphers in Conscrypt's wire order (TLS1.3,
// then ECDHE-ECDSA AES128/AES256/CHACHA, then ECDHE-RSA AES128/AES256/CHACHA,
// RSA CBC/GCM fallback; JA3 f79b6bad2ad0641e1921aef10262856b, cipher-hash
// 8daaf6152771), 13 extensions — the 13th is the
// padding extension (21): Conscrypt pads the ClientHello to exactly 512
// handshake bytes (BoringPaddingStyle), without it JA4 reads t13d1512h2
// instead of the phone's t13d1513h2. No GREASE at all: groups 29-23-24,
// key share X25519 only, sig_algs without the iOS duplicate.
func conscryptOkhttpProfile() profiles.ClientProfile {
 ciphers := []uint16{
  0x1301, 0x1302, 0x1303, // TLS 1.3
  0xC02B, 0xC02C, 0xCCA9, // ECDHE-ECDSA AES128-GCM, AES256-GCM, CHACHA20
  0xC02F, 0xC030, 0xCCA8, // ECDHE-RSA   AES128-GCM, AES256-GCM, CHACHA20
  0xC013, 0xC014, // ECDHE RSA AES128/256 CBC
  0x009C, 0x009D, // RSA AES128/256 GCM
  0x002F, 0x0035, // RSA AES128/256 CBC fallback
 }
 // built per handshake: utls mutates extension objects (key share bytes,
 // padding length) during ApplyPreset; sharing them across connections leaks
 // one handshake's state into the next (same bug class as the 0.4.3 ja3 fix)
 newExtensions := func() []tls.TLSExtension { return []tls.TLSExtension{
  &tls.SNIExtension{},
  &tls.ExtendedMasterSecretExtension{},
  &tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
  &tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}},
  &tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
  &tls.SessionTicketExtension{},
  &tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
  &tls.StatusRequestExtension{},
  &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
   0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
  }},
  &tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}},
  &tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
  &tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
  &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
  // pre_shared_key (41) must stay last. Empty (omitted) on a fresh handshake;
  // on resumption with a cached TLS 1.3 ticket it carries the PSK, as the
  // phone's resumed hello does (51,45,43,…,41)
  &tls.UtlsPreSharedKeyExtension{},
 }}
 // okhttp4 Http2Connection: SETTINGS carries only INITIAL_WINDOW_SIZE=16 MiB,
 // then a connection WINDOW_UPDATE of 16 MiB - 65535; Http2ExchangeCodec writes
 // :method, :path, :authority, :scheme and HEADERS without a priority block.
 // Akamai: 4:16777216|16711681|0|m,p,a,s (same as upstream okhttp4_android_*).
 // The first request goes on stream 3: okhttp reserves stream 1 for clients
 // that upgrade from HTTP/1.1 (Http2Connection.nextStreamId = 3).
 settings := map[http2.SettingID]uint32{
  http2.SettingInitialWindowSize: 16777216,
 }
 order := []http2.SettingID{
  http2.SettingInitialWindowSize,
 }
 pseudo := []string{":method", ":path", ":authority", ":scheme"}
 helloID := tls.ClientHelloID{
  Client: "Conscrypt", Version: "android",
  SpecFactory: func() (tls.ClientHelloSpec, error) {
   return tls.ClientHelloSpec{
    CipherSuites:       append([]uint16(nil), ciphers...),
    CompressionMethods: []byte{tls.CompressionNone},
    Extensions:         newExtensions(),
    GetSessionID:       sha256.Sum256,
   }, nil
  },
 }
 return profiles.NewClientProfile(helloID, settings, order, pseudo, 16711681, nil, &http2.PriorityParam{}, 3, false, nil, nil, 0, nil, false)
}

var extraProfiles = map[string]profiles.ClientProfile{
 "conscrypt_android_latest": conscryptOkhttpProfile(),
 "okhttp4_conscrypt":        conscryptOkhttpProfile(),
 // Edge (Chromium TLS stack): edge_99/edge_101 mirror curl_cffi names, edge_131 is current
 "edge_99":     chromiumProfile(tls.HelloChrome_100, 99),
 "edge_101":    chromiumProfile(tls.HelloChrome_110, 101),
 "edge_131":    chromiumProfile(tls.HelloChrome_131, 131),
 "edge_latest": chromiumProfile(tls.HelloChrome_131, 131),
 // Tor Browser 14+ (Firefox ESR 128 TLS stack, stable since FF110)
 "tor_145": firefoxESR128Profile(tls.HelloFirefox_120),
 // macOS Safari desktop: Apple keeps the TLS ClientHello stable across 16/17/18/26;
 // utls HelloSafari_16_0 is the real, current Apple TLS stack
 "safari_macos_17_0": profileFromH2(tls.HelloSafari_16_0, "safari"),
 "safari_macos_18_0": profileFromH2(tls.HelloSafari_16_0, "safari"),
 "safari_macos_26_0": profileFromH2(tls.HelloSafari_16_0, "safari"),
}

// shufflesExtensions: only Chromium (Chrome/Brave/Opera/Edge) randomizes the
// ClientHello extension order. Every other stack — Conscrypt/okhttp, Apple
// CFNetwork/Safari, Firefox/Tor, the upstream mobile-app captures — sends a fixed
// order, so the session-level random_tls_extension_order (Python default True)
// is ignored for them; otherwise the order on the wire is not the client's.
func shufflesExtensions(identifier string) bool {
 for _, p := range []string{"chrome_", "brave_", "opera_", "edge_"} {
  if strings.HasPrefix(identifier, p) { return true }
 }
 return false
}

func lookupExtraProfile(name string) (profiles.ClientProfile, bool) {
 p, ok := extraProfiles[name]
 return p, ok
}

// resolveProfile: mapped upstream profile, else extra profile, else upstream's
// default (Chrome), with spec consistency fixes applied (cached per name).
func resolveProfile(name string) profiles.ClientProfile {
 if v, ok := fixedProfiles.Load(name); ok { return v.(profiles.ClientProfile) }
 p, ok := profiles.MappedTLSClients[name]
 if !ok {
  if ep, isExtra := lookupExtraProfile(name); isExtra { p = ep } else { p = profiles.DefaultClientProfile }
 }
 if firefoxHeaderPriority[name] {
  p = profiles.NewClientProfile(p.GetClientHelloId(), p.GetSettings(), p.GetSettingsOrder(), p.GetPseudoHeaderOrder(),
   p.GetConnectionFlow(), p.GetPriorities(), &http2.PriorityParam{StreamDep: 0, Exclusive: false, Weight: 41},
   p.GetStreamID(), p.GetAllowHTTP(), p.GetHttp3Settings(), p.GetHttp3SettingsOrder(), p.GetHttp3PriorityParam(),
   p.GetHttp3PseudoHeaderOrder(), p.GetHttp3SendGreaseFrames())
 }
 if spec, err := p.GetClientHelloSpec(); err == nil && fixKeyShares(&spec) {
  id := p.GetClientHelloId()
  orig := id.SpecFactory
  id.SpecFactory = func() (tls.ClientHelloSpec, error) {
   s, err := orig()
   if err == nil { fixKeyShares(&s) }
   return s, err
  }
  p = profiles.NewClientProfile(id, p.GetSettings(), p.GetSettingsOrder(), p.GetPseudoHeaderOrder(),
   p.GetConnectionFlow(), p.GetPriorities(), p.GetHeaderPriority(), p.GetStreamID(), p.GetAllowHTTP(),
   p.GetHttp3Settings(), p.GetHttp3SettingsOrder(), p.GetHttp3PriorityParam(), p.GetHttp3PseudoHeaderOrder(),
   p.GetHttp3SendGreaseFrames())
 }
 if c := h3CaptureFor(name); c != nil {
  if hp, err := applyH3Capture(p, c); err == nil { p = hp }
 }
 fixedProfiles.Store(name, p)
 return p
}

var fixedProfiles sync.Map

// fixKeyShares: every key share must belong to an offered group (RFC 8446
// 4.2.8). Upstream's nike_android_mobile sends a GREASE key share without a
// GREASE supported group, which OpenSSL servers (nginx, Apache, HAProxy)
// reject with illegal_parameter; the share is dropped (JA3/JA4 unchanged).
func fixKeyShares(spec *tls.ClientHelloSpec) bool {
 var curves *tls.SupportedCurvesExtension
 var shares *tls.KeyShareExtension
 for _, e := range spec.Extensions {
  switch x := e.(type) {
  case *tls.SupportedCurvesExtension:
   curves = x
  case *tls.KeyShareExtension:
   shares = x
  }
 }
 if curves == nil || shares == nil { return false }
 for _, c := range curves.Curves {
  if isGREASEU16(uint16(c)) { return false }
 }
 kept := make([]tls.KeyShare, 0, len(shares.KeyShares))
 for _, k := range shares.KeyShares {
  if !isGREASEU16(uint16(k.Group)) { kept = append(kept, k) }
 }
 if len(kept) == len(shares.KeyShares) { return false }
 shares.KeyShares = kept
 return true
}

// ---------------------------------------------------------------------------
// advanced ClientHello controls: tlsExtensionOrder / grease / pskMode /
// echConfigList / udpProxyUrl, and per-request JA3/JA4/Akamai fingerprint.
// Built on the public tls_client.GetSpecFactoryFromJa3String API so upstream
// ja3 parsing is reused, then the spec is adjusted and a ClientProfile is
// rebuilt through profiles.NewClientProfile.
// ---------------------------------------------------------------------------

type advancedTls struct {
 extOrder      []int
 echConfigList []byte
 grease        *bool
 pskMode       string
 // chromeDefaults: profile whose values fill what the custom JA3 leaves open
 // (fill_custom_with_chrome_defaults=True), "" = generic values only
 chromeDefaults string
 // trustAnchors: data of the trust_anchors extension (0xca34), trust_anchors_payload
 trustAnchors []byte
}

// decodeAdvancedTls reads the extra fields straight from the raw payload JSON
// (upstream CustomTlsClient has no such fields; adding them to the vendored
// package is not possible).
func decodeAdvancedTls(rawPayload []byte) *advancedTls {
 var envelope struct {
  CustomTlsClient *struct {
   TLSExtensionOrder []int  `json:"tlsExtensionOrder"`
   ECHConfigListB64  string `json:"echConfigList"`
   Grease            *bool  `json:"grease"`
   PskMode           string `json:"pskMode"`
   ChromeDefaults    string `json:"chromeDefaultsProfile"`
   TrustAnchors      string `json:"trustAnchorsPayload"`
  } `json:"customTlsClient"`
 }
 if err := json.Unmarshal(rawPayload, &envelope); err != nil || envelope.CustomTlsClient == nil {
  return nil
 }
 c := envelope.CustomTlsClient
 a := &advancedTls{}
 if len(c.TLSExtensionOrder) > 0 { a.extOrder = c.TLSExtensionOrder }
 if c.ECHConfigListB64 != "" {
  if raw, err := base64.StdEncoding.DecodeString(c.ECHConfigListB64); err == nil { a.echConfigList = raw }
 }
 if c.Grease != nil { a.grease = c.Grease }
 if c.PskMode != "" { a.pskMode = c.PskMode }
 a.chromeDefaults = c.ChromeDefaults
 if c.TrustAnchors != "" {
  if raw, err := hex.DecodeString(c.TrustAnchors); err == nil { a.trustAnchors = raw }
 }
 return a
}

// applyTrustAnchors sets the trust_anchors extension (0xca34) data given with
// trust_anchors_payload; without it the extension keeps Chrome's list (fill) or
// an empty one.
func applyTrustAnchors(spec *tls.ClientHelloSpec, data []byte) {
 if data == nil { return }
 for _, e := range spec.Extensions {
  if g, ok := e.(*tls.GenericExtension); ok && g.Id == extTrustAnchors {
   g.Data = append([]byte(nil), data...)
  }
 }
}

func applyGrease(spec *tls.ClientHelloSpec, enabled bool) {
 // Ciphers: strip existing GREASE; when enabled, one GREASE cipher goes FIRST.
 kept := make([]uint16, 0, len(spec.CipherSuites))
 for _, c := range spec.CipherSuites {
  if (c&0x0F0F) == 0x0A0A { continue }
  kept = append(kept, c)
 }
 if enabled {
  kept = append([]uint16{tls.GREASE_PLACEHOLDER}, kept...)
 }
 spec.CipherSuites = kept

 // Extensions: strip existing GREASE exts; when enabled, iOS CFNetwork structure:
 //   [0] GREASE ext with EMPTY content (before SNI/0x0000)
 //   [last] GREASE ext with 1 byte 0x00
 // utls ApplyPreset fills them: first -> Value=grease1 (Body empty),
 // second -> Value=grease2 AND Body=0x00 (grease_extensions_seen switch).
 filtered := make([]tls.TLSExtension, 0, len(spec.Extensions)+2)
 for _, e := range spec.Extensions {
  if _, ok := e.(*tls.UtlsGREASEExtension); ok { continue }
  if gen, ok := e.(*tls.GenericExtension); ok && (gen.Id&0x0F0F) == 0x0A0A { continue }
  filtered = append(filtered, e)
 }
 if enabled {
  withGrease := make([]tls.TLSExtension, 0, len(filtered)+2)
  withGrease = append(withGrease, &tls.UtlsGREASEExtension{}) // leading, empty content
  withGrease = append(withGrease, filtered...)
  withGrease = append(withGrease, &tls.UtlsGREASEExtension{}) // trailing, utls sets Body=0x00
  filtered = withGrease
 }
 spec.Extensions = filtered

 // Per-extension GREASE slots (ApplyPreset substitutes boring-GREASE values;
 // the GREASE key-share entry skips key generation, keeping Data=0x00, len=1).
 for _, e := range spec.Extensions {
  switch t := e.(type) {
  case *tls.SupportedCurvesExtension:
   if enabled {
    if len(t.Curves) == 0 || !isGREASEU16(uint16(t.Curves[0])) {
     t.Curves = append([]tls.CurveID{tls.GREASE_PLACEHOLDER}, t.Curves...)
    }
   } else {
    t.Curves = filterGreaseGroups(t.Curves)
   }
  case *tls.KeyShareExtension:
   if enabled {
    if len(t.KeyShares) == 0 || !isGREASEU16(uint16(t.KeyShares[0].Group)) {
     t.KeyShares = append([]tls.KeyShare{{Group: tls.GREASE_PLACEHOLDER, Data: []byte{0}}}, t.KeyShares...)
    }
   } else {
    keptShares := t.KeyShares[:0]
    for _, k := range t.KeyShares {
     if isGREASEU16(uint16(k.Group)) { continue }
     keptShares = append(keptShares, k)
    }
    t.KeyShares = keptShares
   }
  case *tls.SupportedVersionsExtension:
   if enabled {
    if len(t.Versions) == 0 || !isGREASEU16(uint16(t.Versions[0])) {
     t.Versions = append([]uint16{tls.GREASE_PLACEHOLDER}, t.Versions...)
    }
   } else {
    keptVers := t.Versions[:0]
    for _, v := range t.Versions {
     if isGREASEU16(v) { continue }
     keptVers = append(keptVers, v)
    }
    t.Versions = keptVers
   }
  }
 }
}

func filterGreaseGroups(curves []tls.CurveID) []tls.CurveID {
 out := curves[:0]
 for _, c := range curves {
  if isGREASEU16(uint16(c)) { continue }
  out = append(out, c)
 }
 return out
}

func applyPskMode(spec *tls.ClientHelloSpec, mode string) {
 pskCiphers := map[uint16]bool{
  0x1301 - 0x100: true, // placeholder, replaced below with real PSK suites
 }
 // TLS 1.3 PSK-only suites per rfc8446 appendix: psk_ke / psk_dhe_ke are modes,
 // not ciphers; PSK shows up via ext 45 + pre-shared key. What changes CH-wise:
 // ext 45 present (psk) or absent (no_psk); also drop resumption ticket ext for no_psk.
 filtered := make([]tls.TLSExtension, 0, len(spec.Extensions))
 for _, e := range spec.Extensions {
  if _, ok := e.(*tls.PSKKeyExchangeModesExtension); ok {
   if mode == "no_psk" { continue }
  }
  if u, ok := e.(*tls.GenericExtension); ok && u.Id == 41 && mode == "no_psk" {
   continue // pre_shared_key ext
  }
  filtered = append(filtered, e)
 }
 if mode == "psk" {
  hasPsk := false
  for _, e := range filtered {
   if _, ok := e.(*tls.PSKKeyExchangeModesExtension); ok { hasPsk = true; break }
  }
  if !hasPsk {
   filtered = append(filtered, &tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}})
  }
 }
 _ = pskCiphers
 spec.Extensions = filtered
}

// udpProxyFrom: udp_proxy — HTTP/3 (QUIC) goes through this SOCKS5 proxy and TCP through
// `proxy`. Before 0.8.1 the custom-JA3 builder let it replace the TCP proxy too and the
// profile builder ignored it.
func udpProxyFrom(rawPayload []byte) string {
 var env struct {
  UDPProxyUrl string `json:"udpProxyUrl"`
 }
 if json.Unmarshal(rawPayload, &env) != nil { return "" }
 return env.UDPProxyUrl
}

func extensionID(e tls.TLSExtension) uint16 {
 // ids as on the wire; ECH, old ALPS, NPN and pre_shared_key were wrong or missing
 // before 0.8.1, so tls_extension_order put those extensions at the end
 switch t := e.(type) {
 case *tls.SNIExtension: return 0
 case *tls.StatusRequestExtension: return 5
 case *tls.SupportedCurvesExtension: return 10
 case *tls.SupportedPointsExtension: return 11
 case *tls.SignatureAlgorithmsExtension: return 13
 case *tls.ALPNExtension: return 16
 case *tls.StatusRequestV2Extension: return 17
 case *tls.SCTExtension: return 18
 case *tls.UtlsPaddingExtension: return 21
 case *tls.UtlsExtendedMasterSecretExtension: return 23
 case *tls.FakeTokenBindingExtension: return 24
 case *tls.UtlsCompressCertExtension: return 27
 case *tls.FakeRecordSizeLimitExtension: return 28
 case *tls.FakeDelegatedCredentialsExtension: return 34
 case *tls.SessionTicketExtension: return 35
 case *tls.UtlsPreSharedKeyExtension, *tls.FakePreSharedKeyExtension: return 41
 case *tls.SupportedVersionsExtension: return 43
 case *tls.CookieExtension: return 44
 case *tls.PSKKeyExchangeModesExtension: return 45
 case *tls.SignatureAlgorithmsCertExtension: return 50
 case *tls.KeyShareExtension: return 51
 case *tls.QUICTransportParametersExtension: return 57
 case *tls.NPNExtension: return 13172
 case *tls.ApplicationSettingsExtension: return 17513
 case *tls.ApplicationSettingsExtensionNew: return 17613
 case *tls.FakeChannelIDExtension:
  if t.OldExtensionID { return 30031 }
  return 30032
 case tls.EncryptedClientHelloExtension: return 0xfe0d
 case *tls.RenegotiationInfoExtension: return 65281
 case *tls.UtlsGREASEExtension: return tls.GREASE_PLACEHOLDER
 case *tls.GenericExtension: return t.Id
 }
 return 0xFFFF
}

func applyExtensionOrder(spec *tls.ClientHelloSpec, order []int) {
 if len(order) == 0 { return }
 rank := map[uint16]int{}
 for i, id := range order { rank[uint16(id)] = i }
 type pair struct {
  rank int
  ext  tls.TLSExtension
 }
 var ordered []pair
 rest := make([]tls.TLSExtension, 0, len(spec.Extensions))
 for _, e := range spec.Extensions {
  if r, ok := rank[extensionID(e)]; ok { ordered = append(ordered, pair{r, e}) } else { rest = append(rest, e) }
 }
 sort.Slice(ordered, func(i, j int) bool { return ordered[i].rank < ordered[j].rank })
 keyed := make([]tls.TLSExtension, 0, len(spec.Extensions))
 for _, p := range ordered { keyed = append(keyed, p.ext) }
 keyed = append(keyed, rest...)
 spec.Extensions = keyed
}

// ja3/ja4 live in wire.go (helloFields): one implementation for wire bytes
// and for the configured spec.

// settingIDNum: the SETTINGS identifier on the wire (fhttp's SettingID values are the
// RFC 9113 codes); unknown ones such as NO_RFC7540_PRIORITIES (9) printed as 0 before.
func settingIDNum(s http2.SettingID) uint16 { return uint16(s) }

func akamaiFromSpec(settings map[http2.SettingID]uint32, order []http2.SettingID,
 pseudo []string, flow uint32, priorities []http2.Priority) string {
 // canonical Akamai fingerprint: SETTINGS in send order (id:value, ';'),
 // then |<connection window increment>|<headers priority?>|, then pseudo order letters
 parts := []string{}
 for _, sid := range order {
  if v, ok := settings[sid]; ok { parts = append(parts, fmt.Sprintf("%d:%d", settingIDNum(sid), v)) }
 }
 if len(parts) == 0 { return "" }
 fp := strings.Join(parts, ";")
 fp += "|" + fmt.Sprintf("%d", flow)
 // PRIORITY frames sent after the preface: stream:exclusive:dependency:weight
 // (weight as on the wire plus one, 1-256), "0" when none
 if len(priorities) == 0 {
  fp += "|0"
 } else {
  frames := make([]string, 0, len(priorities))
  for _, p := range priorities {
   excl := 0
   if p.PriorityParam.Exclusive { excl = 1 }
   frames = append(frames, fmt.Sprintf("%d:%d:%d:%d", p.StreamID, excl, p.PriorityParam.StreamDep, int(p.PriorityParam.Weight)+1))
  }
  fp += "|" + strings.Join(frames, ",")
 }
 letters := map[string]string{":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}
 pseudoParts := []string{}
 for _, p := range pseudo {
  if letter, ok := letters[p]; ok { pseudoParts = append(pseudoParts, letter) } else { pseudoParts = append(pseudoParts, p) }
 }
 fp += "|" + strings.Join(pseudoParts, ",")
 return fp
}

func fingerprintFromSpec(spec *tls.ClientHelloSpec, settings map[http2.SettingID]uint32,
 settingsOrder []http2.SettingID, pseudo []string, flow uint32, priorities []http2.Priority) map[string]any {
 akamai := akamaiFromSpec(settings, settingsOrder, pseudo, flow, priorities)
 out := fieldsFromSpec(spec).report()
 out["akamai_fingerprint"] = akamai
 out["akamai_hash_sha256_96"] = hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte(akamai)); return s[:12] }())
 return out
}

func ensureSupportedVersions(spec *tls.ClientHelloSpec) {
 for _, e := range spec.Extensions {
  if sv, ok := e.(*tls.SupportedVersionsExtension); ok {
   if len(sv.Versions) == 0 {
    sv.Versions = []uint16{0x0304, 0x0303} // TLS 1.3, 1.2
   }
  }
 }
}

func isGREASEU16(v uint16) bool { return (v&0x0F0F) == 0x0A0A }

func ensureKeyShare(spec *tls.ClientHelloSpec) {
 for _, e := range spec.Extensions {
  if ks, ok := e.(*tls.KeyShareExtension); ok {
   if len(ks.KeyShares) > 0 { continue }
   // Derive shares from the DECLARED supported_groups so groups advertised in
   // the ja3 (e.g. 4588 X25519MLKEM768) actually carry key shares. Servers like
   // Cloudflare send HelloRetryRequest when a preferred advertised group has no
   // share, and the go-tls retry path then rejects the MLKEM curve.
   // utls generates the Data for X25519MLKEM768 (ML-KEM 1184b + X25519 32b),
   // Kyber drafts and classic curves during ApplyPreset.
   var groups []tls.CurveID
   for _, ce := range spec.Extensions {
    if sc, ok := ce.(*tls.SupportedCurvesExtension); ok {
     groups = append(groups, sc.Curves...)
    }
   }
   ks.KeyShares = defaultKeyShares(groups)
  }
 }
}

// defaultKeyShares: Chrome-style shares for the first two declared groups, plus
// X25519 when it is declared further down. Only declared groups get a share (a
// share for a group missing from supported_groups is illegal_parameter, RFC 8446
// 4.2.8), and a hybrid ML-KEM/Kyber share only together with X25519 (as Chrome;
// uTLS cannot complete a handshake on a hybrid share alone).
func defaultKeyShares(groups []tls.CurveID) []tls.KeyShare {
 declared := map[tls.CurveID]bool{}
 for _, g := range groups {
  declared[g] = true
 }
 hybrid := func(g tls.CurveID) bool { return g == tls.X25519MLKEM768 || g == tls.X25519Kyber768Draft00 }
 shares := make([]tls.KeyShare, 0, 3)
 shared := map[tls.CurveID]bool{}
 for _, g := range groups {
  if isGREASEU16(uint16(g)) || shared[g] || (hybrid(g) && !declared[tls.X25519]) {
   continue
  }
  shares = append(shares, tls.KeyShare{Group: g})
  shared[g] = true
  if len(shares) >= 2 {
   break
  }
 }
 if declared[tls.X25519] && !shared[tls.X25519] {
  shares = append(shares, tls.KeyShare{Group: tls.X25519})
 }
 if len(shares) == 0 { // no supported_groups (or only GREASE / hybrids): as before
  shares = []tls.KeyShare{{Group: tls.X25519}}
 }
 return shares
}

func ensureSignatureAlgorithms(spec *tls.ClientHelloSpec, explicit []string) {
 for _, e := range spec.Extensions {
  if sa, ok := e.(*tls.SignatureAlgorithmsExtension); ok {
   if len(sa.SupportedSignatureAlgorithms) == 0 {
    if mapped := mapSigAlgNames(explicit); len(mapped) > 0 {
     sa.SupportedSignatureAlgorithms = mapped
     continue
    }
    // CFNetwork/iOS 26 default set (ecdsa + rsa-pss + rsa-pkcs1)
    sa.SupportedSignatureAlgorithms = []tls.SignatureScheme{
     tls.ECDSAWithP256AndSHA256,
     tls.PSSWithSHA256,
     tls.PSSWithSHA384,
     tls.PSSWithSHA512,
     tls.PKCS1WithSHA256,
     tls.PKCS1WithSHA384,
     tls.PKCS1WithSHA512,
    }
   }
  }
 }
}

func mapSigAlgNames(names []string) []tls.SignatureScheme {
 out := make([]tls.SignatureScheme, 0, len(names))
 for _, n := range names {
  if v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(n, "0x"), "0X"), 16, 16); err == nil {
   out = append(out, tls.SignatureScheme(uint16(v)))
  }
 }
 return out
}

func ensureDelegatedCredentials(spec *tls.ClientHelloSpec, explicit []string) {
 for _, e := range spec.Extensions {
  if dc, ok := e.(*tls.DelegatedCredentialsExtension); ok {
   if len(dc.SupportedSignatureAlgorithms) == 0 {
    if mapped := mapSigAlgNames(explicit); len(mapped) > 0 {
     dc.SupportedSignatureAlgorithms = mapped
    } else {
     dc.SupportedSignatureAlgorithms = []tls.SignatureScheme{
      tls.ECDSAWithP256AndSHA256,
      tls.PSSWithSHA256,
      tls.PSSWithSHA384,
      tls.PSSWithSHA512,
      tls.PKCS1WithSHA256,
      tls.PKCS1WithSHA384,
      tls.PKCS1WithSHA512,
     }
    }
   }
  }
 }
}

func ensureCurves(spec *tls.ClientHelloSpec) {
 for _, e := range spec.Extensions {
  if sc, ok := e.(*tls.SupportedCurvesExtension); ok {
   if len(sc.Curves) == 0 {
    sc.Curves = []tls.CurveID{tls.X25519, 0x0017, 0x0018} // X25519, P-256, P-384
   }
  }
 }
}

// customJa3Profile: the ClientProfile of a ja3_string session and its spec
// builder; the configured fingerprint (fingerprintFromConfig) uses the same.
func customJa3Profile(in src.RequestInput, rawPayload []byte) (profiles.ClientProfile, func() (tls.ClientHelloSpec, error), *advancedTls, error) {
 ct := in.CustomTlsClient
 adv := decodeAdvancedTls(rawPayload)

 sigAlgs := ct.SupportedSignatureAlgorithms
 delegAlgs := ct.SupportedDelegatedCredentialsAlgorithms
 tlsVersions := ct.SupportedVersions
 keyShares := ct.KeyShareCurves
 var echSuites []tls_client.CandidateCipherSuites
 for _, s := range ct.ECHCandidateCipherSuites {
  echSuites = append(echSuites, tls_client.CandidateCipherSuites{KdfId: s.KdfId, AeadId: s.AeadId})
 }

 var ref *chromeReference
 if adv != nil { ref = newChromeReference(adv.chromeDefaults) }
 // extensions whose contents upstream cannot leave empty: compress_certificate
 // (upstream prints to stdout and rejects the ja3) and record_size_limit (0 is
 // invalid, RFC 8449 needs >= 64). brotli is what Chrome and Safari send,
 // 16385 what Firefox sends.
 declaredExts := ja3Extensions(ct.Ja3String)
 certAlgos := ct.CertCompressionAlgos
 if len(certAlgos) == 0 && declaredExts[tls.ExtensionCompressCertificate] { certAlgos = []string{"brotli"} }
 recordSizeLimit := ct.RecordSizeLimit
 if recordSizeLimit == 0 && declaredExts[tls.ExtensionRecordSizeLimit] { recordSizeLimit = 0x4001 }

 upstreamFactory, err := tls_client.GetSpecFactoryFromJa3String(ct.Ja3String, sigAlgs, delegAlgs, tlsVersions, keyShares, ct.ALPNProtocols, ct.ALPSProtocols, echSuites, ct.ECHCandidatePayloads, certAlgos, recordSizeLimit)
 if err != nil { return profiles.ClientProfile{}, nil, nil, fmt.Errorf("ja3 parse: %w", err) }

 // buildSpec runs for EVERY handshake: utls mutates extension objects during
 // ApplyPreset (key share bytes, GREASE values), and a shared spec object would
 // leak the first handshake's key share into the next host's handshake ->
 // 'local error: tls: internal error' on multi-host sessions.
 buildSpec := func() (tls.ClientHelloSpec, error) {
  spec, err := upstreamFactory()
  if err != nil { return tls.ClientHelloSpec{}, err }
  if ref != nil { ref.fillSpec(&spec) }

  // upstream leaves SupportedVersions nil when the ja3 lacks the versions field,
  // which utls then rejects; fill TLS 1.2+1.3 defaults when present but empty
  ensureSupportedVersions(&spec)
  ensureKeyShare(&spec)
  ensureSignatureAlgorithms(&spec, sigAlgs)
  ensureDelegatedCredentials(&spec, delegAlgs)
  ensureCurves(&spec)

  // ja3 that includes ext 16 with an empty ALPN list breaks servers; fill h2/http1.1
  for _, e := range spec.Extensions {
   if alpnExt, ok := e.(*tls.ALPNExtension); ok && len(alpnExt.AlpnProtocols) == 0 {
    alpnExt.AlpnProtocols = []string{"h2", "http/1.1"}
   }
  }

  if adv != nil {
   applyExtensionOrder(&spec, adv.extOrder)
   if adv.grease != nil { applyGrease(&spec, *adv.grease) }
   if adv.pskMode != "" { applyPskMode(&spec, adv.pskMode) }
   applyTrustAnchors(&spec, adv.trustAnchors)
  }
  applyKeyShareData(&spec, rawPayload)
  return spec, nil
 }
 // a ja3 the spec cannot be built from (an extension id without an implementation)
 // fails here, as a configuration error, instead of as an unknown ClientHelloID on
 // every handshake
 if _, err := buildSpec(); err != nil {
  return profiles.ClientProfile{}, nil, nil, fmt.Errorf("ja3_string: %w", err)
 }

 helloID := tls.ClientHelloID{
  Client: "Custom", Version: "ja3",
  SpecFactory: buildSpec,
 }
 h2Settings, h2Order := resolveH2Settings(ct)
 h2in := customH2Input{explicitSettings: len(ct.H2Settings) > 0, settings: h2Settings, order: h2Order,
  pseudo: ct.PseudoHeaderOrder, flow: ct.ConnectionFlow}
 // priority frames / HEADERS priority were dropped before 0.7.0
 for _, pf := range ct.PriorityFrames {
  h2in.priorities = append(h2in.priorities, http2.Priority{StreamID: pf.StreamID, PriorityParam: http2.PriorityParam{
   StreamDep: pf.PriorityParam.StreamDep, Exclusive: pf.PriorityParam.Exclusive, Weight: pf.PriorityParam.Weight}})
 }
 if ct.HeaderPriority != nil {
  h2in.headerPriority = &http2.PriorityParam{StreamDep: ct.HeaderPriority.StreamDep,
   Exclusive: ct.HeaderPriority.Exclusive, Weight: ct.HeaderPriority.Weight}
 }
 h2 := resolveCustomH2(h2in, ref)
 profile := profiles.NewClientProfile(helloID, h2.settings, h2.order, h2.pseudo, h2.flow, h2.priorities,
  h2.headerPriority, 0, false, h2.h3Settings, h2.h3Order, h2.h3Priority, h2.h3Pseudo, h2.h3Grease)
 if ref != nil && ref.profile.GetHTTP3Fingerprint() != nil {
  // filled from Chrome: HTTP/3 and QUIC look like that Chrome's too
  profile = profile.WithHTTP3Fingerprint(ref.profile.GetHTTP3Fingerprint())
 }
 return profile, buildSpec, adv, nil
}

func buildJa3Client(in src.RequestInput, rawPayload []byte, sessionId string) (tls_client.HttpClient, string, bool, *src.TLSClientError) {
 if sessionId == "" { sessionId = fmt.Sprintf("%d", time.Now().UnixNano()) }

 patchedSessions.Lock()
 if existing, ok := patchedSessions.m[sessionId]; ok {
  patchedSessions.Unlock()
  if setter, ok := existing.(interface{ SetFollowRedirect(bool) }); ok { setter.SetFollowRedirect(in.FollowRedirects) }
  return existing, sessionId, true, nil
 }
 patchedSessions.Unlock()

 profile, _, adv, perr := customJa3Profile(in, rawPayload)
 if perr != nil { return nil, sessionId, false, src.NewTLSClientError(perr) }

 timeoutMs := in.TimeoutMilliseconds
 if timeoutMs == 0 && in.TimeoutSeconds != 0 { timeoutMs = in.TimeoutSeconds * 1000 }
 if timeoutMs == 0 { timeoutMs = 30000 }

 extras := decodeSessionExtras(rawPayload)
 keepAlpn := extras.KeepAlpn && in.ForceHttp1
 options := []tls_client.HttpClientOption{
  tls_client.WithClientProfile(profile),
  tls_client.WithTimeoutMilliseconds(timeoutMs),
  tls_client.WithCookieJar(tls_client.NewCookieJar()),
 }
 var transportOpts *tls_client.TransportOptions
 if extras.okhttp() { transportOpts = okhttpTransportOptions() }
 if adv != nil && len(adv.echConfigList) > 0 {
  // ech_config_list: real ECH over TCP (utls encrypts the inner ClientHello into the
  // profile's ECH extension); it used to be parsed and dropped
  if transportOpts == nil { transportOpts = &tls_client.TransportOptions{} }
  transportOpts.EncryptedClientHelloConfigList = adv.echConfigList
 }
 if transportOpts != nil { options = append(options, tls_client.WithTransportOptions(transportOpts)) }
 // explicit tls_extension_order wins over shuffle: CFNetwork/iOS sends a fixed
 // extension order, and ShuffleChromeTLSExtensions would randomize it
 shuffle := in.WithRandomTLSExtensionOrder && (adv == nil || len(adv.extOrder) == 0)
 if shuffle {
  options = append(options, tls_client.WithRandomTLSExtensionOrder())
 }
 // keep_alpn: the hello keeps its ALPN list, HTTP/1.1 is enforced by the strict transport
 if in.ForceHttp1 && !keepAlpn { options = append(options, tls_client.WithForceHttp1()) }
 if wantsNoSessionTickets(rawPayload) { options = append(options, tls_client.WithDisableSessionTickets()) }
 if in.DisableHttp3 { options = append(options, tls_client.WithDisableHttp3()) }
 if in.WithProtocolRacing {
  // the QUIC hello is the inherited browser capture (fill) or quic-go's own; neither
  // takes the JA3's curve list, so X25519MLKEM768 in the JA3 no longer rules HTTP/3 out
  // (before 0.8.1 such a session silently stayed on TCP)
  options = append(options, tls_client.WithProtocolRacing())
 }
 if !in.FollowRedirects { options = append(options, tls_client.WithNotFollowRedirects()) }
 if in.InsecureSkipVerify { options = append(options, tls_client.WithInsecureSkipVerify()) }
 if in.ServerNameOverwrite != nil && *in.ServerNameOverwrite != "" {
  options = append(options, tls_client.WithServerNameOverwrite(*in.ServerNameOverwrite))
 }
 var localAddr *net.TCPAddr
 if in.LocalAddress != nil {
  la, resolveErr := net.ResolveTCPAddr("", *in.LocalAddress)
  if resolveErr != nil { return nil, sessionId, false, src.NewTLSClientError(resolveErr) }
  localAddr = la
  options = append(options, tls_client.WithLocalAddr(*localAddr))
 }
 proxyUrl := ""
 if in.ProxyUrl != nil { proxyUrl = *in.ProxyUrl }
 udpProxyUrl := udpProxyFrom(rawPayload)
 if udpProxyUrl != "" && keepAlpn {
  return nil, sessionId, false, src.NewTLSClientError(fmt.Errorf("keep_alpn cannot be combined with udp_proxy"))
 }

 sink := &helloSink{}
 captured := false
 var sessionDialer proxy.ContextDialer
 // racing keeps the upstream proxy URL so HTTP/3 can tunnel through a SOCKS5 proxy;
 // with a separate udp_proxy the TCP side can use our own dialers
 keepUpstream := in.WithProtocolRacing && udpProxyUrl == ""
 dialOpts, d, dialErr := transportDialOptions(proxyUrl, timeoutMs, localAddr, keepUpstream, sink)
 if dialErr != nil { return nil, sessionId, false, src.NewTLSClientError(dialErr) }
 options = append(options, dialOpts...)
 sessionDialer, captured = d, d != nil
 if udpProxyUrl != "" {
  options = append(options, tls_client.WithHTTP3ProxyUrl(udpProxyUrl))
 }

 client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
 if err != nil { return nil, sessionId, false, src.NewTLSClientError(err) }
 var strict *strictH1Config
 if keepAlpn {
  if sessionDialer == nil { return nil, sessionId, false, src.NewTLSClientError(fmt.Errorf("keep_alpn: no dialer for this proxy configuration")) }
  strict = &strictH1Config{dialer: sessionDialer, helloID: profile.GetClientHelloId(), shuffle: shuffle, disableHttp3: in.DisableHttp3,
   insecure: in.InsecureSkipVerify, noTickets: wantsNoSessionTickets(rawPayload)}
  if in.ServerNameOverwrite != nil { strict.serverName = *in.ServerNameOverwrite }
  if adv != nil { strict.ech = adv.echConfigList }
 }
 if layerErr := applySessionLayer(client, extras.okhttp(), strict, plainConfig{proxyUrl: proxyUrl, localAddr: localAddr, dialTimeout: time.Duration(timeoutMs) * time.Millisecond}); layerErr != nil { return nil, sessionId, false, src.NewTLSClientError(layerErr) }
 if captured { helloSinks.Store(client, sink) }

 return storePatchedSession(sessionId, client), sessionId, true, nil
}

// resolveH2Settings: explicit h2Settings win; otherwise a Chrome-like default is
// applied so the fingerprinted SETTINGS are actually what the transport sends.
func resolveH2Settings(ct *src.CustomTlsClient) (map[http2.SettingID]uint32, []http2.SettingID) {
 h2Settings := map[http2.SettingID]uint32{}
 var h2Order []http2.SettingID
 for name, v := range ct.H2Settings {
  if sid, ok := h2SettingByName(name); ok { h2Settings[sid] = uint32(v); h2Order = append(h2Order, sid) }
 }
 if len(ct.H2SettingsOrder) > 0 {
  h2Order = nil
  for _, name := range ct.H2SettingsOrder {
   if sid, ok := h2SettingByName(name); ok { h2Order = append(h2Order, sid) }
  }
 }
 if len(h2Settings) == 0 {
  h2Settings = map[http2.SettingID]uint32{
   http2.SettingHeaderTableSize:      65536,
   http2.SettingEnablePush:           0,
   http2.SettingMaxConcurrentStreams: 1000,
   http2.SettingInitialWindowSize:    6291456,
   http2.SettingMaxHeaderListSize:    262144,
  }
  h2Order = []http2.SettingID{
   http2.SettingHeaderTableSize,
   http2.SettingEnablePush,
   http2.SettingMaxConcurrentStreams,
   http2.SettingInitialWindowSize,
   http2.SettingMaxHeaderListSize,
  }
 }
 return h2Settings, h2Order
}

// applyKeyShareData: mimic path — pre-captured share bytes per curve group,
// overriding auto-generated ones ("To mimic it, fill the Data field manually").
func applyKeyShareData(spec *tls.ClientHelloSpec, rawPayload []byte) {
 var env struct {
  CustomTlsClient *struct {
   KeyShareData map[string]string `json:"keyShareData"`
  } `json:"customTlsClient"`
 }
 if err := json.Unmarshal(rawPayload, &env); err != nil || env.CustomTlsClient == nil { return }
 data := env.CustomTlsClient.KeyShareData
 if len(data) == 0 { return }
 for _, e := range spec.Extensions {
  ks, ok := e.(*tls.KeyShareExtension)
  if !ok { continue }
  for i := range ks.KeyShares {
   key := strconv.FormatUint(uint64(ks.KeyShares[i].Group), 10)
   if b64, ok := data[key]; ok {
    if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
     ks.KeyShares[i].Data = raw
    }
   }
  }
 }
}

// h2SettingByName: RFC 9113 names, upstream's UNKNOWN_SETTING_<id>, or the id itself
// (decimal or 0x hex), so any setting a client sends can be expressed (Firefox: 9)
func h2SettingByName(name string) (http2.SettingID, bool) {
 lower := strings.ToLower(strings.TrimSpace(name))
 switch lower {
 case "header_table_size": return http2.SettingHeaderTableSize, true
 case "enable_push": return http2.SettingEnablePush, true
 case "max_concurrent_streams": return http2.SettingMaxConcurrentStreams, true
 case "initial_window_size": return http2.SettingInitialWindowSize, true
 case "max_frame_size": return http2.SettingMaxFrameSize, true
 case "max_header_list_size": return http2.SettingMaxHeaderListSize, true
 case "enable_connect_protocol": return 0x8, true
 case "no_rfc7540_priorities": return 0x9, true
 }
 lower = strings.TrimPrefix(lower, "unknown_setting_")
 if id, err := strconv.ParseUint(lower, 0, 16); err == nil && id > 0 {
  return http2.SettingID(id), true
 }
 return 0, false
}

func parseHexU16(s string) uint16 {
 s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
 v, _ := strconv.ParseUint(s, 16, 16)
 return uint16(v)
}

// patched sessions: keyed like cffi's clients map so lifecycle stays identical
var patchedSessions = struct {
 sync.Mutex
 m map[string]tls_client.HttpClient
}{m: map[string]tls_client.HttpClient{}}

var upstreamLayerMu sync.Mutex

// upstreamClient: a session built by upstream code still gets the request control
// and http:// routes of ours (timeouts, per-request cookies, the session's proxy
// and dialer for http://, the profile on http->https hops); without them its
// http:// requests went through a bare client of their own.
func upstreamClient(in src.RequestInput, proxyUrl string) (tls_client.HttpClient, string, bool, *src.TLSClientError) {
 client, sessionId, withSession, cerr := src.CreateClient(in)
 if cerr != nil { return client, sessionId, withSession, cerr }
 upstreamLayerMu.Lock()
 defer upstreamLayerMu.Unlock()
 if _, done := clientTransport(client).(*hopTransport); done { return client, sessionId, withSession, nil }
 var localAddr *net.TCPAddr
 if in.LocalAddress != nil {
  la, err := net.ResolveTCPAddr("", *in.LocalAddress)
  if err != nil { return nil, sessionId, false, src.NewTLSClientError(err) }
  localAddr = la
 }
 timeoutMs := in.TimeoutMilliseconds
 if timeoutMs == 0 && in.TimeoutSeconds != 0 { timeoutMs = in.TimeoutSeconds * 1000 }
 if timeoutMs == 0 { timeoutMs = 30000 }
 if err := applySessionLayer(client, false, nil, plainConfig{proxyUrl: proxyUrl, localAddr: localAddr, dialTimeout: time.Duration(timeoutMs) * time.Millisecond}); err != nil {
  return nil, sessionId, false, src.NewTLSClientError(err)
 }
 return client, sessionId, withSession, nil
}

func createPatchedClient(in src.RequestInput, rawPayload []byte) (tls_client.HttpClient, string, bool, *src.TLSClientError) {
 proxyUrl := ""
 if in.ProxyUrl != nil { proxyUrl = *in.ProxyUrl }
 // ja3_string sessions route through our builder (advanced controls + fingerprint);
 // identifier sessions go through the manual builder so yumeclient_close can always
 // call CloseIdleConnections
 if in.CustomTlsClient != nil && in.CustomTlsClient.Ja3String != "" {
  sessionId := ""
  if in.SessionId != nil { sessionId = *in.SessionId }
  return buildJa3Client(in, rawPayload, sessionId)
 }
 // extra profiles (conscrypt/okhttp, edge, tor, safari_macos) MUST stay on the
 // manual builder: upstream CreateClient only knows profiles.MappedTLSClients and
 // silently falls back to DefaultClientProfile (Chrome) for unknown identifiers —
 // before 0.4.5 every extra profile went out on the wire as a Chrome hello.
 if in.TLSClientIdentifier == "" {
  return upstreamClient(in, proxyUrl)
 }
 sessionId := ""
 if in.SessionId != nil { sessionId = *in.SessionId }
 if sessionId == "" { sessionId = fmt.Sprintf("%d", time.Now().UnixNano()) }

 patchedSessions.Lock()
 if existing, ok := patchedSessions.m[sessionId]; ok {
  patchedSessions.Unlock()
  if setter, ok := existing.(interface{ SetFollowRedirect(bool) }); ok { setter.SetFollowRedirect(in.FollowRedirects) }
  return existing, sessionId, true, nil
 }
 patchedSessions.Unlock()

 profile := resolveProfile(in.TLSClientIdentifier)

 timeoutMs := in.TimeoutMilliseconds
 if timeoutMs == 0 && in.TimeoutSeconds != 0 { timeoutMs = in.TimeoutSeconds * 1000 }
 if timeoutMs == 0 { timeoutMs = 30000 }

 // the proxy leg is deliberately never certificate-verified: the operator picks
 // the proxy, and https:// proxies in the wild (IP hosts, self-signed/domain certs
 // without IP SANs) fail strict verification — every practical TLS client defaults
 // to lenient proxy TLS. Target verification is still governed by InsecureSkipVerify.
 extras := decodeSessionExtras(rawPayload)
 keepAlpn := extras.KeepAlpn && in.ForceHttp1
 options := []tls_client.HttpClientOption{
  tls_client.WithClientProfile(profile),
  tls_client.WithTimeoutMilliseconds(timeoutMs),
  tls_client.WithCookieJar(tls_client.NewCookieJar()),
 }
 if extras.okhttp() { options = append(options, tls_client.WithTransportOptions(okhttpTransportOptions())) }
 var localAddr *net.TCPAddr
 if in.LocalAddress != nil {
  la, resolveErr := net.ResolveTCPAddr("", *in.LocalAddress)
  if resolveErr != nil { return nil, sessionId, false, src.NewTLSClientError(resolveErr) }
  localAddr = la
 }
 sink := &helloSink{}
 udpProxyUrl := udpProxyFrom(rawPayload)
 // named profiles ignored udp_proxy before 0.8.1
 dialOpts, sessionDialer, dialErr := transportDialOptions(proxyUrl, timeoutMs, localAddr,
  in.WithProtocolRacing && udpProxyUrl == "", sink)
 if dialErr != nil { return nil, sessionId, false, src.NewTLSClientError(dialErr) }
 captured := sessionDialer != nil
 options = append(options, dialOpts...)
 if udpProxyUrl != "" { options = append(options, tls_client.WithHTTP3ProxyUrl(udpProxyUrl)) }
 shuffle := in.WithRandomTLSExtensionOrder && shufflesExtensions(in.TLSClientIdentifier)
 if shuffle {
  options = append(options, tls_client.WithRandomTLSExtensionOrder())
 }
 // keep_alpn: the hello keeps its ALPN list, HTTP/1.1 is enforced by the strict transport
 if in.ForceHttp1 && !keepAlpn { options = append(options, tls_client.WithForceHttp1()) }
 if wantsNoSessionTickets(rawPayload) { options = append(options, tls_client.WithDisableSessionTickets()) }
 if in.DisableHttp3 { options = append(options, tls_client.WithDisableHttp3()) }
 if in.WithProtocolRacing { options = append(options, tls_client.WithProtocolRacing()) }
 if !in.FollowRedirects { options = append(options, tls_client.WithNotFollowRedirects()) }
 if in.InsecureSkipVerify { options = append(options, tls_client.WithInsecureSkipVerify()) }
 if in.ServerNameOverwrite != nil && *in.ServerNameOverwrite != "" {
  options = append(options, tls_client.WithServerNameOverwrite(*in.ServerNameOverwrite))
 }
 if localAddr != nil { options = append(options, tls_client.WithLocalAddr(*localAddr)) }
 tlsClient, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
 if err != nil { return nil, sessionId, false, src.NewTLSClientError(err) }
 var strict *strictH1Config
 if keepAlpn {
  if sessionDialer == nil { return nil, sessionId, false, src.NewTLSClientError(fmt.Errorf("keep_alpn: no dialer for this proxy configuration")) }
  strict = &strictH1Config{dialer: sessionDialer, helloID: profile.GetClientHelloId(), shuffle: shuffle, disableHttp3: in.DisableHttp3,
   insecure: in.InsecureSkipVerify, noTickets: wantsNoSessionTickets(rawPayload)}
  if in.ServerNameOverwrite != nil { strict.serverName = *in.ServerNameOverwrite }
 }
 if layerErr := applySessionLayer(tlsClient, extras.okhttp(), strict, plainConfig{proxyUrl: proxyUrl, localAddr: localAddr, dialTimeout: time.Duration(timeoutMs) * time.Millisecond}); layerErr != nil { return nil, sessionId, false, src.NewTLSClientError(layerErr) }
 if captured { helloSinks.Store(tlsClient, sink) }

 return storePatchedSession(sessionId, tlsClient), sessionId, true, nil
}

// insecureDialer: CONNECT dialer for http:// and https:// proxies (TLS to the
// proxy for https://); proxy certificate verification follows skipVerify, target
// TLS stays with the uTLS client.
type insecureDialer struct {
 proxyUrl   *url.URL
 skipVerify bool
 timeout    time.Duration
 localAddr  *net.TCPAddr
}

// localAddr: local_address binds the connection to the proxy (it was ignored for
// https:// proxies before 0.8.2)
func newInsecureHttpsConnectDialer(proxyUrlStr string, timeout time.Duration, skipVerify bool, localAddr *net.TCPAddr) (*insecureDialer, error) {
 parsed, err := url.Parse(proxyUrlStr)
 if err != nil { return nil, err }
 if parsed.Host == "" { return nil, fmt.Errorf("invalid proxy url %q", proxyUrlStr) }
 if parsed.Port() == "" {
  port := "443"
  if strings.EqualFold(parsed.Scheme, "http") { port = "80" }
  parsed.Host = net.JoinHostPort(parsed.Hostname(), port)
 }
 return &insecureDialer{proxyUrl: parsed, skipVerify: skipVerify, timeout: timeout, localAddr: localAddr}, nil
}

// tunneledConn serves bytes buffered during the CONNECT handshake first.
type tunneledConn struct {
 net.Conn
 r *bufio.Reader
}

func (t *tunneledConn) Read(p []byte) (int, error) { return t.r.Read(p) }

func (d *insecureDialer) connect(ctx context.Context, address string) (net.Conn, error) {
 rawDialer := &net.Dialer{Timeout: d.timeout}
 if d.localAddr != nil { rawDialer.LocalAddr = d.localAddr }
 rawConn, err := rawDialer.DialContext(ctx, "tcp", d.proxyUrl.Host)
 if err != nil { return nil, err }
 // the TLS handshake and the CONNECT exchange: bounded by the session limit and
 // by the request context (a proxy that never answers CONNECT used to hold the
 // connection and its goroutine with no deadline after the request gave up)
 if d.timeout > 0 { _ = rawConn.SetDeadline(time.Now().Add(d.timeout)) }
 stop := context.AfterFunc(ctx, func() { _ = rawConn.SetDeadline(time.Now()) })
 defer stop()
 var conn net.Conn = rawConn
 if strings.EqualFold(d.proxyUrl.Scheme, "https") {
  tlsConn := crandtls.Client(rawConn, &crandtls.Config{
   NextProtos:         []string{"http/1.1"},
   ServerName:         d.proxyUrl.Hostname(),
   InsecureSkipVerify: d.skipVerify,
  })
  if err := tlsConn.HandshakeContext(ctx); err != nil {
   _ = rawConn.Close()
   return nil, err
  }
  conn = tlsConn
 }
 req := &http.Request{Method: "CONNECT", URL: &url.URL{Host: address}, Header: make(http.Header), Host: address}
 if d.proxyUrl.User != nil {
  password, _ := d.proxyUrl.User.Password()
  req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(d.proxyUrl.User.Username()+":"+password)))
 }
 reader := bufio.NewReader(conn)
 if err := req.Write(conn); err != nil { _ = conn.Close(); return nil, err }
 resp, err := http.ReadResponse(reader, req)
 if err != nil { _ = conn.Close(); return nil, err }
 if resp.StatusCode == http.StatusOK && !stop() {
  // the request gave up while the tunnel was opening
  _ = conn.Close()
  return nil, context.Cause(ctx)
 }
 _ = rawConn.SetDeadline(time.Time{})
 if resp.StatusCode != http.StatusOK {
  _ = conn.Close()
  // the same text as upstream's CONNECT dialer (docs/proxies.md quotes it)
  return nil, fmt.Errorf("Proxy responded with non 200 code: %s", resp.Status)
 }
 return &tunneledConn{Conn: conn, r: reader}, nil
}

func (d *insecureDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
 return d.connect(ctx, address)
}

func (d *insecureDialer) Dial(network, address string) (net.Conn, error) {
 return d.connect(context.Background(), address)
}

// wantsNoSessionTickets reads disableSessionTickets from the raw payload (the
// Python flag existed but was never applied by the patched builders)
func wantsNoSessionTickets(rawPayload []byte) bool {
 var env struct {
  DisableSessionTickets bool `json:"disableSessionTickets"`
 }
 return json.Unmarshal(rawPayload, &env) == nil && env.DisableSessionTickets
}

func wantsFingerprint(rawPayload []byte) bool {
 var env struct {
  WithFingerprint bool `json:"withFingerprint"`
 }
 return json.Unmarshal(rawPayload, &env) == nil && env.WithFingerprint
}

// fingerprintForSession re-derives the final ClientHello spec for the session's
// profile and returns JA3/JA4/Akamai strings. For identifier-based sessions the
// spec comes from the mapped/extra profile; for ja3 sessions — from the same
// spec buildJa3Client constructed (identical because SpecFactory is deterministic).
// fingerprintForSession: TLS part (ja3/ja4/extensions) from the ClientHello
// captured on the socket when available ("source": "wire"), otherwise from the
// configured spec ("source": "config"). Akamai is always the configured h2
// SETTINGS/WINDOW_UPDATE/pseudo order (what the transport is told to send).
func fingerprintForSession(in src.RequestInput, rawPayload []byte, client tls_client.HttpClient, target *url.URL) map[string]any {
 cfg := fingerprintFromConfig(in, rawPayload)
 var wire []byte
 handshakes := 0
 addr := ""
 if target != nil {
  port := target.Port()
  if port == "" { port = "443" }
  addr = net.JoinHostPort(target.Hostname(), port)
 }
 if sink := sinkFor(client); sink != nil { wire, handshakes = sink.get(addr) }
 if len(wire) == 0 {
  if cfg != nil { cfg["source"] = "config" }
  return cfg
 }
 f, err := parseClientHelloRecord(wire)
 if err != nil {
  if cfg != nil { cfg["source"] = "config"; cfg["wire_error"] = err.Error() }
  return cfg
 }
 out := f.report()
 out["source"] = "wire"
 out["client_hello_len"] = f.hsLen
 out["handshakes"] = handshakes
 if cfg != nil {
  for _, k := range []string{"akamai_fingerprint", "akamai_hash_sha256_96"} {
   if v, ok := cfg[k]; ok { out[k] = v }
  }
  // configured values next to the wire ones: a mismatch means the session's
  // spec is not what goes out (the 0.4.4 okhttp4_conscrypt symptom)
  out["config_ja3_hash_md5"] = cfg["ja3_hash_md5"]
  out["config_ja4"] = cfg["ja4"]
 }
 return out
}

func fingerprintFromConfig(in src.RequestInput, rawPayload []byte) map[string]any {
 var spec *tls.ClientHelloSpec
 var settings map[http2.SettingID]uint32
 var order []http2.SettingID
 var pseudo []string
 var flow uint32

 if in.CustomTlsClient != nil && in.CustomTlsClient.Ja3String != "" {
  prof, build, _, err := customJa3Profile(in, rawPayload)
  if err != nil { return nil }
  s, err := build()
  if err != nil { return nil }
  return fingerprintFromSpec(&s, prof.GetSettings(), prof.GetSettingsOrder(), prof.GetPseudoHeaderOrder(), prof.GetConnectionFlow(), prof.GetPriorities())
 }

 // identifier-based: mapped or extra profile
 prof := resolveProfile(in.TLSClientIdentifier)
 s, err := prof.GetClientHelloSpec()
 if err != nil {
  if resolved, resolveErr := tls.UTLSIdToSpec(prof.GetClientHelloId()); resolveErr == nil {
   s = resolved
  } else {
   return nil
  }
 }
 spec = &s
 settings = prof.GetSettings()
 order = prof.GetSettingsOrder()
 pseudo = prof.GetPseudoHeaderOrder()
 flow = prof.GetConnectionFlow()
 if spec == nil { return nil }
 return fingerprintFromSpec(spec, settings, order, pseudo, flow, prof.GetPriorities())
}

// storePatchedSession registers a new session client; when a concurrent call
// registered one first, that one is used and this one released.
func storePatchedSession(session string, client tls_client.HttpClient) tls_client.HttpClient {
 patchedSessions.Lock()
 existing, ok := patchedSessions.m[session]
 if !ok {
  patchedSessions.m[session] = client
 }
 patchedSessions.Unlock()
 if ok {
  releaseClient(client)
  return existing
 }
 return client
}

// removePatchedSession forgets the session (later calls build a new client) and
// closes its client once the calls still using it are done. With only set, the
// session is removed only while it still has that client: a request that failed
// on a client already replaced must not close the replacement. The close runs
// outside the sessions lock: it can wait for dials in progress.
func removePatchedSession(session string, only ...tls_client.HttpClient) bool {
 patchedSessions.Lock()
 client, ok := patchedSessions.m[session]
 if ok && len(only) > 0 && client != only[0] {
  ok = false
 }
 if ok {
  delete(patchedSessions.m, session)
 }
 patchedSessions.Unlock()
 if ok {
  releaseClient(client)
 }
 return ok
}

// releaseClient closes a session client and drops its per-session state once the
// calls still using it are done.
func releaseClient(client tls_client.HttpClient) {
 closeClient(client, func() {
  helloSinks.Delete(client)
  sessionStyles.Delete(client)
 })
}

// schemeGuard: the session client as call.go uses it. http:// requests go through
// the same client as https:// ones, so redirects between the schemes stay on the
// session (cookies, redirect policy, the profile's TLS for every https:// hop);
// hopTransport sends http:// hops to the session's plain transports (plain.go).
type schemeGuard struct {
 inner    tls_client.HttpClient
 proxyUrl string
}

func wrapClient(client tls_client.HttpClient, proxyUrl string) *schemeGuard {
 return &schemeGuard{inner: client, proxyUrl: proxyUrl}
}

func proxyFuncFromUrl(raw string) func(*http.Request) (*url.URL, error) {
 if raw == "" { return nil }
 parsed, err := url.Parse(raw)
 if err != nil || parsed.Host == "" { return nil }
 return func(*http.Request) (*url.URL, error) { return parsed, nil }
}

func (g *schemeGuard) Do(req *http.Request) (*http.Response, error) {
 if strings.EqualFold(req.URL.Scheme, "http") {
  if hop, ok := clientTransport(g.inner).(*hopTransport); !ok || hop.plain == nil {
   // a session built by upstream code (no request control): a plain client of its own
   p := &plainRoutes{proxyUrl: g.proxyUrl}
   rt, err := p.transport(false)
   if err != nil { return nil, err }
   c := &http.Client{Transport: rt}
   if fr, ok := g.inner.(interface{ GetFollowRedirect() bool }); ok && !fr.GetFollowRedirect() {
    c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
   }
   defer p.closeIdle()
   return c.Do(req)
  }
 }
 return g.inner.Do(req)
}

//export yumeclient_close
func yumeclient_close(session *C.char) {
 removePatchedSession(C.GoString(session))
 src.RemoveSession(C.GoString(session))
}

//export yumeclient_free
func yumeclient_free(p *C.char) { C.free(unsafe.Pointer(p)) }
func main() {}
