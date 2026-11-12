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
 "os"
 "sort"
 "strconv"
 "crypto/md5"
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

// cookiePair mirrors a single cookie with its attributes for the Python side.
type cookiePair struct {
 Name     string `json:"name"`
 Value    string `json:"value"`
 Domain   string `json:"domain"`
 Path     string `json:"path,omitempty"`
 Expires  int64  `json:"expires,omitempty"`
 Secure   bool   `json:"secure,omitempty"`
 HttpOnly bool   `json:"httpOnly,omitempty"`
}

func unixOrZero(t time.Time) int64 {
 if t.IsZero() { return 0 }
 return t.Unix()
}

func pairsFrom(cookies []*http.Cookie, domain string) []cookiePair {
 pairs := make([]cookiePair, 0, len(cookies))
 for _, c := range cookies {
  if c == nil || c.Name == "" { continue }
  pairs = append(pairs, cookiePair{Name: c.Name, Value: c.Value, Domain: domain, Path: c.Path, Expires: unixOrZero(c.Expires), Secure: c.Secure, HttpOnly: c.HttpOnly})
 }
 return pairs
}

// jarDump snapshots the whole client jar (all hosts), so cookies picked up on
// redirect hops or scoped to other hosts survive the trip back to Python.
func jarDump(client tls_client.HttpClient, current []*http.Cookie, currentHost string) map[string][]cookiePair {
 dump := map[string][]cookiePair{}
 if jar, ok := client.GetCookieJar().(tls_client.CookieJar); ok {
  for host, jarCookies := range jar.GetAllCookies() {
   if pairs := pairsFrom(jarCookies, host); len(pairs) > 0 { dump[host] = pairs }
  }
 }
 if len(current) > 0 && currentHost != "" { dump[currentHost] = pairsFrom(current, currentHost) }
 return dump
}

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

func h2Chrome() (map[http2.SettingID]uint32, []http2.SettingID, []string, uint32) {
 settings := map[http2.SettingID]uint32{
  http2.SettingHeaderTableSize:      65536,
  http2.SettingEnablePush:           0,
  http2.SettingMaxConcurrentStreams: 1000,
  http2.SettingInitialWindowSize:    6291456,
  http2.SettingMaxHeaderListSize:    262144,
 }
 order := []http2.SettingID{
  http2.SettingHeaderTableSize,
  http2.SettingEnablePush,
  http2.SettingMaxConcurrentStreams,
  http2.SettingInitialWindowSize,
  http2.SettingMaxHeaderListSize,
 }
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
 case "firefox":
  settings, order, pseudo, flow = h2Firefox()
 default: // chrome/edge family
  settings, order, pseudo, flow = h2Chrome()
 }
 return profiles.NewClientProfile(id, settings, order, pseudo, flow, nil, nil, 0, false, nil, nil, 0, nil, false)
}

var extraProfiles = map[string]profiles.ClientProfile{
 // Edge (Chromium TLS stack): edge_99/edge_101 mirror curl_cffi names, edge_131 is current
 "edge_99":     profileFromH2(tls.HelloChrome_100, "chrome"),
 "edge_101":    profileFromH2(tls.HelloChrome_110, "chrome"),
 "edge_131":    profileFromH2(tls.HelloChrome_131, "chrome"),
 "edge_latest": profileFromH2(tls.HelloChrome_131, "chrome"),
 // Tor Browser 14+ (Firefox ESR 128 TLS stack, stable since FF110)
 "tor_145": profileFromH2(tls.HelloFirefox_120, "firefox"),
 // macOS Safari desktop: Apple keeps the TLS ClientHello stable across 16/17/18/26;
 // utls HelloSafari_16_0 is the real, current Apple TLS stack
 "safari_macos_17_0": profileFromH2(tls.HelloSafari_16_0, "safari"),
 "safari_macos_18_0": profileFromH2(tls.HelloSafari_16_0, "safari"),
 "safari_macos_26_0": profileFromH2(tls.HelloSafari_16_0, "safari"),
}

func lookupExtraProfile(name string) (profiles.ClientProfile, bool) {
 p, ok := extraProfiles[name]
 return p, ok
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
 return a
}

func applyGrease(spec *tls.ClientHelloSpec, enabled bool) {
 kept := make([]uint16, 0, len(spec.CipherSuites))
 for _, c := range spec.CipherSuites {
  isGrease := (c&0x0F0F) == 0x0A0A
  if isGrease && !enabled { continue }
  if !isGrease && enabled && len(kept) > 0 && kept[0] == tls.GREASE_PLACEHOLDER { kept = append(kept, c); continue }
  kept = append(kept, c)
 }
 if enabled && (len(kept) == 0 || kept[0] != tls.GREASE_PLACEHOLDER) {
  kept = append([]uint16{tls.GREASE_PLACEHOLDER}, kept...)
 }
 spec.CipherSuites = kept
 filtered := make([]tls.TLSExtension, 0, len(spec.Extensions)+1)
 sawGrease := false
 for _, e := range spec.Extensions {
  if u, ok := e.(*tls.GenericExtension); ok && (u.Id&0x0F0F) == 0x0A0A {
   sawGrease = true
   if enabled { filtered = append(filtered, e) }
   continue
  }
  filtered = append(filtered, e)
 }
 if enabled && !sawGrease {
  filtered = append(filtered, &tls.GenericExtension{Id: tls.GREASE_PLACEHOLDER})
 }
 spec.Extensions = filtered
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

func extensionID(e tls.TLSExtension) uint16 {
 switch t := e.(type) {
 case *tls.SNIExtension: return 0
 case *tls.StatusRequestExtension: return 5
 case *tls.SupportedCurvesExtension: return 10
 case *tls.SupportedPointsExtension: return 11
 case *tls.SignatureAlgorithmsExtension: return 13
 case *tls.SCTExtension: return 18
 case *tls.ALPNExtension: return 16
 case *tls.SessionTicketExtension: return 35
 case *tls.UtlsExtendedMasterSecretExtension: return 23
 case *tls.KeyShareExtension: return 51
 case *tls.SupportedVersionsExtension: return 43
 case *tls.PSKKeyExchangeModesExtension: return 45
 case *tls.UtlsCompressCertExtension: return 27
 case *tls.RenegotiationInfoExtension: return 65281
 case *tls.UtlsPaddingExtension: return 21
 case *tls.FakeRecordSizeLimitExtension: return 28
 case *tls.DelegatedCredentialsExtension: return 34
 case *tls.ApplicationSettingsExtensionNew: return 17613
 case *tls.ApplicationSettingsExtension: return 13172
 case *tls.GREASEEncryptedClientHelloExtension: return 17513
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

func ja3FromSpec(spec *tls.ClientHelloSpec) string {
 ciphers := make([]string, 0, len(spec.CipherSuites))
 for _, c := range spec.CipherSuites { ciphers = append(ciphers, strconv.Itoa(int(c))) }
 exts := make([]string, 0, len(spec.Extensions))
 curves := ""
 sigAlgs := ""
 for _, e := range spec.Extensions {
  exts = append(exts, strconv.Itoa(int(extensionID(e))))
  if sc, ok := e.(*tls.SupportedCurvesExtension); ok {
   parts := []string{}
   for _, c := range sc.Curves { parts = append(parts, strconv.Itoa(int(c))) }
   curves = strings.Join(parts, "-")
  }
  if sa, ok := e.(*tls.SignatureAlgorithmsExtension); ok {
   parts := []string{}
   for _, s := range sa.SupportedSignatureAlgorithms { parts = append(parts, strconv.Itoa(int(s))) }
   sigAlgs = strings.Join(parts, "-")
  }
 }
 return strings.Join([]string{"771", strings.Join(ciphers, "-"), strings.Join(exts, "-"), curves, sigAlgs}, ",")
}

func ja4FromSpec(spec *tls.ClientHelloSpec) string {
 // JA4: t<proto><ver><sni><cipher_count><ext_count><alpn>_<cipher_hash>_<ext_hash>
 // ciphers sorted numerically, GREASE excluded from count and hashes;
 // extension hash keeps wire order but excludes SNI(0), ALPN(16) and GREASE
 ciphers := make([]int, 0, len(spec.CipherSuites))
 for _, c := range spec.CipherSuites {
  if (c&0x0F0F) == 0x0A0A { continue }
  ciphers = append(ciphers, int(c))
 }
 sort.Ints(ciphers)
 cipherCount := len(ciphers)
 extIDs := make([]string, 0, len(spec.Extensions))
 extCount := 0
 alpnFirst := "00"
 for _, e := range spec.Extensions {
  id := extensionID(e)
  if (id&0x0F0F) == 0x0A0A { continue }
  extCount++ // JA4 counts every non-GREASE ext, including SNI and ALPN
  if id == 0 { continue } // SNI excluded from the hash
  if id == 16 {
   if alpn, ok := e.(*tls.ALPNExtension); ok && len(alpn.AlpnProtocols) > 0 {
    switch alpn.AlpnProtocols[0] {
    case "h2": alpnFirst = "h2"
    case "http/1.1", "http/1.0": alpnFirst = "t"
    default: alpnFirst = "99"
    }
   }
   continue // ALPN excluded from the hash
  }
  extIDs = append(extIDs, strconv.Itoa(int(id)))
 }
 cc := fmt.Sprintf("%02d", cipherCount)
 ec := fmt.Sprintf("%02d", extCount)
 cipherStrings := make([]string, 0, len(ciphers))
 for _, c := range ciphers { cipherStrings = append(cipherStrings, fmt.Sprintf("%04x", c)) }
 cipSum := sha256.Sum256([]byte(strings.Join(cipherStrings, ",")))
 extSum := sha256.Sum256([]byte(strings.Join(extIDs, ",")))
 return fmt.Sprintf("t13d%s%s%s_%s_%s", cc, ec, alpnFirst,
  hex.EncodeToString(cipSum[:6]), hex.EncodeToString(extSum[:6]))
}

func settingIDNum(s http2.SettingID) uint16 {
 switch s {
 case http2.SettingHeaderTableSize: return 1
 case http2.SettingEnablePush: return 2
 case http2.SettingMaxConcurrentStreams: return 3
 case http2.SettingInitialWindowSize: return 4
 case http2.SettingMaxFrameSize: return 5
 case http2.SettingMaxHeaderListSize: return 6
 }
 return 0
}

func akamaiFromSpec(settings map[http2.SettingID]uint32, order []http2.SettingID,
 pseudo []string, flow uint32) string {
 // canonical Akamai fingerprint: SETTINGS in send order (id:value, ';'),
 // then |<connection window increment>|<headers priority?>|, then pseudo order letters
 parts := []string{}
 for _, sid := range order {
  if v, ok := settings[sid]; ok { parts = append(parts, fmt.Sprintf("%d:%d", settingIDNum(sid), v)) }
 }
 if len(parts) == 0 { return "" }
 fp := strings.Join(parts, ";")
 fp += "|" + fmt.Sprintf("%d", flow)
 fp += "|0"
 letters := map[string]string{":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}
 pseudoParts := []string{}
 for _, p := range pseudo {
  if letter, ok := letters[p]; ok { pseudoParts = append(pseudoParts, letter) } else { pseudoParts = append(pseudoParts, p) }
 }
 fp += "|" + strings.Join(pseudoParts, ",")
 return fp
}

func fingerprintFromSpec(spec *tls.ClientHelloSpec, settings map[http2.SettingID]uint32,
 settingsOrder []http2.SettingID, pseudo []string, flow uint32) map[string]any {
 ja3 := ja3FromSpec(spec)
 ja4 := ja4FromSpec(spec)
 akamai := akamaiFromSpec(settings, settingsOrder, pseudo, flow)
 return map[string]any{
  "ja3":           ja3,
  "ja3_hash_md5":  fmt.Sprintf("%x", md5.Sum([]byte(ja3))),
  "ja4":           ja4,
  "akamai_fingerprint": akamai,
  "akamai_hash_sha256_96": fmt.Sprintf("%s", hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte(akamai)); return s[:12] }())),
 }
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

func ensureKeyShare(spec *tls.ClientHelloSpec) {
 for _, e := range spec.Extensions {
  if ks, ok := e.(*tls.KeyShareExtension); ok {
   if len(ks.KeyShares) == 0 {
    ks.KeyShares = []tls.KeyShare{{Group: tls.X25519}}
   }
  }
 }
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

func buildJa3Client(in src.RequestInput, rawPayload []byte, sessionId string) (tls_client.HttpClient, string, bool, *src.TLSClientError) {
 if sessionId == "" { sessionId = fmt.Sprintf("%d", time.Now().UnixNano()) }

 patchedSessions.Lock()
 if existing, ok := patchedSessions.m[sessionId]; ok {
  patchedSessions.Unlock()
  if setter, ok := existing.(interface{ SetFollowRedirect(bool) }); ok { setter.SetFollowRedirect(in.FollowRedirects) }
  return existing, sessionId, true, nil
 }
 patchedSessions.Unlock()

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

 specFactory, err := tls_client.GetSpecFactoryFromJa3String(ct.Ja3String, sigAlgs, delegAlgs, tlsVersions, keyShares, ct.ALPNProtocols, ct.ALPSProtocols, echSuites, ct.ECHCandidatePayloads, ct.CertCompressionAlgos, 0)
 if err != nil { return nil, sessionId, false, src.NewTLSClientError(fmt.Errorf("ja3 parse: %w", err)) }

 spec, err := specFactory()
 if err != nil { return nil, sessionId, false, src.NewTLSClientError(err) }

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
  if adv.grease != nil { applyGrease(&spec, *adv.grease) }
  if adv.pskMode != "" { applyPskMode(&spec, adv.pskMode) }
  applyExtensionOrder(&spec, adv.extOrder)
 }

 helloID := tls.ClientHelloID{
  Client: "Custom", Version: "ja3",
  SpecFactory: func() (tls.ClientHelloSpec, error) { return spec, nil },
 }
 h2Settings, h2Order := resolveH2Settings(ct)
 pseudoOrder := ct.PseudoHeaderOrder
 if len(pseudoOrder) == 0 {
  pseudoOrder = []string{":method", ":authority", ":scheme", ":path"}
 }
 connFlow := ct.ConnectionFlow
 if connFlow == 0 { connFlow = 15663105 }
 profile := profiles.NewClientProfile(helloID, h2Settings, h2Order, pseudoOrder, connFlow, nil, nil, 0, false, nil, nil, 0, nil, false)

 timeoutMs := in.TimeoutMilliseconds
 if timeoutMs == 0 && in.TimeoutSeconds != 0 { timeoutMs = in.TimeoutSeconds * 1000 }
 if timeoutMs == 0 { timeoutMs = 30000 }

 options := []tls_client.HttpClientOption{
  tls_client.WithClientProfile(profile),
  tls_client.WithTimeoutMilliseconds(timeoutMs),
  tls_client.WithCookieJar(tls_client.NewCookieJar()),
 }
 if in.WithRandomTLSExtensionOrder { options = append(options, tls_client.WithRandomTLSExtensionOrder()) }
 if in.ForceHttp1 { options = append(options, tls_client.WithForceHttp1()) }
 if in.DisableHttp3 { options = append(options, tls_client.WithDisableHttp3()) }
 if in.WithProtocolRacing && !hasMLKEMCurve(&spec) {
  // quic-go rejects MLKEM-family keyshare preferences ("CurvePreferences includes
  // unsupported curve"); keep h2-only when the ja3 asks for 4588-family curves
  options = append(options, tls_client.WithProtocolRacing())
 }
 if !in.FollowRedirects { options = append(options, tls_client.WithNotFollowRedirects()) }
 if in.InsecureSkipVerify { options = append(options, tls_client.WithInsecureSkipVerify()) }
 if in.ServerNameOverwrite != nil && *in.ServerNameOverwrite != "" {
  options = append(options, tls_client.WithServerNameOverwrite(*in.ServerNameOverwrite))
 }
 if in.LocalAddress != nil {
  localAddr, resolveErr := net.ResolveTCPAddr("", *in.LocalAddress)
  if resolveErr != nil { return nil, sessionId, false, src.NewTLSClientError(resolveErr) }
  options = append(options, tls_client.WithLocalAddr(*localAddr))
 }
 proxyUrl := ""
 if in.ProxyUrl != nil { proxyUrl = *in.ProxyUrl }
 if strings.HasPrefix(strings.ToLower(proxyUrl), "https://") {
  dialer, dialErr := newInsecureHttpsConnectDialer(proxyUrl, time.Duration(timeoutMs)*time.Millisecond, true)
  if dialErr != nil { return nil, sessionId, false, src.NewTLSClientError(dialErr) }
  options = append(options, tls_client.WithProxyDialerFactory(func(_ string, _ time.Duration, _ *net.TCPAddr, _ http.Header, _ tls_client.Logger) (proxy.ContextDialer, error) {
   return dialer, nil
  }))
 } else if proxyUrl != "" {
  options = append(options, tls_client.WithProxyUrl(proxyUrl))
 }
 // udp_proxy for HTTP/3 racing must be socks5 for upstream; apply when main proxy is not socks5
 var udpProxyUrl string
 var envelopeUdp struct {
  UDPProxyUrl string `json:"udpProxyUrl"`
 }
 if json.Unmarshal(rawPayload, &envelopeUdp) == nil { udpProxyUrl = envelopeUdp.UDPProxyUrl }
 if udpProxyUrl != "" && !strings.HasPrefix(strings.ToLower(proxyUrl), "socks5") {
  options = append(options, tls_client.WithProxyUrl(udpProxyUrl))
 }

 client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
 if err != nil { return nil, sessionId, false, src.NewTLSClientError(err) }

 patchedSessions.Lock()
 patchedSessions.m[sessionId] = client
 patchedSessions.Unlock()
 return client, sessionId, true, nil
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

// hasMLKEMCurve: true when the spec keyshares/curves include MLKEM-family groups
// that quic-go's handshake cannot negotiate.
func hasMLKEMCurve(spec *tls.ClientHelloSpec) bool {
 for _, e := range spec.Extensions {
  if ks, ok := e.(*tls.KeyShareExtension); ok {
   for _, k := range ks.KeyShares {
    switch k.Group {
    case 0x11EC: // 4588 X25519MLKEM768
     return true
    case 0xFE0E, 0xFE0F: // 65038/65039 MLKEM drafts
     return true
    }
   }
  }
  if sc, ok := e.(*tls.SupportedCurvesExtension); ok {
   for _, c := range sc.Curves {
    switch c {
    case 0x11EC, 0xFE0E, 0xFE0F: // 4588 + MLKEM drafts
     return true
    }
   }
  }
 }
 return false
}

func h2SettingByName(name string) (http2.SettingID, bool) {
 switch strings.ToLower(name) {
 case "header_table_size", "1": return http2.SettingHeaderTableSize, true
 case "enable_push", "2": return http2.SettingEnablePush, true
 case "max_concurrent_streams", "3": return http2.SettingMaxConcurrentStreams, true
 case "initial_window_size", "4": return http2.SettingInitialWindowSize, true
 case "max_frame_size", "5": return http2.SettingMaxFrameSize, true
 case "max_header_list_size", "6": return http2.SettingMaxHeaderListSize, true
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

func createPatchedClient(in src.RequestInput, rawPayload []byte) (tls_client.HttpClient, string, bool, *src.TLSClientError) {
 proxyUrl := ""
 if in.ProxyUrl != nil { proxyUrl = *in.ProxyUrl }
 _, isExtra := lookupExtraProfile(in.TLSClientIdentifier)
 // ja3_string sessions route through our builder (advanced controls + fingerprint);
 // identifier sessions go through the manual builder so yumeclient_close can always
 // call CloseIdleConnections
 if os.Getenv("YUMECLIENT_UPSTREAM_JA3") != "" && in.CustomTlsClient != nil && in.CustomTlsClient.Ja3String != "" {
  return src.CreateClient(in)
 }
 if in.CustomTlsClient != nil && in.CustomTlsClient.Ja3String != "" {
  sessionId := ""
  if in.SessionId != nil { sessionId = *in.SessionId }
  return buildJa3Client(in, rawPayload, sessionId)
 }
 if isExtra || in.TLSClientIdentifier == "" {
  return src.CreateClient(in)
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

 profile, ok := profiles.MappedTLSClients[in.TLSClientIdentifier]
 if !ok {
  if ep, isExtra := lookupExtraProfile(in.TLSClientIdentifier); isExtra {
   profile = ep
  } else {
   profile = profiles.DefaultClientProfile
  }
 }

 timeoutMs := in.TimeoutMilliseconds
 if timeoutMs == 0 && in.TimeoutSeconds != 0 { timeoutMs = in.TimeoutSeconds * 1000 }
 if timeoutMs == 0 { timeoutMs = 30000 }

 // the proxy leg is deliberately never certificate-verified: the operator picks
 // the proxy, and https:// proxies in the wild (IP hosts, self-signed/domain certs
 // without IP SANs) fail strict verification — every practical TLS client defaults
 // to lenient proxy TLS. Target verification is still governed by InsecureSkipVerify.
 options := []tls_client.HttpClientOption{
  tls_client.WithClientProfile(profile),
  tls_client.WithTimeoutMilliseconds(timeoutMs),
  tls_client.WithCookieJar(tls_client.NewCookieJar()),
 }
 if strings.HasPrefix(strings.ToLower(proxyUrl), "https://") {
  dialer, err := newInsecureHttpsConnectDialer(proxyUrl, time.Duration(timeoutMs)*time.Millisecond, true)
  if err != nil { return nil, sessionId, false, src.NewTLSClientError(err) }
  options = append(options, tls_client.WithProxyDialerFactory(func(_ string, _ time.Duration, _ *net.TCPAddr, _ http.Header, _ tls_client.Logger) (proxy.ContextDialer, error) {
   return dialer, nil
  }))
 } else if proxyUrl != "" {
  options = append(options, tls_client.WithProxyUrl(proxyUrl))
 }
 if in.WithRandomTLSExtensionOrder { options = append(options, tls_client.WithRandomTLSExtensionOrder()) }
 if in.ForceHttp1 { options = append(options, tls_client.WithForceHttp1()) }
 if in.DisableHttp3 { options = append(options, tls_client.WithDisableHttp3()) }
 if in.WithProtocolRacing { options = append(options, tls_client.WithProtocolRacing()) }
 if !in.FollowRedirects { options = append(options, tls_client.WithNotFollowRedirects()) }
 if in.InsecureSkipVerify { options = append(options, tls_client.WithInsecureSkipVerify()) }
 if in.ServerNameOverwrite != nil && *in.ServerNameOverwrite != "" {
  options = append(options, tls_client.WithServerNameOverwrite(*in.ServerNameOverwrite))
 }
 if in.LocalAddress != nil {
  localAddr, resolveErr := net.ResolveTCPAddr("", *in.LocalAddress)
  if resolveErr != nil { return nil, sessionId, false, src.NewTLSClientError(resolveErr) }
  options = append(options, tls_client.WithLocalAddr(*localAddr))
 }
 tlsClient, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
 if err != nil { return nil, sessionId, false, src.NewTLSClientError(err) }

 patchedSessions.Lock()
 patchedSessions.m[sessionId] = tlsClient
 patchedSessions.Unlock()
 return tlsClient, sessionId, true, nil
}

// insecureDialer: TLS+CONNECT dialer for https:// proxies; proxy certificate
// verification follows skipVerify, target TLS stays with the uTLS client.
type insecureDialer struct {
 proxyUrl   *url.URL
 skipVerify bool
 timeout    time.Duration
}

func newInsecureHttpsConnectDialer(proxyUrlStr string, timeout time.Duration, skipVerify bool) (*insecureDialer, error) {
 parsed, err := url.Parse(proxyUrlStr)
 if err != nil { return nil, err }
 if parsed.Host == "" { return nil, fmt.Errorf("invalid proxy url %q", proxyUrlStr) }
 if parsed.Port() == "" { parsed.Host = net.JoinHostPort(parsed.Host, "443") }
 return &insecureDialer{proxyUrl: parsed, skipVerify: skipVerify, timeout: timeout}, nil
}

// tunneledConn serves bytes buffered during the CONNECT handshake first.
type tunneledConn struct {
 net.Conn
 r *bufio.Reader
}

func (t *tunneledConn) Read(p []byte) (int, error) { return t.r.Read(p) }

func (d *insecureDialer) connect(ctx context.Context, address string) (net.Conn, error) {
 rawDialer := &net.Dialer{Timeout: d.timeout}
 rawConn, err := rawDialer.DialContext(ctx, "tcp", d.proxyUrl.Host)
 if err != nil { return nil, err }
 var conn net.Conn = rawConn
 if d.proxyUrl.Scheme == "https" {
  tlsConn := crandtls.Client(rawConn, &crandtls.Config{
   NextProtos:         []string{"http/1.1"},
   ServerName:         d.proxyUrl.Hostname(),
   InsecureSkipVerify: d.skipVerify,
  })
  tlsConn.SetDeadline(time.Now().Add(d.timeout))
  if err := tlsConn.HandshakeContext(ctx); err != nil {
   _ = rawConn.Close()
   return nil, err
  }
  tlsConn.SetDeadline(time.Time{})
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
 if resp.StatusCode != http.StatusOK {
  _ = conn.Close()
  return nil, fmt.Errorf("https proxy responded with non 200 code: %s", resp.Status)
 }
 return &tunneledConn{Conn: conn, r: reader}, nil
}

func (d *insecureDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
 return d.connect(ctx, address)
}

func (d *insecureDialer) Dial(network, address string) (net.Conn, error) {
 return d.connect(context.Background(), address)
}

//export yumeclient_call
func yumeclient_call(input *C.char) *C.char {
 rawInput := []byte(C.GoString(input))
 var in src.RequestInput
 if err := json.Unmarshal(rawInput, &in); err != nil { return C.CString(`{"status":0,"body":"invalid input"}`) }
 sessionProxy := ""
 if in.ProxyUrl != nil { sessionProxy = *in.ProxyUrl }
 client, session, withSession, clientErr := createPatchedClient(in, rawInput)
 if clientErr != nil {
  b,_:=json.Marshal(map[string]any{"status":0, "body":"client creation failed: "+clientErr.Error()})
  return C.CString(string(b))
 }
 req, clientErr := src.BuildRequest(in)
 if clientErr != nil {
  if withSession { src.RemoveSession(session) }
  b,_:=json.Marshal(map[string]any{"status":0, "body":clientErr.Error()})
  return C.CString(string(b))
 }
 // upstream cffi never applies input.RequestCookies; seed them into the jar so
 // the first call of a session sends the Python-side cookies (and they survive redirects)
 if len(in.RequestCookies) > 0 {
  jarCookies := make([]*http.Cookie, 0, len(in.RequestCookies))
  for _, c := range in.RequestCookies {
   if c.Name == "" { continue }
   jarCookies = append(jarCookies, &http.Cookie{Name: c.Name, Value: c.Value, Path: c.Path})
  }
  if len(jarCookies) > 0 && req.URL != nil { client.SetCookies(req.URL, jarCookies) }
 }
 resp, err := wrapClient(client, sessionProxy).Do(req)
 if err != nil {
  if withSession { src.RemoveSession(session); removePatchedSession(session) }
  b,_:=json.Marshal(map[string]any{"status":0, "body":err.Error()})
  return C.CString(string(b))
 }
 cookies := client.GetCookies(resp.Request.URL)
 out, clientErr := src.BuildResponse(session, withSession, resp, cookies, in)
 if clientErr != nil {
  if withSession { src.RemoveSession(session); removePatchedSession(session) }
  b,_:=json.Marshal(map[string]any{"status":0, "body":clientErr.Error()})
  return C.CString(string(b))
 }
 raw, err := json.Marshal(out)
 if err != nil { return C.CString(`{"status":0,"body":"response encoding failed"}`) }
 var payload map[string]any
 if json.Unmarshal(raw, &payload) == nil {
  currentHost := ""
  if resp.Request != nil && resp.Request.URL != nil { currentHost = resp.Request.URL.Hostname() }
  payload["jarDump"] = jarDump(client, cookies, currentHost)
  if wantsFingerprint(rawInput) {
   if fp := fingerprintForSession(in, rawInput, client); fp != nil { payload["fingerprint"] = fp }
  }
  if raw2, err := json.Marshal(payload); err == nil { raw = raw2 }
 }
 return C.CString(string(raw))
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
func fingerprintForSession(in src.RequestInput, rawPayload []byte, client tls_client.HttpClient) map[string]any {
 var spec *tls.ClientHelloSpec
 var settings map[http2.SettingID]uint32
 var order []http2.SettingID
 var pseudo []string
 var flow uint32

 if in.CustomTlsClient != nil && in.CustomTlsClient.Ja3String != "" {
  ct := in.CustomTlsClient
  specFactory, err := tls_client.GetSpecFactoryFromJa3String(ct.Ja3String, ct.SupportedSignatureAlgorithms,
   ct.SupportedDelegatedCredentialsAlgorithms, ct.SupportedVersions, ct.KeyShareCurves,
   ct.ALPNProtocols, ct.ALPSProtocols, nil, ct.ECHCandidatePayloads, ct.CertCompressionAlgos, 0)
  if err != nil { return nil }
  s, err := specFactory()
  if err != nil { return nil }
  spec = &s
  ensureSupportedVersions(spec)
  ensureKeyShare(spec)
  ensureSignatureAlgorithms(spec, ct.SupportedSignatureAlgorithms)
  ensureDelegatedCredentials(spec, ct.SupportedDelegatedCredentialsAlgorithms)
  ensureCurves(spec)
  // keep in sync with buildJa3Client: empty ALPN breaks servers and JA4 alpn tag
  for _, e := range spec.Extensions {
   if alpnExt, ok := e.(*tls.ALPNExtension); ok && len(alpnExt.AlpnProtocols) == 0 {
    alpnExt.AlpnProtocols = []string{"h2", "http/1.1"}
   }
  }
  if adv := decodeAdvancedTls(rawPayload); adv != nil {
   if adv.grease != nil { applyGrease(spec, *adv.grease) }
   if adv.pskMode != "" { applyPskMode(spec, adv.pskMode) }
   applyExtensionOrder(spec, adv.extOrder)
  }
  settings, order = resolveH2Settings(ct)
  pseudo = ct.PseudoHeaderOrder
  if len(pseudo) == 0 {
   pseudo = []string{":method", ":authority", ":scheme", ":path"}
  }
  flow = ct.ConnectionFlow
  if flow == 0 { flow = 15663105 }
  return fingerprintFromSpec(spec, settings, order, pseudo, flow)
 }

 // identifier-based: mapped or extra profile
 var prof profiles.ClientProfile
 if p, ok := profiles.MappedTLSClients[in.TLSClientIdentifier]; ok {
  prof = p
 } else if ep, ok := lookupExtraProfile(in.TLSClientIdentifier); ok {
  prof = ep
 } else {
  prof = profiles.DefaultClientProfile
 }
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
 return fingerprintFromSpec(spec, settings, order, pseudo, flow)
}

func removePatchedSession(session string) {
 patchedSessions.Lock()
 if client, ok := patchedSessions.m[session]; ok {
  client.CloseIdleConnections()
  delete(patchedSessions.m, session)
 }
 patchedSessions.Unlock()
}

// schemeGuard isolates plain-http requests from the https transport state.
// Upstream keys its cached transports by host:443 regardless of scheme, so an
// h2/h3 transport cached from an https call gets handed to an http:// request
// for the same host -> "http2: unsupported scheme" / "protocol negotiated".
// http:// always speaks plain HTTP/1.1 on a fresh dedicated transport here,
// with the SAME cookie jar, timeout and redirect policy as the inner client.
type schemeGuard struct {
 inner tls_client.HttpClient
 // proxyUrl is remembered from session creation so plain-http requests keep
 // going through the operator's proxy instead of leaking direct connections.
 proxyUrl string
}

func wrapClient(client tls_client.HttpClient, proxyUrl string) *schemeGuard {
 return &schemeGuard{inner: client, proxyUrl: proxyUrl}
}

func httpErrUseLast(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func proxyFuncFromUrl(raw string) func(*http.Request) (*url.URL, error) {
 if raw == "" { return nil }
 parsed, err := url.Parse(raw)
 if err != nil || parsed.Host == "" { return nil }
 return func(*http.Request) (*url.URL, error) { return parsed, nil }
}

func (g *schemeGuard) buildPlainHTTPClient() *http.Client {
 inner := g.inner
 transport := http.DefaultTransport.(*http.Transport).Clone()
 if pf := proxyFuncFromUrl(g.proxyUrl); pf != nil { transport.Proxy = pf }
 client := &http.Client{Timeout: 30 * time.Second, Transport: transport}
 if fr, ok := inner.(interface{ GetFollowRedirect() bool }); ok && !fr.GetFollowRedirect() {
  client.CheckRedirect = httpErrUseLast
 }
 client.Jar = inner.GetCookieJar()
 return client
}

func (g *schemeGuard) Do(req *http.Request) (*http.Response, error) {
 if strings.EqualFold(req.URL.Scheme, "http") {
  return g.buildPlainHTTPClient().Do(req)
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
