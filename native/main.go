package main

/*
#include <stdlib.h>
*/
import "C"

import (
 "encoding/json"
 "time"
 "unsafe"

 http "github.com/bogdanfinn/fhttp"
 src "github.com/bogdanfinn/tls-client/cffi_src"
 tls_client "github.com/bogdanfinn/tls-client"
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

//export yumeclient_call
func yumeclient_call(input *C.char) *C.char {
 var in src.RequestInput
 if err := json.Unmarshal([]byte(C.GoString(input)), &in); err != nil { return C.CString(`{"status":0,"body":"invalid input"}`) }
 client, session, withSession, clientErr := src.CreateClient(in)
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
 resp, err := client.Do(req)
 if err != nil {
  if withSession { src.RemoveSession(session) }
  b,_:=json.Marshal(map[string]any{"status":0, "body":err.Error()})
  return C.CString(string(b))
 }
 cookies := client.GetCookies(resp.Request.URL)
 out, clientErr := src.BuildResponse(session, withSession, resp, cookies, in)
 if clientErr != nil {
  if withSession { src.RemoveSession(session) }
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
  if raw2, err := json.Marshal(payload); err == nil { raw = raw2 }
 }
 return C.CString(string(raw))
}

//export yumeclient_close
func yumeclient_close(session *C.char) { src.RemoveSession(C.GoString(session)) }

//export yumeclient_free
func yumeclient_free(p *C.char) { C.free(unsafe.Pointer(p)) }
func main() {}
