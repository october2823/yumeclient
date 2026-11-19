package main

// Per-request RFC 6265 cookie jar (0.5.0).
//
// The Python CookieJar is the single source of truth. Every native call gets a
// fresh jar seeded with the Python snapshot; hopTransport attaches matching
// cookies to each hop (redirects included) and stores Set-Cookie answers in it;
// the call returns only the changes ("jarDelta"), which Python merges.
//
// This replaces tls-client's session jar, which keys cookies by the last two
// host labels and returns every cookie under that key regardless of Domain,
// Path, Secure or host-only scope (a Secure cookie from https://a.example.com
// went to http://b.example.com), and which kept cookies the Python side had
// already removed. A per-request jar also keeps concurrent requests of one
// session from overwriting each other's cookie state.

import (
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// seedCookie is one cookie of the Python snapshot ("jar" payload field).
type seedCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	Secure   bool    `json:"secure"`
	HttpOnly bool    `json:"httpOnly"`
	HostOnly bool    `json:"hostOnly"`
	SameSite string  `json:"sameSite"`
}

type jarEntry struct {
	name, value, domain, path string
	expires                   time.Time // zero: session cookie
	secure, httpOnly          bool
	hostOnly                  bool
	anyHost                   bool // Python cookie without a domain: sent to every host (requests semantics)
	sameSite                  string
	created                   time.Time
	seq                       uint64
}

func (e *jarEntry) key() string { return e.domain + ";" + e.path + ";" + e.name }

type requestJar struct {
	mu      sync.Mutex
	entries map[string]*jarEntry
	changed map[string]*jarEntry // nil value: deleted
	seq     uint64
}

func newRequestJar() *requestJar {
	return &requestJar{entries: map[string]*jarEntry{}, changed: map[string]*jarEntry{}}
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(d), "."), "."))
}

func canonicalHost(u *url.URL) string {
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

// seed adds the Python snapshot without recording changes.
func (j *requestJar) seed(cookies []seedCookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	for _, c := range cookies {
		if c.Name == "" {
			continue
		}
		e := &jarEntry{name: c.Name, value: c.Value, domain: normalizeDomain(c.Domain), path: c.Path,
			secure: c.Secure, httpOnly: c.HttpOnly, hostOnly: c.HostOnly, sameSite: c.SameSite, created: now}
		if e.path == "" || !strings.HasPrefix(e.path, "/") {
			e.path = "/"
		}
		if e.domain == "" {
			e.anyHost, e.hostOnly = true, false
		}
		if c.Expires > 0 {
			e.expires = time.Unix(0, int64(c.Expires*1e9))
			if !e.expires.After(now) {
				continue
			}
		}
		j.seq++
		e.seq = j.seq
		j.entries[e.key()] = e
	}
}

// override applies explicit per-request cookies (cookies= kwarg): they replace
// every same-name jar cookie for this URL and are not reported back unless the
// server sets them.
func (j *requestJar) override(u *url.URL, pairs map[string]string) {
	if u == nil || len(pairs) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	host := canonicalHost(u)
	for k, e := range j.entries {
		if _, ok := pairs[e.name]; ok && e.matchesHost(host) {
			delete(j.entries, k)
		}
	}
	names := make([]string, 0, len(pairs))
	for name := range pairs {
		names = append(names, name)
	}
	sort.Strings(names)
	now := time.Now()
	for _, name := range names {
		j.seq++
		e := &jarEntry{name: name, value: pairs[name], domain: host, path: "/", hostOnly: true, created: now, seq: j.seq}
		j.entries[e.key()] = e
	}
}

func (e *jarEntry) matchesHost(host string) bool {
	switch {
	case e.anyHost:
		return true
	case e.hostOnly:
		return host == e.domain
	default:
		return domainMatch(host, e.domain)
	}
}

// domainMatch: RFC 6265 5.1.3 (an IP address only matches itself).
func domainMatch(host, domain string) bool {
	if host == domain {
		return true
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return strings.HasSuffix(host, "."+domain)
}

// pathMatch: RFC 6265 5.1.4.
func pathMatch(reqPath, cookiePath string) bool {
	if reqPath == "" {
		reqPath = "/"
	}
	if reqPath == cookiePath {
		return true
	}
	if strings.HasPrefix(reqPath, cookiePath) {
		return strings.HasSuffix(cookiePath, "/") || reqPath[len(cookiePath)] == '/'
	}
	return false
}

// defaultPath: RFC 6265 5.1.4.
func defaultPath(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" || p[0] != '/' {
		return "/"
	}
	i := strings.LastIndex(p, "/")
	if i == 0 {
		return "/"
	}
	return p[:i]
}

func secureScheme(u *url.URL) bool {
	s := strings.ToLower(u.Scheme)
	return s == "https" || s == "wss"
}

// Cookies: RFC 6265 5.4 selection and order (longer paths first, then older).
func (j *requestJar) Cookies(u *url.URL) []*http.Cookie {
	if u == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	host, now := canonicalHost(u), time.Now()
	reqPath := u.EscapedPath()
	var selected []*jarEntry
	for k, e := range j.entries {
		if !e.expires.IsZero() && !e.expires.After(now) {
			delete(j.entries, k)
			continue
		}
		if !e.matchesHost(host) || !pathMatch(reqPath, e.path) || (e.secure && !secureScheme(u)) {
			continue
		}
		selected = append(selected, e)
	}
	sort.Slice(selected, func(a, b int) bool {
		if len(selected[a].path) != len(selected[b].path) {
			return len(selected[a].path) > len(selected[b].path)
		}
		return selected[a].seq < selected[b].seq
	})
	scoped := map[string]bool{}
	for _, e := range selected {
		if !e.anyHost {
			scoped[e.name] = true
		}
	}
	out := make([]*http.Cookie, 0, len(selected))
	for _, e := range selected {
		if e.anyHost && scoped[e.name] {
			continue // a domainless jar entry never shadows a host/domain-scoped one
		}
		out = append(out, &http.Cookie{Name: e.name, Value: e.value})
	}
	return out
}

// SetCookies: RFC 6265 5.3 storage model for response cookies of u.
func (j *requestJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if u == nil || len(cookies) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	host, now := canonicalHost(u), time.Now()
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		e := &jarEntry{name: c.Name, value: c.Value, secure: c.Secure, httpOnly: c.HttpOnly, created: now}
		switch c.SameSite {
		case http.SameSiteLaxMode:
			e.sameSite = "Lax"
		case http.SameSiteStrictMode:
			e.sameSite = "Strict"
		case http.SameSiteNoneMode:
			e.sameSite = "None"
		}
		if d := normalizeDomain(c.Domain); d != "" {
			if !domainMatch(host, d) {
				continue // a host may not set cookies for an unrelated domain
			}
			e.domain = d
		} else {
			e.domain, e.hostOnly = host, true
		}
		if c.Path != "" && strings.HasPrefix(c.Path, "/") {
			e.path = c.Path
		} else {
			e.path = defaultPath(u)
		}
		// a Secure cookie from an http:// origin is stored (like Go's cookiejar and
		// requests do) but, as every Secure cookie, only ever sent over https
		remove := false
		switch {
		case c.MaxAge < 0:
			remove = true
		case c.MaxAge > 0:
			e.expires = now.Add(time.Duration(c.MaxAge) * time.Second)
		case !c.Expires.IsZero():
			e.expires = c.Expires
			remove = !c.Expires.After(now)
		}
		k := e.key()
		if old, ok := j.entries[k]; ok {
			e.created, e.seq = old.created, old.seq
		} else {
			j.seq++
			e.seq = j.seq
		}
		if remove {
			delete(j.entries, k)
			j.changed[k] = nil
			continue
		}
		j.entries[k] = e
		j.changed[k] = e
	}
}

// delta: the cookies the server set or deleted during this call.
func (j *requestJar) delta() []map[string]any {
	j.mu.Lock()
	defer j.mu.Unlock()
	keys := make([]string, 0, len(j.changed))
	for k := range j.changed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		e := j.changed[k]
		if e == nil {
			parts := strings.SplitN(k, ";", 3)
			out = append(out, map[string]any{"domain": parts[0], "path": parts[1], "name": parts[2], "deleted": true})
			continue
		}
		item := map[string]any{"name": e.name, "value": e.value, "domain": e.domain, "path": e.path,
			"secure": e.secure, "httpOnly": e.httpOnly, "hostOnly": e.hostOnly}
		if !e.expires.IsZero() {
			item["expires"] = float64(e.expires.UnixNano()) / 1e9
		}
		if e.sameSite != "" {
			item["sameSite"] = e.sameSite
		}
		out = append(out, item)
	}
	return out
}

// valuesFor: name -> value of the cookies that would be sent to u (Response.cookies).
func (j *requestJar) valuesFor(u *url.URL) map[string]string {
	out := map[string]string{}
	for _, c := range j.Cookies(u) {
		if _, ok := out[c.Name]; !ok {
			out[c.Name] = c.Value
		}
	}
	return out
}
