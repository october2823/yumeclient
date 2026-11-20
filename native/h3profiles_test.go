package main

import "testing"

func TestH3ProfilesApply(t *testing.T) {
	data, err := loadH3Profiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Profiles) == 0 {
		t.Fatal("no profiles")
	}
	for name, p := range data.Profiles {
		c := data.Captures[p.Capture]
		if c == nil {
			t.Errorf("%s: capture %s missing", name, p.Capture)
			continue
		}
		base := resolveProfile("chrome_133")
		hp, err := applyH3Capture(base, c)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		fp := hp.GetHTTP3Fingerprint()
		if fp == nil || fp.QUIC == nil || fp.QUIC.ClientHello == nil {
			t.Errorf("%s: no fingerprint", name)
			continue
		}
		if _, err := fp.QUIC.ClientHello(); err != nil {
			t.Errorf("%s: client hello: %v", name, err)
		}
	}
	if resolveProfile("chrome_144").GetHTTP3Fingerprint() == nil {
		t.Error("chrome_144 has no HTTP/3 fingerprint")
	}
}
