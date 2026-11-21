package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// echConfig marshals one ECHConfig (draft-ietf-tls-esni-22, version 0xfe0d) for an
// X25519 key with HKDF-SHA256 / AES-128-GCM.
func echConfig(id uint8, pub []byte, publicName string) []byte {
	var c []byte
	c = append(c, id)
	c = binary.BigEndian.AppendUint16(c, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	c = binary.BigEndian.AppendUint16(c, 4)
	c = binary.BigEndian.AppendUint16(c, 0x0001) // HKDF-SHA256
	c = binary.BigEndian.AppendUint16(c, 0x0001) // AES-128-GCM
	c = append(c, 0)                             // maximum_name_length
	c = append(c, uint8(len(publicName)))
	c = append(c, publicName...)
	c = binary.BigEndian.AppendUint16(c, 0) // extensions
	out := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c)))
	return append(out, c...)
}

func selfSigned(t *testing.T, names ...string) stdtls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestCustomJa3EncryptedClientHello: ech_config_list makes the custom JA3 hello carry a
// real ECH (the server decrypts the inner hello and sees the inner SNI); without it the
// ECH extension stays GREASE. ech_config_list used to be parsed and dropped.
func TestCustomJa3EncryptedClientHello(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := echConfig(7, priv.PublicKey().Bytes(), "public.example")
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		fmt.Fprintf(w, "ech=%v sni=%s", r.TLS.ECHAccepted, r.TLS.ServerName)
	}))
	srv.TLS = &stdtls.Config{
		MinVersion:               stdtls.VersionTLS13,
		Certificates:             []stdtls.Certificate{selfSigned(t, "localhost", "public.example")},
		EncryptedClientHelloKeys: []stdtls.EncryptedClientHelloKey{{Config: config, PrivateKey: priv.Bytes()}},
	}
	srv.StartTLS()
	defer srv.Close()
	url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	list := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	list = append(list, config...)
	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53," +
		"0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-65037-21,4588-29-23-24,0"
	for _, tc := range []struct {
		name string
		ech  []byte
		want string
	}{
		{"real", list, "ech=true sni=localhost"},
		{"grease", nil, "ech=false sni=localhost"},
	} {
		custom := map[string]any{"ja3String": ja3, "chromeDefaultsProfile": "chrome_152"}
		if tc.ech != nil {
			custom["echConfigList"] = base64.StdEncoding.EncodeToString(tc.ech)
		}
		payload, _ := json.Marshal(map[string]any{
			"requestMethod": "GET", "requestUrl": url + "/", "tlsClientIdentifier": "",
			"sessionId": "ech-test-" + tc.name, "headers": map[string]string{}, "headerOrder": []string{},
			"insecureSkipVerify": true, "timeoutMilliseconds": 5000, "followRedirects": true,
			"isByteResponse": true, "customTlsClient": custom,
		})
		out := runCall(payload)
		if out["status"] != 200 {
			t.Fatalf("%s: %v", tc.name, out)
		}
		body, _ := base64.StdEncoding.DecodeString(fmt.Sprint(out["body"]))
		if string(body) != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, body, tc.want)
		}
		removePatchedSession("ech-test-" + tc.name)
	}
}
