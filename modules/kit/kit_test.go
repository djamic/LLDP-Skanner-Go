package kit

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"000B82AABB01": "00:0b:82:aa:bb:01", "00-0b-82-aa-bb-01": "00:0b:82:aa:bb:01", "000b.82aa.bb01": "00:0b:82:aa:bb:01",
		"00:0b:82:aa:bb": "", "zz0b82aabb01": "", "": "",
	} {
		if got := NormMAC(in); got != want {
			t.Errorf("NormMAC(%q) = %q, want %q", in, got, want)
		}
	}
	if Plural(1, "host") != "1 host" || Plural(0, "host") != "0 hosts" || Plural(2, "site") != "2 sites" {
		t.Error("Plural")
	}
	if FirstOf(" ", "", " a ", "b") != "a" || FirstOf() != "" {
		t.Error("FirstOf")
	}
	for _, c := range []struct {
		s, w string
		want bool
	}{
		{"Grandstream Networks", "grandstream", true}, {"GrandstreamX", "grandstream", false},
		{"sip-t46 yealink", "Yealink", true}, {"l'yealink", "yealink", false}, {"x", "", false},
	} {
		if HasWord(c.s, c.w) != c.want {
			t.Errorf("HasWord(%q, %q) != %v", c.s, c.w, c.want)
		}
	}
	if err := (&HTTPError{URL: "https://x/y", Status: 500}).Error(); err != "HTTP 500 from https://x/y" {
		t.Error(err)
	}
}

func TestNewHTTPClient(t *testing.T) {
	c := NewHTTPClient(HTTPOptions{Timeout: 3 * time.Second})
	tr := c.Transport.(*http.Transport)
	if c.Timeout != 3*time.Second || c.Jar != nil || c.CheckRedirect != nil || tr.TLSHandshakeTimeout != 0 ||
		tr.DisableKeepAlives || !tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.CipherSuites != nil {
		t.Errorf("plain client: %+v %+v", c, tr)
	}
	c = NewHTTPClient(HTTPOptions{Timeout: time.Second, HandshakeTimeout: 2 * time.Second, Cookies: true,
		NoRedirects: true, RSAKeyExchange: true, NoKeepAlives: true})
	tr = c.Transport.(*http.Transport)
	if c.Jar == nil || c.CheckRedirect == nil || tr.TLSHandshakeTimeout != 2*time.Second || !tr.DisableKeepAlives {
		t.Errorf("client: %+v %+v", c, tr)
	}
	if c.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("a redirect is followed")
	}
	suites := tr.TLSClientConfig.CipherSuites
	if len(suites) < 2 || suites[len(suites)-2] != tls.TLS_RSA_WITH_AES_256_GCM_SHA384 || suites[len(suites)-1] != tls.TLS_RSA_WITH_AES_128_GCM_SHA256 {
		t.Errorf("cipher suites %v", suites)
	}
}
