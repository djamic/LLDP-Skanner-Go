// Package kit is what the device modules share: their HTTP client for the
// devices of the local network and its status error, the words of their
// results, a MAC address's one spelling and the LLDP capability bits.
package kit

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"time"
)

// HTTPOptions is how a module's HTTP client talks to a device.
type HTTPOptions struct {
	Timeout          time.Duration // a request's, its answer read included
	HandshakeTimeout time.Duration // the TLS handshake's own; 0 = none
	Cookies          bool          // a cookie jar, for a session cookie
	// NoRedirects makes a redirect the answer: an API answers itself, while
	// a web server that is not the API sends to its login page, and Go
	// would send a key header along, also to another host.
	NoRedirects bool
	// RSAKeyExchange offers, after Go's secure TLS 1.2 suites, AES-GCM with
	// RSA key exchange, which Go no longer offers unless asked (Go 1.22
	// took it off the defaults, Go 1.25 lists it as insecure): the only TLS
	// of some embedded web servers (Kerio Embedded WebServer 1.0).
	RSAKeyExchange bool
	NoKeepAlives   bool // a connection per request
}

// rsaCipherSuites are Go's secure suites, then AES-GCM with RSA key exchange.
var rsaCipherSuites = func() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	return append(ids, tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_GCM_SHA256)
}()

// NewHTTPClient is an HTTP client with options o. A device's certificate is
// its own self-signed one, so it is not checked: the scanner only talks to
// devices of the local network.
func NewHTTPClient(o HTTPOptions) *http.Client {
	tc := &tls.Config{InsecureSkipVerify: true}
	if o.RSAKeyExchange {
		tc.CipherSuites = rsaCipherSuites
	}
	c := &http.Client{
		Timeout: o.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:     tc,
			TLSHandshakeTimeout: o.HandshakeTimeout,
			DisableKeepAlives:   o.NoKeepAlives,
		},
	}
	if o.Cookies {
		c.Jar, _ = cookiejar.New(nil)
	}
	if o.NoRedirects {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

// HTTPError is an HTTP answer a module did not want (other than 200, or a
// refused login it tells as modules.ErrLoginRejected).
type HTTPError struct {
	URL    string
	Status int
}

func (e *HTTPError) Error() string { return fmt.Sprintf("HTTP %d from %s", e.Status, e.URL) }

// Plural is "1 host", "2 hosts".
func Plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// FirstOf is the first of values that is not blank, trimmed; "" when none.
func FirstOf(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// HasWord reports whether s contains w as a whole word (case-insensitive):
// the bytes around the match are not letters, digits, apostrophes or
// non-ASCII.
func HasWord(s, w string) bool {
	s = strings.ToLower(s)
	w = strings.ToLower(w)
	if w == "" {
		return false
	}
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(w)
		if (j == 0 || !isWordByte(s[j-1])) && (end == len(s) || !isWordByte(s[end])) {
			return true
		}
		i = j + 1
	}
}

func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '\'' || b >= 0x80
}

// NormMAC is a MAC address in canonical form ("00:0b:82:12:34:56") from
// any of the usual spellings (colons, dashes, Cisco dots, spaces, none),
// "" when s is none.
func NormMAC(s string) string {
	var hex []byte
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex = append(hex, byte(r))
		case r == ':' || r == '-' || r == '.' || r == ' ':
		default:
			return ""
		}
	}
	if len(hex) != 12 {
		return ""
	}
	parts := make([]string, 6)
	for i := range parts {
		parts[i] = string(hex[2*i : 2*i+2])
	}
	return strings.Join(parts, ":")
}

// LLDP system capability bits (IEEE 802.1AB LldpSystemCapabilitiesMap, the
// first octet of lldpRemSysCapEnabled).
const (
	LLDPCapBridge = 0x80 >> 2 // 0x20: a bridge, also the 2-port PC bridge of a desk phone
	LLDPCapWLANAP = 0x80 >> 3 // 0x10: a wireless access point
	LLDPCapRouter = 0x80 >> 4 // 0x08: a router
	LLDPCapPhone  = 0x80 >> 5 // 0x04: a telephone
)
