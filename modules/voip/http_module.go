package voip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"lldp_scanner/modules"
	"lldp_scanner/modules/kit"
)

func init() {
	modules.Register(GrandstreamModule{})
	modules.Register(YealinkModule{})
}

// The phones' modules recognize their devices without a login.
var (
	_ modules.Prober = GrandstreamModule{}
	_ modules.Prober = YealinkModule{}
)

// GrandstreamModule probes and inspects Grandstream GXP/GRP IP phones over HTTP/HTTPS.
type GrandstreamModule struct {
	BaseURL string // optional test override ("http://127.0.0.1:PORT")
}

func (GrandstreamModule) ID() string       { return "grandstream" }
func (GrandstreamModule) Label() string    { return "Grandstream VoIP" }
func (GrandstreamModule) Type() string     { return "voip-grandstream" }
func (GrandstreamModule) Protocol() string { return "https" }

func (GrandstreamModule) Actions() []modules.Action {
	return []modules.Action{
		{ID: "detect", Label: "🔎 Phone Status"},
	}
}

// Probe recognizes Grandstream's embedded web server without logging in
// (modules.Prober: the scanner offers the module for a device it answers).
func (m GrandstreamModule) Probe(ctx context.Context, ip string) bool {
	hdr, body, status, err := fetchRoot(ctx, m.BaseURL, ip)
	if err != nil || status == 0 {
		return false
	}
	server := strings.ToLower(hdr.Get("Server"))
	low := strings.ToLower(body)
	if strings.Contains(server, "grandstream") || strings.Contains(low, "grandstream") {
		return true
	}
	// Grandstream GXP/GRP GWT web UI served by mini_httpd
	return strings.Contains(server, "mini_httpd") && strings.Contains(low, "webapp/webapp.nocache.js")
}

func (m GrandstreamModule) Run(ctx context.Context, req modules.Request) (modules.Result, error) {
	if req.Action != "detect" {
		return modules.Result{}, fmt.Errorf("unknown action %q", req.Action)
	}
	client, base, err := newPhoneHTTPClient(ctx, m.BaseURL, req.IP)
	if err != nil {
		return modules.Result{}, err
	}
	defer client.CloseIdleConnections()

	var res modules.Result
	res.AddFact("Vendor", "Grandstream")
	res.AddFact("Web UI", base)

	// Authenticate via Grandstream CGI API (/cgi-bin/dologin)
	form := url.Values{"username": {req.Login.Username}, "password": {req.Login.Password}}
	resp, err := postForm(ctx, client, base+"/cgi-bin/dologin", form)
	if err != nil {
		return res, err
	}
	var loginAns struct {
		Response string `json:"response"`
		Body     struct {
			Sid string `json:"sid"`
		} `json:"body"`
	}
	// An answer that is no JSON is no login: an older firmware without
	// the CGI API, or another web server (it used to count as a login that
	// worked)
	if err := json.Unmarshal(resp, &loginAns); err != nil {
		return res, fmt.Errorf("no Grandstream CGI API answer from %s/cgi-bin/dologin (%d bytes, not JSON): the login is not known to work", base, len(resp))
	}
	if strings.EqualFold(loginAns.Response, "error") || loginAns.Body.Sid == "" {
		return res, fmt.Errorf("%w: Grandstream web login refused", modules.ErrLoginRejected)
	}
	sid := url.QueryEscape(loginAns.Body.Sid)
	if statusBytes, err := getBody(ctx, client, base+"/cgi-bin/api-get_phone_status?passcode=&sid="+sid); err == nil {
		var st struct {
			Body map[string]any `json:"body"`
		}
		if json.Unmarshal(statusBytes, &st) == nil {
			for _, k := range []string{"product_model", "prog_version", "boot_version", "mac", "ip", "system-time"} {
				if v, ok := st.Body[k]; ok && fmt.Sprint(v) != "" {
					res.AddFact(k, fmt.Sprint(v))
				}
			}
		}
	}
	res.Summary = fmt.Sprintf("Grandstream phone at %s authenticated via CGI API", req.IP)
	return res, nil
}

// YealinkModule probes and inspects Yealink SIP-T/VP/W series IP phones over HTTP/HTTPS.
type YealinkModule struct {
	BaseURL string // optional test override
}

func (YealinkModule) ID() string       { return "yealink" }
func (YealinkModule) Label() string    { return "Yealink VoIP" }
func (YealinkModule) Type() string     { return "voip-yealink" }
func (YealinkModule) Protocol() string { return "https" }

func (YealinkModule) Actions() []modules.Action {
	return []modules.Action{
		{ID: "detect", Label: "🔎 Phone Status"},
	}
}

// Probe recognizes Yealink's web interface without logging in
// (modules.Prober).
func (m YealinkModule) Probe(ctx context.Context, ip string) bool {
	hdr, body, status, err := fetchRoot(ctx, m.BaseURL, ip)
	if err != nil || status == 0 {
		return false
	}
	server := strings.ToLower(hdr.Get("Server"))
	auth := strings.ToLower(hdr.Get("WWW-Authenticate"))
	low := strings.ToLower(body)
	return strings.Contains(server, "yealink") ||
		strings.Contains(auth, "yealink") ||
		strings.Contains(low, "yealink") ||
		strings.Contains(low, "/servlet?m=mod_listener") ||
		strings.Contains(low, "/yl_login")
}

func (m YealinkModule) Run(ctx context.Context, req modules.Request) (modules.Result, error) {
	if req.Action != "detect" {
		return modules.Result{}, fmt.Errorf("unknown action %q", req.Action)
	}
	client, base, err := newPhoneHTTPClient(ctx, m.BaseURL, req.IP)
	if err != nil {
		return modules.Result{}, err
	}
	defer client.CloseIdleConnections()

	var res modules.Result
	res.AddFact("Vendor", "Yealink")
	res.AddFact("Web UI", base)

	// The login is an AJAX call: it answers, it does not redirect. A
	// redirect (back to the login page) is a refused login; followed, its
	// page had none of the words below and counted as one that worked.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	form := url.Values{"username": {req.Login.Username}, "pwd": {req.Login.Password}}
	body, err := postForm(ctx, &noRedirect, base+"/servlet?m=mod_listener&p=login&q=login", form)
	if errors.Is(err, errRedirected) {
		return res, fmt.Errorf("%w: Yealink web login refused (%v)", modules.ErrLoginRejected, err)
	}
	if err != nil {
		return res, err
	}
	txt := strings.TrimSpace(string(body))
	low := strings.ToLower(txt)
	if strings.Contains(low, "fail") || strings.Contains(low, "error") || strings.Contains(low, "locked") {
		return res, fmt.Errorf("%w: Yealink web login refused", modules.ErrLoginRejected)
	}
	res.Summary = fmt.Sprintf("Yealink phone at %s authenticated via Web UI", req.IP)
	return res, nil
}

// phoneBase is the web UI address of a phone at ip by scheme (an IPv6
// address in brackets).
func phoneBase(scheme, ip string) string {
	port := map[string]string{"https": "443", "http": "80"}[scheme]
	return scheme + "://" + net.JoinHostPort(ip, port)
}

// newPhoneHTTPClient is the client of one Run (its caller closes its idle
// connections) and the web UI address that answered.
func newPhoneHTTPClient(ctx context.Context, override, ip string) (*http.Client, string, error) {
	client := kit.NewHTTPClient(kit.HTTPOptions{Timeout: 4 * time.Second, Cookies: true})
	if override != "" {
		return client, strings.TrimRight(override, "/"), nil
	}
	for _, scheme := range []string{"https", "http"} {
		base := phoneBase(scheme, ip)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			return client, base, nil
		}
	}
	client.CloseIdleConnections()
	return nil, "", fmt.Errorf("unreachable HTTP/HTTPS web interface on %s", ip)
}

// fetchRoot reads the web UI's root page (http, then https), with no
// connection kept.
func fetchRoot(ctx context.Context, override, ip string) (http.Header, string, int, error) {
	client := kit.NewHTTPClient(kit.HTTPOptions{Timeout: 2 * time.Second, NoKeepAlives: true})
	candidates := []string{phoneBase("http", ip) + "/", phoneBase("https", ip) + "/"}
	if override != "" {
		candidates = []string{strings.TrimRight(override, "/") + "/"}
	}
	var lastErr error
	for _, target := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return resp.Header, string(data), resp.StatusCode, nil
	}
	return nil, "", 0, lastErr
}

func getBody(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 16384))
}

func postForm(ctx context.Context, client *http.Client, target string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, modules.ErrLoginRejected
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("%w: HTTP %d to %q", errRedirected, resp.StatusCode, resp.Header.Get("Location"))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16384))
}

// errRedirected is a POST answered with a redirect (a client that does not
// follow redirects).
var errRedirected = errors.New("redirected")
