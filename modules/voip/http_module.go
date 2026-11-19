package voip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// CheckWebUI recognizes Grandstream's embedded web server without logging in.
func (m GrandstreamModule) CheckWebUI(ctx context.Context, ip string) bool {
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
	if json.Unmarshal(resp, &loginAns) == nil {
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

	res.Summary = fmt.Sprintf("Grandstream web interface reachable at %s", base)
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

// CheckWebUI recognizes Yealink's web interface without logging in.
func (m YealinkModule) CheckWebUI(ctx context.Context, ip string) bool {
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

	var res modules.Result
	res.AddFact("Vendor", "Yealink")
	res.AddFact("Web UI", base)

	form := url.Values{"username": {req.Login.Username}, "pwd": {req.Login.Password}}
	body, err := postForm(ctx, client, base+"/servlet?m=mod_listener&p=login&q=login", form)
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

func newPhoneHTTPClient(ctx context.Context, override, ip string) (*http.Client, string, error) {
	client := kit.NewHTTPClient(kit.HTTPOptions{Timeout: 4 * time.Second, Cookies: true})
	if override != "" {
		return client, strings.TrimRight(override, "/"), nil
	}
	for _, scheme := range []string{"https", "http"} {
		base := scheme + "://" + ip
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
	return nil, "", fmt.Errorf("unreachable HTTP/HTTPS web interface on %s", ip)
}

func fetchRoot(ctx context.Context, override, ip string) (http.Header, string, int, error) {
	client := kit.NewHTTPClient(kit.HTTPOptions{Timeout: 2 * time.Second})
	candidates := []string{"http://" + ip + "/", "https://" + ip + "/"}
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
	return io.ReadAll(io.LimitReader(resp.Body, 16384))
}
