package unificontroller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"lldp_scanner/modules"
	"lldp_scanner/modules/kit"
)

// apiBases gives the addresses of the Network Integration API (v1) of the
// application at ip, in the order they are tried (a variable for tests):
// a UniFi OS console (UDM, Cloud Key, ...) serves it on port 443 behind
// its /proxy/network, a self-hosted Network Application 9.x on port 8443.
var apiBases = func(ip string) []string {
	return []string{
		"https://" + net.JoinHostPort(ip, "443") + integrationPath,
		"https://" + net.JoinHostPort(ip, "8443") + integrationPath,
	}
}

// statusURLs gives the status pages of the application at ip, which answer
// with no login (a variable for tests): the self-hosted application's
// https://IP:8443/status and the same page behind a UniFi OS console's
// /proxy/network. They answer
// {"meta":{"rc":"ok","up":true,"server_version":"9.0.114"},"data":[]}.
var statusURLs = func(ip string) []string {
	return []string{
		"https://" + net.JoinHostPort(ip, "8443") + "/status",
		"https://" + net.JoinHostPort(ip, "443") + "/proxy/network/status",
	}
}

const (
	requestTimeout = 10 * time.Second
	probeTimeout   = 3 * time.Second
	// pageLimit is the most items the API gives in one page
	pageLimit = 200
	// maxItems caps a list: past it the rest is not read (this network has
	// some 100 devices and some 1500 clients)
	maxItems = 5000
)

// newHTTPClient is an HTTP client for the application. A redirect is not
// followed: the API answers itself, while a web server that is not the API
// sends to its login page, and Go would send the X-API-KEY header along,
// also to another host.
func newHTTPClient(timeout time.Duration) *http.Client {
	return kit.NewHTTPClient(kit.HTTPOptions{Timeout: timeout, HandshakeTimeout: timeout, NoRedirects: true})
}

// apiClient talks the Network Integration API of one UniFi Network
// application, with an API key in the X-API-KEY header.
type apiClient struct {
	http *http.Client
	base string // "https://10.9.60.5:443/proxy/network/integration/v1"
	key  string
}

// get reads one answer of the API into out. A 401 or 403 (the key is not
// valid, or not for this application) wraps modules.ErrLoginRejected; the
// error never carries the key.
func (c *apiClient) get(ctx context.Context, path string, query url.Values, out any) error {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-KEY", c.key)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: HTTP %d from %s", modules.ErrLoginRejected, resp.StatusCode, u)
	default:
		return &kit.HTTPError{URL: u, Status: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("no JSON answer from %s: %w", u, err)
	}
	return nil
}

// appInfo is the answer of /info: {"applicationVersion":"9.0.114"}.
type appInfo struct {
	ApplicationVersion string `json:"applicationVersion"`
}

// connect finds the API of the application at ip: the first base that
// answers /info with the key. A 401 or 403 there is a refused key (it
// wraps modules.ErrLoginRejected) and ends the search; a base that does
// not answer, answers 404 or answers no JSON (a UniFi OS console with no
// Network application, another web server) is passed for the next.
func connect(ctx context.Context, ip, key string) (*apiClient, appInfo, error) {
	var tried []string
	for _, base := range apiBases(ip) {
		c := &apiClient{http: newHTTPClient(requestTimeout), base: base, key: key}
		var info appInfo
		err := c.get(ctx, "/info", nil, &info)
		if err == nil {
			return c, info, nil
		}
		c.http.CloseIdleConnections()
		if errors.Is(err, modules.ErrLoginRejected) || ctx.Err() != nil {
			return nil, appInfo{}, err
		}
		tried = append(tried, err.Error())
	}
	return nil, appInfo{}, fmt.Errorf("no UniFi Network API at %s (%s)", ip, strings.Join(tried, "; "))
}

// getAll reads every page of a list of the API ("/sites", ...), which
// answers {"offset":0,"limit":200,"count":200,"totalCount":1530,"data":[...]},
// and returns its items, at most maxItems, with the total the API counts
// (more than the items when the list was cut at maxItems).
func getAll[T any](ctx context.Context, c *apiClient, path string) ([]T, int, error) {
	var items []T
	total := 0
	for len(items) < maxItems {
		var page struct {
			Limit      int `json:"limit"`
			TotalCount int `json:"totalCount"`
			Data       []T `json:"data"`
		}
		query := url.Values{"offset": {strconv.Itoa(len(items))}, "limit": {strconv.Itoa(pageLimit)}}
		if err := c.get(ctx, path, query, &page); err != nil {
			return nil, 0, err
		}
		items = append(items, page.Data...)
		total = max(total, page.TotalCount)
		// The last page: an empty one, one that reaches the total, or, from
		// an API that sends no total, one shorter than a full page
		full := pageLimit
		if page.Limit > 0 {
			full = min(page.Limit, pageLimit)
		}
		if len(page.Data) == 0 || (page.TotalCount > 0 && len(items) >= page.TotalCount) ||
			(page.TotalCount == 0 && len(page.Data) < full) {
			break
		}
	}
	if len(items) > maxItems {
		items = items[:maxItems]
	}
	return items, max(total, len(items)), nil
}

// ─── Probe ────────────────────────────────────────────────────────────────────

// isStatusPage tells whether u answers as the application's status page:
// JSON with a meta.server_version ("9.0.114").
func isStatusPage(ctx context.Context, hc *http.Client, u string) bool {
	var status struct {
		Meta struct {
			ServerVersion string `json:"server_version"`
		} `json:"meta"`
	}
	code, ok := probeGet(ctx, hc, u, &status)
	return ok && code == http.StatusOK && strings.TrimSpace(status.Meta.ServerVersion) != ""
}

// refusesWithoutKey tells whether the API's /info at base refuses a
// request with no key as the application does: 401 (or 403) with its own
// error JSON, of the Integration API
// ({"statusCode":401,"statusName":"UNAUTHORIZED","code":"api.authentication.missing-credentials",...})
// or of the application's older API ({"meta":{"rc":"error","msg":"api.err.LoginRequired"}}).
// A web server that refuses every path, also with JSON, says neither.
func refusesWithoutKey(ctx context.Context, hc *http.Client, base string) bool {
	var refusal struct {
		StatusCode int    `json:"statusCode"`
		StatusName string `json:"statusName"`
		Code       string `json:"code"`
		Meta       struct {
			Msg string `json:"msg"`
		} `json:"meta"`
	}
	code, ok := probeGet(ctx, hc, base+"/info", &refusal)
	if !ok || (code != http.StatusUnauthorized && code != http.StatusForbidden) {
		return false
	}
	return (refusal.StatusCode == code && refusal.StatusName != "") ||
		strings.HasPrefix(refusal.Code, "api.") ||
		strings.HasPrefix(refusal.Meta.Msg, "api.err.")
}

// integrationPath is where a UniFi OS console serves the application's
// Integration API.
const integrationPath = "/proxy/network/integration/v1"

// unifiOSConsole tells whether base is the application behind a UniFi OS
// console (UDM, Cloud Key, UniFi OS Server): the console's own page, titled
// "UniFi OS", and its gateway refusing the API with no key as
// {"error":{"code":401,"message":"Unauthorized"}} (172.15.1.2 does, and
// has no status page that answers with no login). Both must hold: another
// web server may refuse in the same words.
func unifiOSConsole(ctx context.Context, hc *http.Client, base string) bool {
	root, ok := strings.CutSuffix(base, integrationPath)
	if !ok {
		return false
	}
	var refusal struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	code, ok := probeGet(ctx, hc, base+"/info", &refusal)
	if !ok || (code != http.StatusUnauthorized && code != http.StatusForbidden) || refusal.Error.Code != code {
		return false
	}
	return probeTitle(ctx, hc, root+"/") == "UniFi OS"
}

var htmlTitle = regexp.MustCompile(`(?is)<title>\s*([^<]*?)\s*</title>`)

// probeTitle is the title of the HTML page at u, "" when there is none.
func probeTitle(ctx context.Context, hc *http.Client, u string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	resp, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	if m := htmlTitle.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// probeGet asks u with no key and reads its answer, a JSON object, into
// out: the HTTP status, and false when there is no such answer.
func probeGet(ctx context.Context, hc *http.Client, u string, out any) (int, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(data)), "{") || json.Unmarshal(data, out) != nil {
		return resp.StatusCode, false
	}
	return resp.StatusCode, true
}
