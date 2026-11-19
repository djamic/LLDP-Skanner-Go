package keriooperator

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"slices"
	"strings"
	"time"

	"lldp_scanner/modules"
)

// adminBase gives the administration of the PBX at ip (a variable for
// tests): its web client and its API are on port 4021 under /admin.
var adminBase = func(ip string) string {
	return "https://" + net.JoinHostPort(ip, "4021") + "/admin"
}

const (
	requestTimeout = 15 * time.Second
	probeTimeout   = 3 * time.Second
	// pageLimit is the most rows asked for in one page
	pageLimit = 500
	// maxItems caps a list: past it the rest is not read
	maxItems = 5000
	// historyLimit is how many of the newest calls are read for the
	// phones' addresses
	historyLimit = 1000
)

// application is how the scanner names itself to Session.login.
var application = map[string]string{"name": "LLDP scanner", "vendor": "lldp_scanner", "version": "1.0"}

// cipherSuites are the TLS 1.2 suites offered: Go's secure ones, then
// AES-GCM with RSA key exchange, which Go no longer offers unless asked
// (Go 1.22 took it off the defaults, Go 1.25 lists it as insecure). The
// PBX's "Kerio Embedded WebServer 1.0" speaks TLS 1.2 with AES256-GCM-SHA384
// (TLS_RSA_WITH_AES_256_GCM_SHA384) only: the default suites end in a
// handshake failure.
var cipherSuites = func() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	return append(ids, tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_GCM_SHA256)
}()

// newHTTPClient is an HTTP client for the PBX, with the cookie jar the
// session cookie needs. Its certificate is its own self-signed one, so it
// is not checked: the scanner only talks to devices of the local network.
// A redirect is not followed: the API answers itself, while a web server
// that is not the API sends to a login page.
func newHTTPClient(timeout time.Duration) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout: timeout,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, CipherSuites: cipherSuites},
			TLSHandshakeTimeout: timeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// client talks the administration API (JSON-RPC 2.0) of one PBX, in a
// session: Session.login gives a token for the X-Token header and a
// session cookie, and every later call needs both.
type client struct {
	http  *http.Client
	url   string // "https://172.20.16.97:4021/admin/api/jsonrpc/"
	token string
	id    int
}

// rpcError is an error the API answers: {"code":-32001,"message":"Invalid
// session."}.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("%s (error %d)", e.Message, e.Code) }

// httpError is an HTTP answer other than 200.
type httpError struct {
	URL    string
	Status int
}

func (e *httpError) Error() string { return fmt.Sprintf("HTTP %d from %s", e.Status, e.URL) }

// call runs one method with params and reads its result into out (nil:
// the result is not read). An error of the API is an *rpcError, wrapped
// with the method; no error carries the request, so none carries the
// password.
func (c *client) call(ctx context.Context, method string, params any, out any) error {
	c.id++
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("X-Token", c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &httpError{URL: c.url, Status: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	var ans struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(data, &ans); err != nil {
		return fmt.Errorf("no JSON-RPC answer from %s: %w", c.url, err)
	}
	if ans.Error != nil {
		return fmt.Errorf("%s: %w", method, ans.Error)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(ans.Result, out); err != nil {
		return fmt.Errorf("%s: unexpected result: %w", method, err)
	}
	return nil
}

// login opens a session on the PBX at ip with l. An answer of the API that
// refuses it wraps modules.ErrLoginRejected (the scanner tries the next
// login); a PBX that does not answer is another error.
func login(ctx context.Context, ip string, l modules.Login) (*client, error) {
	user := strings.TrimSpace(l.Username)
	if user == "" {
		return nil, fmt.Errorf("%w: no user name (an Operator account logs in)", modules.ErrLoginRejected)
	}
	c := &client{http: newHTTPClient(requestTimeout), url: adminBase(ip) + "/api/jsonrpc/"}
	var ans struct {
		Token string `json:"token"`
	}
	err := c.call(ctx, "Session.login", map[string]any{"userName": user, "password": l.Password, "application": application}, &ans)
	if re := (*rpcError)(nil); errors.As(err, &re) {
		c.http.CloseIdleConnections()
		return nil, fmt.Errorf("%w: %s", modules.ErrLoginRejected, re.Message)
	}
	if err == nil && ans.Token == "" {
		err = errors.New("Session.login gave no token")
	}
	if err != nil {
		c.http.CloseIdleConnections()
		return nil, err
	}
	c.token = ans.Token
	return c, nil
}

// close ends the session.
func (c *client) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.call(ctx, "Session.logout", map[string]any{}, nil)
	c.http.CloseIdleConnections()
}

// row is one item of a list, its fields as the API sends them: the types
// are not documented, so each is read as text when it is used (text).
type row map[string]json.RawMessage

// text is the first of keys the row has a value for, as text.
func (r row) text(keys ...string) string {
	for _, k := range keys {
		if t := rawText(r[k]); t != "" {
			return t
		}
	}
	return ""
}

// flag reads a yes/no field: true, 1 or "true".
func (r row) flag(key string) bool {
	switch strings.ToLower(rawText(r[key])) {
	case "true", "1", "yes":
		return true
	}
	return false
}

// secretKey reports whether a field may hold a password: it is never
// shown.
func secretKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.Contains(k, "pin")
}

// rawText is a JSON value as text: a string trimmed, a number or a boolean
// as JSON writes it, a list joined by ", ", an object as its "key: value"
// pairs (no field that may hold a password), null "".
func rawText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	switch raw[0] {
	case '"':
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return strings.TrimSpace(s)
		}
	case '[':
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) == nil {
			var parts []string
			for _, it := range items {
				if t := rawText(it); t != "" {
					parts = append(parts, t)
				}
			}
			return strings.Join(parts, ", ")
		}
	case '{':
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) == nil {
			var parts []string
			for _, k := range slices.Sorted(maps.Keys(obj)) {
				if t := rawText(obj[k]); t != "" && !secretKey(k) {
					parts = append(parts, k+": "+t)
				}
			}
			return strings.Join(parts, ", ")
		}
	}
	return string(raw)
}

// list reads a list method page by page: params {"query": query with start
// and limit}, the rows in result[root], their count in result.totalItems.
// A page may be shorter than asked: the next starts where it stopped,
// until the count is read (or, with no count, a page is short). It reads
// maxItems rows at most; total is the count the API tells (the rows read
// when it tells none).
func (c *client) list(ctx context.Context, method, root string, query map[string]any) (rows []row, total int, err error) {
	for start := 0; ; {
		q := maps.Clone(query)
		q["start"], q["limit"] = start, pageLimit
		var res map[string]json.RawMessage
		if err := c.call(ctx, method, map[string]any{"query": q}, &res); err != nil {
			return rows, max(total, len(rows)), err
		}
		raw, ok := res[root]
		if !ok {
			return rows, max(total, len(rows)), fmt.Errorf("%s: no %q in its result", method, root)
		}
		var page []row
		if err := json.Unmarshal(raw, &page); err != nil {
			return rows, max(total, len(rows)), fmt.Errorf("%s: unexpected %q: %w", method, root, err)
		}
		json.Unmarshal(res["totalItems"], &total)
		rows = append(rows, page...)
		start += len(page)
		if len(page) == 0 || start >= maxItems || (total > 0 && start >= total) || (total == 0 && len(page) < pageLimit) {
			return rows, max(total, len(rows)), nil
		}
	}
}

// listFields reads a list asking for fields, as the web client does; an
// API that refuses the query is asked again with no fields (all of them).
func (c *client) listFields(ctx context.Context, method, root string, fields []string) ([]row, int, error) {
	rows, total, err := c.list(ctx, method, root, map[string]any{"fields": fields})
	if re := (*rpcError)(nil); errors.As(err, &re) && len(rows) == 0 {
		return c.list(ctx, method, root, map[string]any{})
	}
	return rows, total, err
}
