package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Tests of the web login (auth.go): the session cookie, the middleware in
// front of every route, the login and logout calls, the failed-try limit,
// the bot's token and the user commands.

// authTestSetup points the secrets directory and the bot token at a fresh
// temporary directory and forgets the sessions, failed tries and unlocks
// of earlier tests.
func authTestSetup(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldDir, oldBot := secretsDir, botTokenFile
	secretsDir, botTokenFile = filepath.Join(dir, "secrets"), filepath.Join(dir, "bot", ".api_token")
	authLogins, credentialsUnlocks = newAuthLimiter(), newAuthLimiter()
	authRevokedMu.Lock()
	authRevoked = make(map[string]int64)
	authRevokedMu.Unlock()
	credentialsUnlockMu.Lock()
	credentialsUnlockedUntil = make(map[string]time.Time)
	credentialsUnlockMu.Unlock()
	credentialsMu.Lock()
	credentialsWorkedID = make(map[string]string)
	credentialsMu.Unlock()
	t.Cleanup(func() { secretsDir, botTokenFile = oldDir, oldBot })
}

// authTestUser adds a user with a cheap hash.
func authTestUser(t *testing.T, name, password string) {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	users, _ := authLoadUsers()
	if err := authSaveUsers(append(users, authUser{Name: name, Hash: string(hash)})); err != nil {
		t.Fatal(err)
	}
}

// authTestCookie returns a valid session cookie value of user.
func authTestCookie(t *testing.T, user string) (string, authSession) {
	t.Helper()
	s := authSession{User: user, ID: randomHex(16), Exp: time.Now().Add(time.Hour).Unix()}
	v, err := authSign(s)
	if err != nil {
		t.Fatal(err)
	}
	return v, s
}

func TestAuthSessionCookie(t *testing.T) {
	authTestSetup(t)
	authTestUser(t, "admin", "password1")
	now := time.Now()
	value, s := authTestCookie(t, "admin")
	if got, ok := authVerify(value, now); !ok || got != s {
		t.Fatalf("authVerify(valid) = %+v, %v", got, ok)
	}
	payload, sig, _ := strings.Cut(value, ".")
	other, _ := authSign(authSession{User: "root", ID: s.ID, Exp: s.Exp})
	otherPayload, _, _ := strings.Cut(other, ".")
	for name, v := range map[string]string{
		"another payload":      otherPayload + "." + sig,
		"no signature":         payload,
		"cut signature":        payload + "." + sig[:10],
		"not base64":           "!!!." + sig,
		"empty":                "",
		"signed for no user":   other,
		"expired":              mustSign(t, authSession{User: "admin", ID: "x1", Exp: now.Add(-time.Second).Unix()}),
		"without a session id": mustSign(t, authSession{User: "admin", Exp: now.Add(time.Hour).Unix()}),
	} {
		if _, ok := authVerify(v, now); ok {
			t.Errorf("%s: authVerify accepted it", name)
		}
	}

	// A logged-out session, and the session of a removed user, end
	authRevoke(s, now)
	if _, ok := authVerify(value, now); ok {
		t.Error("a logged-out session is still valid")
	}
	value2, _ := authTestCookie(t, "admin")
	if err := authCommandUserDel("admin"); err != nil {
		t.Fatal(err)
	}
	if _, ok := authVerify(value2, now); ok {
		t.Error("the session of a removed user is still valid")
	}

	// The key file is the scanner's own
	if info, err := os.Stat(filepath.Join(secretsDir, "session.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("session.key: %v, %v; want mode 0600", info.Mode().Perm(), err)
	}
	if info, err := os.Stat(secretsDir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("secrets directory: %v, %v; want mode 0700", info.Mode().Perm(), err)
	}
}

func mustSign(t *testing.T, s authSession) string {
	t.Helper()
	v, err := authSign(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// authTestServer is the middleware in front of a mux whose routes answer
// 200 "ok".
func authTestServer() http.Handler {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }
	for _, p := range []string{"/", "/api/graph", "/api/bot/action", "/login.html", "/login.js", "/app.js"} {
		mux.HandleFunc(p, ok)
	}
	return authMiddleware(mux)
}

func authTestDo(h http.Handler, method, path, cookie string, header map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://scanner:8088"+path, nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAuthMiddleware(t *testing.T) {
	authTestSetup(t)
	h := authTestServer()

	// No user yet: only the login page answers
	for path, want := range map[string]int{"/api/graph": 503, "/": 503, "/app.js": 503, "/login.html": 200, "/login.js": 200} {
		if w := authTestDo(h, "GET", path, "", nil); w.Code != want {
			t.Errorf("no user, GET %s: %d, want %d", path, w.Code, want)
		}
	}

	authTestUser(t, "admin", "password1")
	cookie, _ := authTestCookie(t, "admin")
	cases := []struct {
		method, path, cookie string
		header               map[string]string
		code                 int
		location             string
	}{
		{"GET", "/api/graph", "", nil, 401, ""},
		{"GET", "/", "", nil, 302, "/login.html?next=%2F"},
		{"GET", "/index.html?x=1", "", nil, 302, "/login.html?next=%2Findex.html%3Fx%3D1"},
		{"GET", "/app.js", "", nil, 401, ""},
		{"GET", "/login.html", "", nil, 200, ""},
		{"GET", "/api/graph", "garbage", nil, 401, ""},
		{"GET", "/api/graph", cookie, nil, 200, ""},
		{"GET", "/", cookie, nil, 200, ""},
		{"POST", "/api/graph", cookie, nil, 200, ""},
		{"POST", "/api/graph", cookie, map[string]string{"Origin": "http://scanner:8088"}, 200, ""},
		{"POST", "/api/graph", cookie, map[string]string{"Origin": "http://evil.example"}, 403, ""},
		{"DELETE", "/api/graph", cookie, map[string]string{"Referer": "http://evil.example/page"}, 403, ""},
		{"GET", "/api/graph", cookie, map[string]string{"Origin": "http://evil.example"}, 200, ""},
	}
	for _, c := range cases {
		w := authTestDo(h, c.method, c.path, c.cookie, c.header)
		if w.Code != c.code || (c.location != "" && w.Header().Get("Location") != c.location) {
			t.Errorf("%s %s (cookie %v, %v): %d %q, want %d %q", c.method, c.path, c.cookie != "", c.header,
				w.Code, w.Header().Get("Location"), c.code, c.location)
		}
	}
	if w := authTestDo(h, "GET", "/api/graph", "", nil); !strings.Contains(w.Body.String(), "login required") ||
		w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("API answer without a login: %q %q", w.Header().Get("Content-Type"), w.Body.String())
	}

	// The bot's token opens /api/bot/action only
	os.MkdirAll(filepath.Dir(botTokenFile), 0o700)
	token := randomHex(32)
	os.WriteFile(botTokenFile, []byte(token+"\n"), 0o600)
	bearer := map[string]string{"Authorization": "Bearer " + token}
	if w := authTestDo(h, "POST", "/api/bot/action", "", bearer); w.Code != 200 {
		t.Errorf("bot with its token: %d", w.Code)
	}
	if w := authTestDo(h, "GET", "/api/graph", "", bearer); w.Code != 401 {
		t.Errorf("bot token on another route: %d, want 401", w.Code)
	}
	if w := authTestDo(h, "POST", "/api/bot/action", "", map[string]string{"Authorization": "Bearer " + randomHex(32)}); w.Code != 401 {
		t.Errorf("a wrong bot token: %d, want 401", w.Code)
	}
	os.WriteFile(botTokenFile, []byte("short"), 0o600)
	if w := authTestDo(h, "POST", "/api/bot/action", "", map[string]string{"Authorization": "Bearer short"}); w.Code != 401 {
		t.Errorf("a token file with a short token opens the route: %d", w.Code)
	}
}

func authTestLogin(user, password string, header map[string]string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"user": user, "password": password})
	r := httptest.NewRequest("POST", "http://scanner:8088/api/login", strings.NewReader(string(body)))
	r.RemoteAddr = "10.9.0.7:51000"
	for k, v := range header {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	captureStdoutQuiet(func() { authLoginHandler(w, r) })
	return w
}

// captureStdoutQuiet runs f with the scanner's prints thrown away.
func captureStdoutQuiet(f func()) {
	old := os.Stdout
	null, _ := os.Open(os.DevNull)
	os.Stdout = null
	defer func() { os.Stdout = old; null.Close() }()
	f()
}

func TestAuthLogin(t *testing.T) {
	authTestSetup(t)
	status := func() bool {
		w := httptest.NewRecorder()
		authLoginHandler(w, httptest.NewRequest("GET", "/api/login", nil))
		var v struct{ Users bool }
		json.NewDecoder(w.Body).Decode(&v)
		return v.Users
	}
	if status() {
		t.Error("GET /api/login says a user exists before any was added")
	}
	authTestUser(t, "admin", "password1")
	if !status() {
		t.Error("GET /api/login says no user exists")
	}

	w := authTestLogin("admin", "password1", nil)
	cookies := w.Result().Cookies()
	if w.Code != 200 || len(cookies) != 1 {
		t.Fatalf("good login: %d, cookies %v", w.Code, cookies)
	}
	c := cookies[0]
	if c.Name != sessionCookie || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("session cookie %+v, want HttpOnly, SameSite=Strict, path /", c)
	}
	if s, ok := authVerify(c.Value, time.Now()); !ok || s.User != "admin" ||
		time.Until(time.Unix(s.Exp, 0)) > sessionLifetime || time.Until(time.Unix(s.Exp, 0)) < sessionLifetime-time.Minute {
		t.Errorf("the login's session %+v, %v", s, ok)
	}

	for _, c := range []struct{ user, password string }{{"admin", "password2"}, {"nobody", "password1"}, {"", ""}} {
		if w := authTestLogin(c.user, c.password, nil); w.Code != 401 || len(w.Result().Cookies()) != 0 {
			t.Errorf("login %q/%q: %d, cookies %v; want 401 and none", c.user, c.password, w.Code, w.Result().Cookies())
		}
	}
	if w := authTestLogin("admin", "password1", map[string]string{"Origin": "http://evil.example"}); w.Code != 403 {
		t.Errorf("login from another site's page: %d, want 403", w.Code)
	}

	// The 3 failures above and 2 more lock the address out, also for the
	// right password
	authTestLogin("admin", "x", nil)
	authTestLogin("admin", "x", nil)
	if w := authTestLogin("admin", "password1", nil); w.Code != 429 {
		t.Errorf("login after %d failures: %d, want 429", authMaxFailures, w.Code)
	}
	authLogins.mu.Lock()
	authLogins.fails["10.9.0.7"].until = time.Now().Add(-time.Second)
	authLogins.mu.Unlock()
	if w := authTestLogin("admin", "password1", nil); w.Code != 200 {
		t.Errorf("login once the lockout ended: %d", w.Code)
	}
}

func TestAuthLogout(t *testing.T) {
	authTestSetup(t)
	authTestUser(t, "admin", "password1")
	cookie, s := authTestCookie(t, "admin")
	credentialsUnlock(s, time.Now())
	r := httptest.NewRequest("POST", "/api/logout", nil)
	r = r.WithContext(context.WithValue(r.Context(), authCtxKey{}, s))
	w := httptest.NewRecorder()
	authLogoutHandler(w, r)
	if _, ok := authVerify(cookie, time.Now()); ok {
		t.Error("the session is valid after the logout")
	}
	if credentialsUnlocked(s, time.Now()) {
		t.Error("the Credentials window stays open after the logout")
	}
	if c := w.Result().Cookies(); len(c) != 1 || c[0].MaxAge >= 0 {
		t.Errorf("logout cookies %v, want the session cookie cleared", c)
	}
}

// authTestInput is a file holding the given input, as a command reads it
// from a pipe.
func authTestInput(t *testing.T, input string) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input")
	os.WriteFile(path, []byte(input), 0o600)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestAuthCommands(t *testing.T) {
	authTestSetup(t)
	run := func(f func() error) error {
		var err error
		captureStdoutQuiet(func() { err = f() })
		return err
	}
	if err := run(func() error { return authCommandUserAdd("admin", authTestInput(t, "first-pass\n")) }); err != nil {
		t.Fatal(err)
	}
	if !authCheckPassword(authUserHash("admin"), "first-pass") {
		t.Error("the added user's password does not match")
	}
	if info, err := os.Stat(filepath.Join(secretsDir, "users.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("users.json mode %v (%v), want 0600", info.Mode().Perm(), err)
	}
	data, _ := os.ReadFile(filepath.Join(secretsDir, "users.json"))
	if strings.Contains(string(data), "first-pass") || !regexp.MustCompile(`"hash": "\$2a\$`).Match(data) {
		t.Errorf("users.json holds no bcrypt hash or the password:\n%s", data)
	}

	// Again: a new password, still one user
	run(func() error { return authCommandUserAdd("admin", authTestInput(t, "second-pass")) })
	if users, _ := authLoadUsers(); len(users) != 1 || !authCheckPassword(users[0].Hash, "second-pass") {
		t.Errorf("users after a new password: %+v", users)
	}

	for name, f := range map[string]func() error{
		"short password":  func() error { return authCommandUserAdd("bob", authTestInput(t, "short\n")) },
		"no input":        func() error { return authCommandUserAdd("bob", authTestInput(t, "")) },
		"bad name":        func() error { return authCommandUserAdd("bob smith", authTestInput(t, "long-enough\n")) },
		"remove a nobody": func() error { return authCommandUserDel("bob") },
	} {
		if err := run(f); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if users, _ := authLoadUsers(); len(users) != 1 {
		t.Errorf("users after failed commands: %+v", users)
	}
	if err := run(func() error { return authCommandUserDel("admin") }); err != nil {
		t.Error(err)
	}
	if users, _ := authLoadUsers(); len(users) != 0 {
		t.Errorf("users after the removal: %+v", users)
	}
}

func TestAuthEnsureBotToken(t *testing.T) {
	authTestSetup(t)
	captureStdoutQuiet(authEnsureBotToken) // no bot directory: nothing
	if _, err := os.Stat(botTokenFile); err == nil {
		t.Fatal("a token was made without a bot directory")
	}
	os.MkdirAll(filepath.Dir(botTokenFile), 0o755)
	captureStdoutQuiet(authEnsureBotToken)
	data, err := os.ReadFile(botTokenFile)
	info, _ := os.Stat(botTokenFile)
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{64}\n$`).Match(data) || info.Mode().Perm() != 0o600 {
		t.Fatalf("bot token %q (%v), mode %v", data, err, info.Mode().Perm())
	}
	captureStdoutQuiet(authEnsureBotToken)
	if again, _ := os.ReadFile(botTokenFile); string(again) != string(data) {
		t.Error("an existing bot token was replaced")
	}
}
