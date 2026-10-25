package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ─── Web login ────────────────────────────────────────────────────────────────
//
// Every page and API of the web server needs a login (authMiddleware): a
// user of secrets/users.json (bcrypt hashes, written by --user-add) gets a
// session cookie signed with secrets/session.key. The Telegram bot calls
// /api/bot/action with the token of bot/.api_token instead. The secrets
// directory is the scanner's own: 0700, its files 0600 (the scanner and
// its commands run as root).

// secretsDir holds the login and credential files (a variable for tests).
var secretsDir = "secrets"

// botTokenFile is the token the Telegram bot sends to /api/bot/action; its
// owner is the bot's user (a variable for tests).
var botTokenFile = filepath.Join("bot", ".api_token")

const (
	sessionCookie   = "lldp_session"
	sessionLifetime = 12 * time.Hour
	authMaxFailures = 5               // failed tries of one address before it waits
	authLockout     = 5 * time.Minute // how long it waits then
	authMinPassword = 8
)

// authUserName is the form of a login name.
var authUserName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// ─── Secrets files ────────────────────────────────────────────────────────────

// secretsWrite writes a file of the secrets directory atomically, readable
// by its owner only, and makes the directory (0700) when it is missing.
func secretsWrite(name string, data []byte) error {
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(secretsDir, name+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // fails harmlessly after the rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(secretsDir, name))
}

// secretsKeyMu guards the making of the key files (secretsKey).
var secretsKeyMu sync.Mutex

// secretsKey returns the 32 random bytes of a key file of the secrets
// directory, made at first use.
func secretsKey(name string) ([]byte, error) {
	secretsKeyMu.Lock()
	defer secretsKeyMu.Unlock()
	path := filepath.Join(secretsDir, name)
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("%s has %d bytes, want 32", path, len(key))
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := secretsWrite(name, key); err != nil {
		return nil, err
	}
	return key, nil
}

// randomHex is n random bytes in hex.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on Linux
	}
	return hex.EncodeToString(b)
}

// ─── Users ────────────────────────────────────────────────────────────────────

// authUser is one login of secrets/users.json.
type authUser struct {
	Name    string    `json:"name"`
	Hash    string    `json:"hash"` // bcrypt
	Created time.Time `json:"created"`
}

type authUsersFile struct {
	Users []authUser `json:"users"`
}

// authLoadUsers reads secrets/users.json; no file is no user. The file is
// read on every check, so a user added or removed by a command counts at
// once, without a restart.
func authLoadUsers() ([]authUser, error) {
	path := filepath.Join(secretsDir, "users.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f authUsersFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f.Users, nil
}

func authSaveUsers(users []authUser) error {
	data, err := json.MarshalIndent(authUsersFile{Users: users}, "", "  ")
	if err != nil {
		return err
	}
	return secretsWrite("users.json", data)
}

// authUserHash returns the bcrypt hash of user, or "" when there is none.
func authUserHash(name string) string {
	users, err := authLoadUsers()
	if err != nil {
		fmt.Printf("⚠️  [Auth] %v\n", err)
		return ""
	}
	for _, u := range users {
		if u.Name == name {
			return u.Hash
		}
	}
	return ""
}

// authDummyHash is compared when the user does not exist, so a wrong name
// takes as long as a wrong password.
var authDummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte(randomHex(16)), bcrypt.DefaultCost)
	return h
})

// authCheckPassword reports whether password is the one of hash (a bcrypt
// hash; "" never matches, after the same work).
func authCheckPassword(hash, password string) bool {
	if hash == "" {
		bcrypt.CompareHashAndPassword(authDummyHash(), []byte(password))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ─── Sessions ─────────────────────────────────────────────────────────────────

// authSession is the content of a session cookie, signed with
// secrets/session.key (HMAC-SHA256), so it outlives a restart.
type authSession struct {
	User string `json:"u"`
	ID   string `json:"sid"`
	Exp  int64  `json:"exp"` // unix seconds
}

// authRevoked holds the sessions logged out before they expired, by id
// (guarded by authRevokedMu).
var (
	authRevokedMu sync.Mutex
	authRevoked   = make(map[string]int64)
)

// authSign gives the cookie value of s: payload and signature in base64.
func authSign(s authSession) (string, error) {
	key, err := secretsKey("session.key")
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(mac.Sum(nil)), nil
}

// authVerify returns the session of a cookie value: its signature is
// right, it has not expired or been logged out, and its user still exists.
func authVerify(value string, now time.Time) (authSession, bool) {
	var s authSession
	p, m, ok := strings.Cut(value, ".")
	if !ok {
		return s, false
	}
	enc := base64.RawURLEncoding
	payload, err1 := enc.DecodeString(p)
	sig, err2 := enc.DecodeString(m)
	key, err3 := secretsKey("session.key")
	if err1 != nil || err2 != nil || err3 != nil {
		return s, false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(payload, &s) != nil {
		return s, false
	}
	if s.ID == "" || now.Unix() >= s.Exp {
		return s, false
	}
	authRevokedMu.Lock()
	_, revoked := authRevoked[s.ID]
	authRevokedMu.Unlock()
	if revoked || authUserHash(s.User) == "" {
		return s, false
	}
	return s, true
}

// authRevoke logs a session out until it would have expired.
func authRevoke(s authSession, now time.Time) {
	authRevokedMu.Lock()
	defer authRevokedMu.Unlock()
	for id, exp := range authRevoked {
		if now.Unix() >= exp {
			delete(authRevoked, id)
		}
	}
	authRevoked[s.ID] = s.Exp
}

// authCtxKey is the request context key of the session (authMiddleware).
type authCtxKey struct{}

// authSessionOf returns the session authMiddleware found for the request.
func authSessionOf(r *http.Request) (authSession, bool) {
	s, ok := r.Context().Value(authCtxKey{}).(authSession)
	return s, ok
}

// ─── Failed tries ─────────────────────────────────────────────────────────────

// authLimiter counts failed password tries by client address: after
// authMaxFailures the address waits authLockout.
type authLimiter struct {
	mu    sync.Mutex
	fails map[string]*authFails
}

type authFails struct {
	n     int
	until time.Time
}

func newAuthLimiter() *authLimiter { return &authLimiter{fails: make(map[string]*authFails)} }

func (l *authLimiter) blocked(addr string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[addr]
	return f != nil && now.Before(f.until)
}

func (l *authLimiter) fail(addr string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[addr]
	if f == nil {
		f = &authFails{}
		l.fails[addr] = f
	}
	if f.n++; f.n >= authMaxFailures {
		f.n, f.until = 0, now.Add(authLockout)
	}
}

func (l *authLimiter) succeed(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, addr)
}

// authLogins counts the failed logins.
var authLogins = newAuthLimiter()

// authClientAddr is the address a request comes from (the scanner has no
// proxy in front of it).
func authClientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ─── Middleware ───────────────────────────────────────────────────────────────

// authPublic are the paths served without a login: the login page with its
// files, and the login call.
var authPublic = map[string]bool{
	"/login.html": true, "/login.css": true, "/login.js": true, "/api/login": true, "/favicon.ico": true,
}

// authMiddleware lets a request through with a valid session cookie, the
// bot's token on /api/bot/action, or to a public path. Otherwise an API
// call gets 401, a page a redirect to the login page, and while no user
// exists every request gets 503 with the command that adds one. A request
// that changes something (not GET or HEAD) from a page of another origin
// gets 403.
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authPublic[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/api/bot/action" && authBotToken(r) {
			next.ServeHTTP(w, r)
			return
		}
		var s authSession
		ok := false
		if c, err := r.Cookie(sessionCookie); err == nil {
			s, ok = authVerify(c.Value, time.Now())
		}
		if !ok {
			authDeny(w, r)
			return
		}
		if !authSameOrigin(r) {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authCtxKey{}, s)))
	})
}

// authDeny answers a request without a valid login.
func authDeny(w http.ResponseWriter, r *http.Request) {
	api := strings.HasPrefix(r.URL.Path, "/api/")
	if users, _ := authLoadUsers(); len(users) == 0 {
		msg := "no web user yet: run sudo ./lldp_scanner --user-add NAME on the server"
		if api {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": msg})
			return
		}
		http.Error(w, msg, http.StatusServiceUnavailable)
		return
	}
	switch {
	case api:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "login required"})
	case r.URL.Path == "/" || strings.HasSuffix(r.URL.Path, ".html"):
		http.Redirect(w, r, "/login.html?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	default:
		http.Error(w, "login required", http.StatusUnauthorized)
	}
}

// authSameOrigin reports whether a request may change something: GET and
// HEAD may, other methods when they come from this server's pages
// (authFromHere).
func authSameOrigin(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead || authFromHere(r)
}

// authFromHere reports whether the page that sent the request is of this
// server (Origin, else Referer); a client that sends neither is no browser
// page.
func authFromHere(r *http.Request) bool {
	from := r.Header.Get("Origin")
	if from == "" {
		from = r.Header.Get("Referer")
	}
	if from == "" {
		return true
	}
	u, err := url.Parse(from)
	return err == nil && u.Host == r.Host
}

// authBotToken reports whether the request carries the bot's token
// ("Authorization: Bearer <token of bot/.api_token>").
func authBotToken(r *http.Request) bool {
	data, err := os.ReadFile(botTokenFile)
	token := strings.TrimSpace(string(data))
	if err != nil || len(token) < 32 {
		return false
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// authEnsureBotToken makes bot/.api_token when it is missing: a random
// token, readable by the owner of the bot directory only, who runs the bot.
func authEnsureBotToken() {
	if _, err := os.Stat(botTokenFile); err == nil || !errors.Is(err, os.ErrNotExist) {
		return
	}
	dir := filepath.Dir(botTokenFile)
	info, err := os.Stat(dir)
	if err != nil {
		return // no bot here
	}
	if err := os.WriteFile(botTokenFile, []byte(randomHex(32)+"\n"), 0o600); err != nil {
		fmt.Printf("⚠️  [Auth] %s: %v\n", botTokenFile, err)
		return
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		os.Chown(botTokenFile, int(st.Uid), int(st.Gid))
	}
	fmt.Printf("🔐 [Auth] Bot API token made: %s\n", botTokenFile)
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// authLoginHandler: GET tells the login page whether a user exists, POST
// {"user", "password"} logs in and sets the session cookie.
func authLoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		users, _ := authLoadUsers()
		json.NewEncoder(w).Encode(map[string]bool{"users": len(users) > 0})
	case http.MethodPost:
		if !authSameOrigin(r) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "cross-origin request refused"})
			return
		}
		addr, now := authClientAddr(r), time.Now()
		if authLogins.blocked(addr, now) {
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": "too many failed logins: wait a few minutes"})
			return
		}
		var req struct {
			User     string `json:"user"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request"})
			return
		}
		if !authCheckPassword(authUserHash(req.User), req.Password) {
			authLogins.fail(addr, now)
			fmt.Printf("🔐 [Auth] Failed login for %q from %s\n", req.User, addr)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "wrong user or password"})
			return
		}
		authLogins.succeed(addr)
		s := authSession{User: req.User, ID: randomHex(16), Exp: now.Add(sessionLifetime).Unix()}
		value, err := authSign(s)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "session key: " + err.Error()})
			return
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: "/", Expires: time.Unix(s.Exp, 0),
			HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
		fmt.Printf("🔐 [Auth] %s logged in from %s\n", req.User, addr)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// authLogoutHandler (POST) logs the session out and clears its cookie.
func authLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s, ok := authSessionOf(r); ok {
		authRevoke(s, time.Now())
		credentialsLock(s)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// authMeHandler tells the page who is logged in and the state of the
// Credentials section.
func authMeHandler(w http.ResponseWriter, r *http.Request) {
	s, _ := authSessionOf(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user":            s.User,
		"vaultConfigured": credentialsVaultHash() != "",
		"vaultUnlocked":   credentialsUnlocked(s, time.Now()),
	})
}

// registerAuthRoutes adds the login calls, and warns when no user exists.
func registerAuthRoutes() {
	http.HandleFunc("/api/login", authLoginHandler)
	http.HandleFunc("/api/logout", authLogoutHandler)
	http.HandleFunc("/api/me", authMeHandler)
	if users, err := authLoadUsers(); err != nil {
		fmt.Printf("⚠️  [Auth] %v\n", err)
	} else if len(users) == 0 {
		fmt.Println("⚠️  [Auth] No web user: the UI answers 503 until one is added (sudo ./lldp_scanner --user-add NAME)")
	}
	authEnsureBotToken()
}

// ─── Commands ─────────────────────────────────────────────────────────────────

var (
	userAddFlag   = flag.String("user-add", "", "Web login: add a user, or set a new password for one (asks for it)")
	userDelFlag   = flag.String("user-del", "", "Web login: remove a user")
	vaultPassFlag = flag.Bool("vault-password", false, "Set the password of the Credentials section (asks for it)")
)

// runAuthCommand runs the login command of the command line, if one was
// given, and reports whether it did (the scanner does not start then).
func runAuthCommand() bool {
	var err error
	switch {
	case *userAddFlag != "":
		err = authCommandUserAdd(*userAddFlag, os.Stdin)
	case *userDelFlag != "":
		err = authCommandUserDel(*userDelFlag)
	case *vaultPassFlag:
		err = credentialsCommandVaultPassword(os.Stdin)
	default:
		return false
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "❌", err)
		os.Exit(1)
	}
	return true
}

// authCommandUserAdd adds a user, or sets a user's new password.
func authCommandUserAdd(name string, in *os.File) error {
	if !authUserName.MatchString(name) {
		return fmt.Errorf("user name %q: use 1-32 letters, digits, '.', '_' or '-'", name)
	}
	password, err := authAskPassword(in, "Password for "+name)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	users, err := authLoadUsers()
	if err != nil {
		return err
	}
	verb := "added"
	found := false
	for i := range users {
		if users[i].Name == name {
			users[i].Hash, found, verb = string(hash), true, "has a new password"
		}
	}
	if !found {
		users = append(users, authUser{Name: name, Hash: string(hash), Created: time.Now()})
	}
	if err := authSaveUsers(users); err != nil {
		return err
	}
	fmt.Printf("✅ Web user %s %s\n", name, verb)
	return nil
}

// authCommandUserDel removes a user; its sessions end at its next request.
func authCommandUserDel(name string) error {
	users, err := authLoadUsers()
	if err != nil {
		return err
	}
	kept := users[:0]
	for _, u := range users {
		if u.Name != name {
			kept = append(kept, u)
		}
	}
	if len(kept) == len(users) {
		return fmt.Errorf("no web user %q", name)
	}
	if err := authSaveUsers(kept); err != nil {
		return err
	}
	fmt.Printf("✅ Web user %s removed\n", name)
	return nil
}

// authAskPassword reads a new password: on a terminal twice and without
// echo, else one line (a script's input). It must have authMinPassword
// characters.
func authAskPassword(in *os.File, prompt string) (string, error) {
	reader := bufio.NewReader(in)
	info, _ := in.Stat()
	terminal := info != nil && info.Mode()&os.ModeCharDevice != 0
	read := func(p string) (string, error) {
		if terminal {
			fmt.Fprint(os.Stderr, p+": ")
			if err := authEcho(in, false); err == nil {
				defer func() {
					authEcho(in, true)
					fmt.Fprintln(os.Stderr)
				}()
			}
		}
		line, err := reader.ReadString('\n')
		if err != nil && !(errors.Is(err, io.EOF) && line != "") {
			return "", fmt.Errorf("no password read: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	password, err := read(prompt)
	if err != nil {
		return "", err
	}
	if len(password) < authMinPassword {
		return "", fmt.Errorf("the password needs at least %d characters", authMinPassword)
	}
	if terminal {
		again, err := read("Repeat it")
		if err != nil {
			return "", err
		}
		if again != password {
			return "", errors.New("the passwords differ")
		}
	}
	return password, nil
}

// authEcho turns the terminal's echo on or off (stty).
func authEcho(in *os.File, on bool) error {
	arg := "-echo"
	if on {
		arg = "echo"
	}
	cmd := exec.Command("stty", arg)
	cmd.Stdin = in
	return cmd.Run()
}
