package main

import (
	"cmp"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ─── Credentials ──────────────────────────────────────────────────────────────
//
// The logins the scanner uses on the devices (the ESXi vSphere API, switch
// SSH, iLO/iDRAC Redfish, ...) are kept in secrets/credentials.json, each
// password encrypted with AES-256-GCM under secrets/vault.key, which is
// made at first use so the scanner reads them unattended. A login is given
// for one IP, an IP range or a device type, with several per target tried
// in their order (credentialsFor). The UI's Credentials window opens with
// its own password (secrets/vault.json, bcrypt, set by --vault-password)
// for credentialsUnlockTime; no API ever returns a password.

const credentialsUnlockTime = 15 * time.Minute

// credentialTarget is what a login is for: one IP ("ip"), an IP range
// ("cidr") or a device type ("type", credentialTypes).
type credentialTarget struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// credentialEntry is one login of secrets/credentials.json.
type credentialEntry struct {
	ID       string           `json:"id"`
	Target   credentialTarget `json:"target"`
	Protocol string           `json:"protocol"`
	Username string           `json:"username"`
	// Secret is base64(nonce | AES-GCM ciphertext) of the password, the
	// entry id as additional data (credentialsSeal)
	Secret string `json:"secret"`
	Note   string `json:"note,omitempty"`
	// DeviceType, on a login for an IP or a range, says what the device
	// is (a credentialTypes id): the scanner then knows it with no probe
	// (deviceTypesOf), as the owner knows the UniFi controller's address
	DeviceType string    `json:"deviceType,omitempty"`
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`
}

type credentialsFile struct {
	Entries []credentialEntry `json:"entries"`
}

// credentialOption is a protocol or device type the UI offers.
type credentialOption struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// credentialProtocols are the ways a login is used. "https" is a device's
// web API, whose token may stand in the password with no user name.
var credentialProtocols = []credentialOption{
	{"vsphere", "ESXi / vCenter (vSphere API)"},
	{"ssh", "SSH"},
	{"telnet", "Telnet"},
	{"redfish", "iLO / iDRAC (Redfish)"},
	{"https", "Web API (HTTPS)"},
}

// credentialTypes are the device types a login can be given for.
var credentialTypes = []credentialOption{
	{"esxi", "ESXi hosts"},
	{"vcenter", "vCenter Servers"},
	{"switch", "All switches"},
	{"switch-hpe", "HPE / H3C switches"},
	{"switch-aruba", "Aruba switches"},
	{"switch-eltex", "Eltex switches"},
	{"switch-snr", "SNR switches"},
	{"switch-huawei", "Huawei switches"},
	{"switch-pixietech", "PiXiETECH switches"},
	{"bmc", "All BMCs (iLO, iDRAC, iRMC)"},
	{"ilo", "HPE iLO"},
	{"idrac", "Dell iDRAC"},
	{"router", "Gateways and routers"},
	{"fortigate", "FortiGate"},
	{"unifi-controller", "UniFi Network controllers"},
	{"linux", "Linux servers"},
	{"any", "Any device"},
}

func credentialOptionKnown(options []credentialOption, id string) bool {
	return slices.ContainsFunc(options, func(o credentialOption) bool { return o.ID == id })
}

// ─── File and encryption ──────────────────────────────────────────────────────

// credentialsMu guards secrets/credentials.json (a change is read, changed
// and written under it) and credentialsWorkedID.
var credentialsMu sync.Mutex

func credentialsLoad() ([]credentialEntry, error) {
	path := filepath.Join(secretsDir, "credentials.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f credentialsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f.Entries, nil
}

func credentialsSave(entries []credentialEntry) error {
	data, err := json.MarshalIndent(credentialsFile{Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	return secretsWrite("credentials.json", data)
}

func credentialsGCM() (cipher.AEAD, error) {
	key, err := secretsKey("vault.key")
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// credentialsSeal encrypts the password of entry id.
func credentialsSeal(id, password string) (string, error) {
	gcm, err := credentialsGCM()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(password), []byte(id))), nil
}

// credentialsOpen decrypts the password of entry id.
func credentialsOpen(id, secret string) (string, error) {
	gcm, err := credentialsGCM()
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(secret)
	if err != nil || len(data) < gcm.NonceSize() {
		return "", errors.New("damaged secret")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], []byte(id))
	if err != nil {
		return "", errors.New("secret does not open: another vault.key, or a damaged file")
	}
	return string(plain), nil
}

// ─── Choosing the logins of a device ──────────────────────────────────────────

// credentialLogin is a decrypted login to try.
type credentialLogin struct {
	ID       string
	Username string
	Password string
}

// credentialsWorkedID holds the entry that last logged in, by IP and
// protocol ("172.20.0.3|vsphere"; guarded by credentialsMu).
var credentialsWorkedID = make(map[string]string)

// credentialsWorked notes that entry id logged in to ip by protocol: it is
// tried first there next time.
func credentialsWorked(ip, protocol, id string) {
	credentialsMu.Lock()
	defer credentialsMu.Unlock()
	credentialsWorkedID[ip+"|"+protocol] = id
}

// credentialsFor returns the logins to try on the device at ip by protocol,
// in order: the one that last worked there, those of its IP, those of the
// IP ranges that hold it (the narrowest first), and those of its device
// types in the order given ("any" always last), each group in the order of
// the entries.
func credentialsFor(ip, protocol string, types []string) ([]credentialLogin, error) {
	addr := net.ParseIP(ip)
	credentialsMu.Lock()
	entries, err := credentialsLoad()
	worked := credentialsWorkedID[ip+"|"+protocol]
	credentialsMu.Unlock()
	if err != nil || addr == nil {
		return nil, err
	}
	rank := func(e credentialEntry) (int, int, bool) { // group, then a rank within it
		switch e.Target.Kind {
		case "ip":
			return 1, 0, e.Target.Value == addr.String()
		case "cidr":
			_, n, err := net.ParseCIDR(e.Target.Value)
			if err != nil || !n.Contains(addr) {
				return 0, 0, false
			}
			ones, _ := n.Mask.Size()
			return 2, -ones, true
		case "type":
			if e.Target.Value == "any" {
				return 4, 0, true
			}
			i := slices.Index(types, e.Target.Value)
			return 3, i, i >= 0
		}
		return 0, 0, false
	}
	type match struct {
		e           credentialEntry
		group, rank int
		order       int
	}
	var matches []match
	for i, e := range entries {
		if e.Protocol != protocol {
			continue
		}
		if g, r, ok := rank(e); ok {
			if e.ID == worked {
				g = 0
			}
			matches = append(matches, match{e, g, r, i})
		}
	}
	slices.SortFunc(matches, func(a, b match) int {
		return cmp.Or(cmp.Compare(a.group, b.group), cmp.Compare(a.rank, b.rank), cmp.Compare(a.order, b.order))
	})
	var out []credentialLogin
	for _, m := range matches {
		password, err := credentialsOpen(m.e.ID, m.e.Secret)
		if err != nil {
			fmt.Printf("⚠️  [Credentials] %s: %v\n", m.e.ID, err)
			continue
		}
		out = append(out, credentialLogin{ID: m.e.ID, Username: m.e.Username, Password: password})
	}
	return out, nil
}

// credentialsDeclaredTypes returns the device types the Credentials window
// declares for the device at ip (credentialEntry.DeviceType): those of the
// logins for its IP, then of the IP ranges that hold it (the narrowest
// first), each once.
func credentialsDeclaredTypes(ip string) []string {
	addr := net.ParseIP(ip)
	credentialsMu.Lock()
	entries, err := credentialsLoad()
	credentialsMu.Unlock()
	if err != nil || addr == nil {
		return nil
	}
	type declared struct {
		typ  string
		rank int // 0 for the IP itself, else the range's host bits + 1
	}
	var found []declared
	for _, e := range entries {
		if e.DeviceType == "" {
			continue
		}
		switch e.Target.Kind {
		case "ip":
			if e.Target.Value == addr.String() {
				found = append(found, declared{e.DeviceType, 0})
			}
		case "cidr":
			if _, n, err := net.ParseCIDR(e.Target.Value); err == nil && n.Contains(addr) {
				ones, bits := n.Mask.Size()
				found = append(found, declared{e.DeviceType, bits - ones + 1})
			}
		}
	}
	slices.SortStableFunc(found, func(a, b declared) int { return cmp.Compare(a.rank, b.rank) })
	var types []string
	for _, d := range found {
		if !slices.Contains(types, d.typ) {
			types = append(types, d.typ)
		}
	}
	return types
}

// ─── The vault password ───────────────────────────────────────────────────────

// credentialsVaultHash is the bcrypt hash of the Credentials password, ""
// when none was set.
func credentialsVaultHash() string {
	data, err := os.ReadFile(filepath.Join(secretsDir, "vault.json"))
	if err != nil {
		return ""
	}
	var v struct {
		Hash string `json:"hash"`
	}
	if json.Unmarshal(data, &v) != nil {
		return ""
	}
	return v.Hash
}

// credentialsCommandVaultPassword sets the Credentials password.
func credentialsCommandVaultPassword(in *os.File) error {
	password, err := authAskPassword(in, "Credentials password")
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(map[string]string{"hash": string(hash)})
	if err := secretsWrite("vault.json", data); err != nil {
		return err
	}
	if _, err := secretsKey("vault.key"); err != nil {
		return err
	}
	fmt.Println("✅ Credentials password set")
	return nil
}

// credentialsUnlockedUntil holds, by session id, until when the
// Credentials window is open (guarded by credentialsUnlockMu).
var (
	credentialsUnlockMu      sync.Mutex
	credentialsUnlockedUntil = make(map[string]time.Time)
	credentialsUnlocks       = newAuthLimiter()
)

// credentialsUnlocked reports whether the session opened the Credentials
// window less than credentialsUnlockTime ago (counted from its last call).
func credentialsUnlocked(s authSession, now time.Time) bool {
	credentialsUnlockMu.Lock()
	defer credentialsUnlockMu.Unlock()
	return s.ID != "" && now.Before(credentialsUnlockedUntil[s.ID])
}

func credentialsUnlock(s authSession, now time.Time) {
	credentialsUnlockMu.Lock()
	defer credentialsUnlockMu.Unlock()
	for id, until := range credentialsUnlockedUntil {
		if !now.Before(until) {
			delete(credentialsUnlockedUntil, id)
		}
	}
	credentialsUnlockedUntil[s.ID] = now.Add(credentialsUnlockTime)
}

func credentialsLock(s authSession) {
	credentialsUnlockMu.Lock()
	defer credentialsUnlockMu.Unlock()
	delete(credentialsUnlockedUntil, s.ID)
}

// ─── API ──────────────────────────────────────────────────────────────────────

// credentialView is an entry as the API shows it: never its password.
type credentialView struct {
	ID          string           `json:"id"`
	Target      credentialTarget `json:"target"`
	Protocol    string           `json:"protocol"`
	Username    string           `json:"username"`
	HasPassword bool             `json:"hasPassword"`
	Note        string           `json:"note"`
	DeviceType  string           `json:"deviceType,omitempty"`
	Updated     time.Time        `json:"updated"`
}

// credentialRequest is the body of a create or an update: the password is
// kept on an update that leaves it empty.
type credentialRequest struct {
	ID         string           `json:"id"`
	Target     credentialTarget `json:"target"`
	Protocol   string           `json:"protocol"`
	Username   string           `json:"username"`
	Password   string           `json:"password"`
	Note       string           `json:"note"`
	DeviceType string           `json:"deviceType"`
}

// credentialsValidate checks a request and puts its target in canonical
// form (an IP as Go prints it, a range as its network).
func credentialsValidate(req *credentialRequest, create bool) error {
	req.Target.Value = strings.TrimSpace(req.Target.Value)
	req.Username = strings.TrimSpace(req.Username)
	req.Note = strings.TrimSpace(req.Note)
	switch req.Target.Kind {
	case "ip":
		ip := net.ParseIP(req.Target.Value)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("%q is no IPv4 address", req.Target.Value)
		}
		req.Target.Value = ip.String()
	case "cidr":
		_, n, err := net.ParseCIDR(req.Target.Value)
		if err != nil || n.IP.To4() == nil {
			return fmt.Errorf("%q is no IPv4 range (172.20.0.0/24)", req.Target.Value)
		}
		req.Target.Value = n.String()
	case "type":
		if !credentialOptionKnown(credentialTypes, req.Target.Value) {
			return fmt.Errorf("unknown device type %q", req.Target.Value)
		}
	default:
		return fmt.Errorf("unknown target kind %q", req.Target.Kind)
	}
	switch {
	case req.Target.Kind == "type":
		req.DeviceType = "" // the target already is the type
	case req.DeviceType != "" && (req.DeviceType == "any" || !credentialOptionKnown(credentialTypes, req.DeviceType)):
		return fmt.Errorf("unknown device type %q", req.DeviceType)
	}
	if !credentialOptionKnown(credentialProtocols, req.Protocol) {
		return fmt.Errorf("unknown protocol %q", req.Protocol)
	}
	if req.Username == "" && req.Protocol != "https" {
		return errors.New("the user name is missing")
	}
	if len(req.Username) > 128 || len(req.Password) > 256 || len(req.Note) > 200 {
		return errors.New("user name, password or note too long")
	}
	if create && req.Password == "" {
		return errors.New("the password is missing")
	}
	return nil
}

// credentialsReply writes a JSON answer.
func credentialsReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func credentialsError(w http.ResponseWriter, status int, msg string) {
	credentialsReply(w, status, map[string]string{"error": msg})
}

// credentialsUnlockHandler (POST {"password"}) opens the Credentials window
// for the session.
func credentialsUnlockHandler(w http.ResponseWriter, r *http.Request) {
	s, ok := authSessionOf(r)
	if r.Method != http.MethodPost || !ok {
		credentialsError(w, http.StatusMethodNotAllowed, "POST with a login")
		return
	}
	hash := credentialsVaultHash()
	if hash == "" {
		credentialsError(w, http.StatusServiceUnavailable, "no Credentials password yet: run sudo ./lldp_scanner --vault-password on the server")
		return
	}
	addr, now := authClientAddr(r), time.Now()
	if credentialsUnlocks.blocked(addr, now) {
		credentialsError(w, http.StatusTooManyRequests, "too many wrong passwords: wait a few minutes")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) != nil || !authCheckPassword(hash, req.Password) {
		credentialsUnlocks.fail(addr, now)
		fmt.Printf("🔐 [Credentials] Wrong password from %s (%s)\n", s.User, addr)
		credentialsError(w, http.StatusUnauthorized, "wrong password")
		return
	}
	credentialsUnlocks.succeed(addr)
	credentialsUnlock(s, now)
	fmt.Printf("🔐 [Credentials] Opened by %s (%s)\n", s.User, addr)
	credentialsReply(w, http.StatusOK, map[string]bool{"ok": true})
}

// credentialsLockHandler (POST) closes the Credentials window.
func credentialsLockHandler(w http.ResponseWriter, r *http.Request) {
	if s, ok := authSessionOf(r); ok && r.Method == http.MethodPost {
		credentialsLock(s)
	}
	credentialsReply(w, http.StatusOK, map[string]bool{"ok": true})
}

// credentialsHandler lists (GET), adds (POST), changes (PUT) and removes
// (DELETE ?id=) logins, and moves one up or down (PATCH {"id", "move": -1
// or 1}), for a session that opened the Credentials window.
func credentialsHandler(w http.ResponseWriter, r *http.Request) {
	s, ok := authSessionOf(r)
	now := time.Now()
	if !ok || !credentialsUnlocked(s, now) {
		credentialsError(w, http.StatusForbidden, "locked")
		return
	}
	credentialsUnlock(s, now) // each call keeps the window open

	credentialsMu.Lock()
	defer credentialsMu.Unlock()
	entries, err := credentialsLoad()
	if err != nil {
		credentialsError(w, http.StatusInternalServerError, err.Error())
		return
	}
	find := func(id string) int {
		return slices.IndexFunc(entries, func(e credentialEntry) bool { return e.ID == id })
	}
	save := func(what string) bool {
		if err := credentialsSave(entries); err != nil {
			credentialsError(w, http.StatusInternalServerError, err.Error())
			return false
		}
		fmt.Printf("🔐 [Credentials] %s by %s\n", what, s.User)
		return true
	}

	switch r.Method {
	case http.MethodGet:
		views := make([]credentialView, 0, len(entries))
		for _, e := range entries {
			views = append(views, credentialView{ID: e.ID, Target: e.Target, Protocol: e.Protocol, Username: e.Username,
				HasPassword: e.Secret != "", Note: e.Note, DeviceType: e.DeviceType, Updated: e.Updated})
		}
		credentialsReply(w, http.StatusOK, map[string]any{"entries": views, "protocols": credentialProtocols, "types": credentialTypes})

	case http.MethodPost, http.MethodPut:
		var req credentialRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&req); err != nil {
			credentialsError(w, http.StatusBadRequest, "invalid request")
			return
		}
		create := r.Method == http.MethodPost
		if err := credentialsValidate(&req, create); err != nil {
			credentialsError(w, http.StatusBadRequest, err.Error())
			return
		}
		var e credentialEntry
		i := -1
		if create {
			e = credentialEntry{ID: randomHex(8), Created: now}
		} else if i = find(req.ID); i < 0 {
			credentialsError(w, http.StatusNotFound, "no such login")
			return
		} else {
			e = entries[i]
		}
		e.Target, e.Protocol, e.Username, e.Note, e.DeviceType, e.Updated = req.Target, req.Protocol, req.Username, req.Note, req.DeviceType, now
		if req.Password != "" {
			if e.Secret, err = credentialsSeal(e.ID, req.Password); err != nil {
				credentialsError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		verb := "changed"
		if create {
			entries, verb = append(entries, e), "added"
		} else {
			entries[i] = e
		}
		if save(fmt.Sprintf("%s login %s (%s for %s %s)", verb, e.ID, e.Protocol, e.Target.Kind, e.Target.Value)) {
			credentialsReply(w, http.StatusOK, map[string]string{"id": e.ID})
		}

	case http.MethodDelete:
		i := find(r.URL.Query().Get("id"))
		if i < 0 {
			credentialsError(w, http.StatusNotFound, "no such login")
			return
		}
		id := entries[i].ID
		entries = slices.Delete(entries, i, i+1)
		if save("removed login " + id) {
			credentialsReply(w, http.StatusOK, map[string]bool{"ok": true})
		}

	case http.MethodPatch:
		var req struct {
			ID   string `json:"id"`
			Move int    `json:"move"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) != nil || (req.Move != -1 && req.Move != 1) {
			credentialsError(w, http.StatusBadRequest, "invalid request")
			return
		}
		i := find(req.ID)
		j := i + req.Move
		if i < 0 || j < 0 || j >= len(entries) {
			credentialsError(w, http.StatusBadRequest, "cannot move it there")
			return
		}
		entries[i], entries[j] = entries[j], entries[i]
		if save("moved login " + req.ID) {
			credentialsReply(w, http.StatusOK, map[string]bool{"ok": true})
		}

	default:
		credentialsError(w, http.StatusMethodNotAllowed, "GET, POST, PUT, PATCH or DELETE")
	}
}

// registerCredentialRoutes adds the Credentials API, and warns when its
// password is not set.
func registerCredentialRoutes() {
	http.HandleFunc("/api/credentials", credentialsHandler)
	http.HandleFunc("/api/credentials/unlock", credentialsUnlockHandler)
	http.HandleFunc("/api/credentials/lock", credentialsLockHandler)
	if credentialsVaultHash() == "" {
		fmt.Println("⚠️  [Credentials] No Credentials password: the window stays closed until one is set (sudo ./lldp_scanner --vault-password)")
	}
}
