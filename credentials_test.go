package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Tests of the Credentials store (credentials.go): the encryption, the API
// behind the window's own password, and the order the logins of a device
// are tried in.

func TestCredentialsSeal(t *testing.T) {
	authTestSetup(t)
	secret, err := credentialsSeal("id1", "Esxi-Pass!")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := credentialsOpen("id1", secret); err != nil || got != "Esxi-Pass!" {
		t.Errorf("credentialsOpen = %q, %v", got, err)
	}
	if _, err := credentialsOpen("id2", secret); err == nil {
		t.Error("a secret opens under another entry's id")
	}
	if again, _ := credentialsSeal("id1", "Esxi-Pass!"); again == secret {
		t.Error("two seals of one password are equal (no fresh nonce)")
	}
	if info, err := os.Stat(filepath.Join(secretsDir, "vault.key")); err != nil || info.Mode().Perm() != 0o600 || info.Size() != 32 {
		t.Errorf("vault.key: %v", err)
	}
}

// credentialsTestCall calls the Credentials API as session s.
func credentialsTestCall(t *testing.T, s authSession, method, path string, body any) (int, map[string]any, string) {
	t.Helper()
	var payload string
	if body != nil {
		data, _ := json.Marshal(body)
		payload = string(data)
	}
	r := httptest.NewRequest(method, "http://scanner:8088"+path, strings.NewReader(payload))
	r.RemoteAddr = "10.9.0.8:52000"
	r = r.WithContext(context.WithValue(r.Context(), authCtxKey{}, s))
	w := httptest.NewRecorder()
	captureStdoutQuiet(func() {
		switch {
		case strings.HasPrefix(path, "/api/credentials/unlock"):
			credentialsUnlockHandler(w, r)
		case strings.HasPrefix(path, "/api/credentials/lock"):
			credentialsLockHandler(w, r)
		default:
			credentialsHandler(w, r)
		}
	})
	var v map[string]any
	json.Unmarshal(w.Body.Bytes(), &v)
	return w.Code, v, w.Body.String()
}

func TestCredentialsAPI(t *testing.T) {
	authTestSetup(t)
	s := authSession{User: "admin", ID: randomHex(16), Exp: time.Now().Add(time.Hour).Unix()}

	// Locked, and no window password yet
	if code, _, _ := credentialsTestCall(t, s, "GET", "/api/credentials", nil); code != 403 {
		t.Errorf("GET while locked: %d, want 403", code)
	}
	if code, _, _ := credentialsTestCall(t, s, "POST", "/api/credentials/unlock", map[string]string{"password": "x"}); code != 503 {
		t.Errorf("unlock without a window password: %d, want 503", code)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("vault-pass"), bcrypt.MinCost)
	data, _ := json.Marshal(map[string]string{"hash": string(hash)})
	secretsWrite("vault.json", data)
	if code, _, _ := credentialsTestCall(t, s, "POST", "/api/credentials/unlock", map[string]string{"password": "wrong"}); code != 401 {
		t.Errorf("unlock with a wrong password: %d, want 401", code)
	}
	if code, _, _ := credentialsTestCall(t, s, "POST", "/api/credentials/unlock", map[string]string{"password": "vault-pass"}); code != 200 {
		t.Fatalf("unlock: %d", code)
	}
	other := authSession{User: "admin", ID: randomHex(16)}
	if code, _, _ := credentialsTestCall(t, other, "GET", "/api/credentials", nil); code != 403 {
		t.Errorf("another session of the user is unlocked too: %d", code)
	}

	// Bad requests change nothing
	for name, req := range map[string]credentialRequest{
		"not an IP":        {Target: credentialTarget{"ip", "172.20.0.300"}, Protocol: "vsphere", Username: "root", Password: "p"},
		"IPv6":             {Target: credentialTarget{"ip", "fe80::1"}, Protocol: "vsphere", Username: "root", Password: "p"},
		"bad range":        {Target: credentialTarget{"cidr", "172.20.0.0/33"}, Protocol: "ssh", Username: "admin", Password: "p"},
		"unknown type":     {Target: credentialTarget{"type", "toaster"}, Protocol: "ssh", Username: "admin", Password: "p"},
		"unknown kind":     {Target: credentialTarget{"mac", "x"}, Protocol: "ssh", Username: "admin", Password: "p"},
		"unknown protocol": {Target: credentialTarget{"type", "esxi"}, Protocol: "ftp", Username: "root", Password: "p"},
		"no user":          {Target: credentialTarget{"type", "esxi"}, Protocol: "vsphere", Password: "p"},
		"no password":      {Target: credentialTarget{"type", "esxi"}, Protocol: "vsphere", Username: "root"},
	} {
		if code, _, body := credentialsTestCall(t, s, "POST", "/api/credentials", req); code != 400 {
			t.Errorf("%s: %d %s, want 400", name, code, body)
		}
	}

	add := func(req credentialRequest) string {
		t.Helper()
		code, v, body := credentialsTestCall(t, s, "POST", "/api/credentials", req)
		if code != 200 {
			t.Fatalf("add %+v: %d %s", req, code, body)
		}
		return v["id"].(string)
	}
	esxi := add(credentialRequest{Target: credentialTarget{"type", "esxi"}, Protocol: "vsphere", Username: "root", Password: "Default-1", Note: "default"})
	host := add(credentialRequest{Target: credentialTarget{"ip", " 172.20.0.3 "}, Protocol: "vsphere", Username: "root", Password: "Host-Pass"})
	rng := add(credentialRequest{Target: credentialTarget{"cidr", "172.20.0.77/24"}, Protocol: "ssh", Username: "admin", Password: "Ssh-Pass"})
	add(credentialRequest{Target: credentialTarget{"type", "fortigate"}, Protocol: "https", Password: "api-token"})

	// The list shows no password, in any form
	code, v, body := credentialsTestCall(t, s, "GET", "/api/credentials", nil)
	if code != 200 {
		t.Fatalf("GET: %d %s", code, body)
	}
	for _, secret := range []string{"Default-1", "Host-Pass", "Ssh-Pass", "api-token", "secret", "password\""} {
		if strings.Contains(body, secret) {
			t.Errorf("the list holds %q:\n%s", secret, body)
		}
	}
	entries := v["entries"].([]any)
	if len(entries) != 4 || len(v["protocols"].([]any)) == 0 || len(v["types"].([]any)) == 0 {
		t.Fatalf("list %s", body)
	}
	if e := entries[1].(map[string]any); e["target"].(map[string]any)["value"] != "172.20.0.3" || e["hasPassword"] != true {
		t.Errorf("the IP entry %v, want its IP trimmed and a password set", e)
	}
	if e := entries[2].(map[string]any); e["target"].(map[string]any)["value"] != "172.20.0.0/24" {
		t.Errorf("the range entry %v, want its network", e)
	}

	// The file holds no password either, and only its owner reads it
	file, _ := os.ReadFile(filepath.Join(secretsDir, "credentials.json"))
	for _, secret := range []string{"Default-1", "Host-Pass", "Ssh-Pass", "api-token"} {
		if strings.Contains(string(file), secret) {
			t.Errorf("credentials.json holds %q", secret)
		}
	}
	if info, _ := os.Stat(filepath.Join(secretsDir, "credentials.json")); info.Mode().Perm() != 0o600 {
		t.Errorf("credentials.json mode %v", info.Mode().Perm())
	}

	// A change without a password keeps it; with one it replaces it
	if code, _, body := credentialsTestCall(t, s, "PUT", "/api/credentials", credentialRequest{ID: host,
		Target: credentialTarget{"ip", "172.20.0.3"}, Protocol: "vsphere", Username: "admin"}); code != 200 {
		t.Fatalf("PUT: %d %s", code, body)
	}
	logins, _ := credentialsFor("172.20.0.3", "vsphere", []string{"esxi"})
	if len(logins) != 2 || logins[0].ID != host || logins[0].Username != "admin" || logins[0].Password != "Host-Pass" {
		t.Errorf("after a change without a password: %+v", logins)
	}
	credentialsTestCall(t, s, "PUT", "/api/credentials", credentialRequest{ID: host,
		Target: credentialTarget{"ip", "172.20.0.3"}, Protocol: "vsphere", Username: "admin", Password: "New-Pass"})
	if logins, _ := credentialsFor("172.20.0.3", "vsphere", nil); len(logins) != 1 || logins[0].Password != "New-Pass" {
		t.Errorf("after a new password: %+v", logins)
	}
	if code, _, _ := credentialsTestCall(t, s, "PUT", "/api/credentials", credentialRequest{ID: "nope",
		Target: credentialTarget{"ip", "172.20.0.3"}, Protocol: "vsphere", Username: "x"}); code != 404 {
		t.Errorf("PUT of an unknown id: %d, want 404", code)
	}

	// Move and remove
	if code, _, _ := credentialsTestCall(t, s, "PATCH", "/api/credentials", map[string]any{"id": esxi, "move": -1}); code != 400 {
		t.Errorf("moving the first entry up: %d, want 400", code)
	}
	credentialsTestCall(t, s, "PATCH", "/api/credentials", map[string]any{"id": esxi, "move": 1})
	if code, _, _ := credentialsTestCall(t, s, "DELETE", "/api/credentials?id="+rng, nil); code != 200 {
		t.Errorf("DELETE: %d", code)
	}
	stored, _ := credentialsLoad()
	ids := []string{}
	for _, e := range stored {
		ids = append(ids, e.ID)
	}
	if len(ids) != 3 || ids[0] != host || ids[1] != esxi {
		t.Errorf("entries after the move and removal %v, want %s, %s, then the FortiGate", ids, host, esxi)
	}

	// The window closes after its time, or when asked
	credentialsUnlockMu.Lock()
	credentialsUnlockedUntil[s.ID] = time.Now().Add(-time.Second)
	credentialsUnlockMu.Unlock()
	if code, _, _ := credentialsTestCall(t, s, "GET", "/api/credentials", nil); code != 403 {
		t.Errorf("GET after the window's time: %d, want 403", code)
	}
	credentialsTestCall(t, s, "POST", "/api/credentials/unlock", map[string]string{"password": "vault-pass"})
	credentialsTestCall(t, s, "POST", "/api/credentials/lock", nil)
	if code, _, _ := credentialsTestCall(t, s, "GET", "/api/credentials", nil); code != 403 {
		t.Errorf("GET after the lock: %d, want 403", code)
	}
}

func TestCredentialsFor(t *testing.T) {
	authTestSetup(t)
	var entries []credentialEntry
	add := func(id, kind, value, protocol string) {
		secret, _ := credentialsSeal(id, "pw-"+id)
		entries = append(entries, credentialEntry{ID: id, Target: credentialTarget{kind, value}, Protocol: protocol, Username: "u-" + id, Secret: secret})
	}
	add("any", "type", "any", "vsphere")
	add("esxi1", "type", "esxi", "vsphere")
	add("wide", "cidr", "172.20.0.0/16", "vsphere")
	add("narrow", "cidr", "172.20.0.0/24", "vsphere")
	add("host", "ip", "172.20.0.3", "vsphere")
	add("ssh", "ip", "172.20.0.3", "ssh")
	add("esxi2", "type", "esxi", "vsphere")
	add("bmc", "type", "bmc", "vsphere")
	add("other", "ip", "172.20.0.4", "vsphere")
	if err := credentialsSave(entries); err != nil {
		t.Fatal(err)
	}
	order := func(ip string, types ...string) []string {
		logins, err := credentialsFor(ip, "vsphere", types)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, l := range logins {
			if l.Password != "pw-"+l.ID || l.Username != "u-"+l.ID {
				t.Errorf("login %+v decrypted wrong", l)
			}
			ids = append(ids, l.ID)
		}
		return ids
	}
	for _, c := range []struct {
		ip    string
		types []string
		want  []string
	}{
		{"172.20.0.3", []string{"esxi"}, []string{"host", "narrow", "wide", "esxi1", "esxi2", "any"}},
		{"172.20.0.3", []string{"bmc", "esxi"}, []string{"host", "narrow", "wide", "bmc", "esxi1", "esxi2", "any"}},
		{"172.20.9.9", []string{"esxi"}, []string{"wide", "esxi1", "esxi2", "any"}},
		{"10.0.0.1", nil, []string{"any"}},
		{"not-an-ip", []string{"esxi"}, nil},
	} {
		if got := order(c.ip, c.types...); !slices.Equal(got, c.want) {
			t.Errorf("credentialsFor(%s, %v) = %v, want %v", c.ip, c.types, got, c.want)
		}
	}

	// The one that last worked there comes first, there only
	credentialsWorked("172.20.0.3", "vsphere", "esxi2")
	if got, want := order("172.20.0.3", "esxi"), []string{"esxi2", "host", "narrow", "wide", "esxi1", "any"}; !slices.Equal(got, want) {
		t.Errorf("after esxi2 worked: %v, want %v", got, want)
	}
	if got := order("172.20.9.9", "esxi"); got[0] != "wide" {
		t.Errorf("esxi2 comes first on another host too: %v", got)
	}
	// A login of another vault.key is skipped
	os.Remove(filepath.Join(secretsDir, "vault.key"))
	captureStdoutQuiet(func() {
		if got := order("172.20.0.3", "esxi"); len(got) != 0 {
			t.Errorf("logins that do not decrypt: %v", got)
		}
	})
}

func TestCredentialsVaultCommand(t *testing.T) {
	authTestSetup(t)
	var err error
	captureStdoutQuiet(func() { err = credentialsCommandVaultPassword(authTestInput(t, "vault-pass-1\n")) })
	if err != nil || !authCheckPassword(credentialsVaultHash(), "vault-pass-1") {
		t.Fatalf("vault password: %v, hash %q", err, credentialsVaultHash())
	}
	if _, err := os.Stat(filepath.Join(secretsDir, "vault.key")); err != nil {
		t.Errorf("the vault key was not made: %v", err)
	}
}
