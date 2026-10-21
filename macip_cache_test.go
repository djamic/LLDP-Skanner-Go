package main

import (
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// captureStdout runs fn and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		out, _ := io.ReadAll(r)
		done <- string(out)
	}()
	defer func() { os.Stdout = saved }()
	fn()
	w.Close()
	os.Stdout = saved
	return <-done
}

// TestMACIPCacheGatewayExpiry (H8, Q18): with the gateway's SNMP ARP walk
// failing, as on every production start, no cache entry expires however old
// it is, and the run prints one warning naming the gateway. Once the gateway
// answers, entries it has not shown for more than the TTL expire, newer ones
// stay. mac_ip_cache.json keeps the old "mac": "ip" form and the times go to
// the sidecar.
func TestMACIPCacheGatewayExpiry(t *testing.T) {
	resetState(t)
	dir := t.TempDir()
	macIPCacheFile = filepath.Join(dir, "mac_ip_cache.json")
	now := testClock.Now()
	writeFile := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(macIPCacheFile, `{"00:1b:21:0b:00:01": "10.0.2.1", "00:1b:21:0b:00:02": "10.0.2.2", "00:1b:21:0b:00:03": "10.0.2.3"}`)
	writeFile(filepath.Join(dir, "mac_ip_cache_seen.json"), strings.NewReplacer(
		"OLD", strconv.FormatInt(now.Add(-10*24*time.Hour).Unix(), 10),
		"RECENT", strconv.FormatInt(now.Add(-3*24*time.Hour).Unix(), 10),
	).Replace(`{"00:1b:21:0b:00:01": OLD, "00:1b:21:0b:00:02": RECENT}`))
	loadMacIPCache()

	// Two sweeps with the gateway silent: nothing expires, one warning
	out := captureStdout(t, func() {
		collectARPFromAllSwitches()
		testClock.advance(5 * time.Minute)
		collectARPFromAllSwitches()
	})
	if n := strings.Count(out, "did not answer the SNMP ARP walk"); n != 1 || !strings.Contains(out, "Gateway "+fixedGatewayIP+" ") {
		t.Errorf("want one gateway warning naming %s, got %d in:\n%s", fixedGatewayIP, n, out)
	}
	if got := len(collectCacheMap()); got != 3 {
		t.Errorf("entries after sweeps without the gateway = %d, want 3", got)
	}

	// The gateway answers: the entry it has not shown for 10 days expires;
	// the one seen 3 days ago and the one without a time stay
	fakeSNMP.set(fixedGatewayIP, map[string][]string{oidARP: {
		oidARP + ".5.10.0.2.4 = Hex-STRING: 00 1B 21 0B 00 04 ",
	}})
	collectARPFromAllSwitches()
	want := map[string]string{"00:1b:21:0b:00:02": "10.0.2.2", "00:1b:21:0b:00:03": "10.0.2.3", "00:1b:21:0b:00:04": "10.0.2.4"}
	if got := collectCacheMap(); !maps.Equal(got, want) {
		t.Errorf("cache after the gateway answered = %v, want %v", got, want)
	}
	var saved map[string]string
	decodeJSONFile(t, macIPCacheFile, &saved)
	if !maps.Equal(saved, want) {
		t.Errorf("saved cache = %v, want the old form %v", saved, want)
	}
	var seen map[string]int64
	decodeJSONFile(t, filepath.Join(dir, "mac_ip_cache_seen.json"), &seen)
	if len(seen) != 3 || seen["00:1b:21:0b:00:04"] != testClock.Now().Unix() {
		t.Errorf("saved sidecar = %v", seen)
	}
}

// TestWriteFileReplacingMountPoint (RC-5): when the rename onto the target
// fails with EBUSY (the target is a mount point: docker-compose.yml
// bind-mounts mac_ip_cache.json as a single file) or EXDEV, the file is
// rewritten in place instead of never being updated; another rename error
// leaves the old file. The temporary file never stays behind, and the
// plain case still replaces the file through the rename.
func TestWriteFileReplacingMountPoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mac_ip_cache.json")
	failing := func(errno syscall.Errno) func(string, string) error {
		return func(oldpath, newpath string) error {
			return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: errno}
		}
	}
	check := func(name, want string) {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Errorf("%s: file holds %q (%v), want %q", name, got, err, want)
		}
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Errorf("%s: %s.tmp was left behind", name, path)
		}
	}

	if err := writeFileReplacing(path, []byte("v1"), os.Rename); err != nil {
		t.Fatal(err)
	}
	check("rename", "v1")
	if err := writeFileReplacing(path, []byte("v2"), failing(syscall.EBUSY)); err != nil {
		t.Errorf("EBUSY: %v, want the file rewritten in place", err)
	}
	check("EBUSY", "v2")
	if err := writeFileReplacing(path, []byte("v3"), failing(syscall.EXDEV)); err != nil {
		t.Errorf("EXDEV: %v, want the file rewritten in place", err)
	}
	check("EXDEV", "v3")
	if err := writeFileReplacing(path, []byte("v4"), failing(syscall.EACCES)); err == nil {
		t.Error("EACCES: no error, want the rename error")
	}
	check("EACCES", "v3")

	// The cache itself goes through it (writeJSONAtomic).
	if !writeJSONAtomic(path, map[string]string{"00:1b:21:0a:00:01": "10.0.9.1"}) {
		t.Fatal("writeJSONAtomic failed")
	}
	check("writeJSONAtomic", "{\n  \"00:1b:21:0a:00:01\": \"10.0.9.1\"\n}")
}

// gitignored reports whether .gitignore ignores a file of this name in the
// repository root: the last matching pattern without a slash decides ("!"
// undoes), as git reads them for root files.
func gitignored(t *testing.T, name string) bool {
	t.Helper()
	data, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatal(err)
	}
	ignored := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pattern, negated := strings.CutPrefix(line, "!")
		if strings.Contains(strings.TrimSuffix(pattern, "/"), "/") {
			continue // anchored or nested: not about root files
		}
		if ok, _ := path.Match(pattern, name); ok {
			ignored = !negated
		}
	}
	return ignored
}

// TestGitignoreCoversRuntimeFiles (R7): the files the scanner writes into
// its working directory, the repository checkout, are ignored, and so are
// the temporary files of its atomic writes: mac_ip_cache.json.tmp holds
// the network's MAC->IP inventory when the process dies between the write
// and the rename, and `git add -A` would have committed it.
func TestGitignoreCoversRuntimeFiles(t *testing.T) {
	for _, name := range []string{filepath.Base(macIPCacheFile), filepath.Base(macIPSeenFile()), savedDataFile, filepath.Base(graphDebugFile)} {
		for _, file := range []string{name, name + ".tmp"} {
			if !gitignored(t, file) {
				t.Errorf(".gitignore does not ignore %s", file)
			}
		}
	}
	if gitignored(t, "analyzer.go") || gitignored(t, "go.mod") {
		t.Error("gitignored matches source files")
	}
}
