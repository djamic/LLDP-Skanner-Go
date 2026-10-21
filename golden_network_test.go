package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/oui"
)

// TestGoldenScenarioNetwork pins the code behind the network seams that the
// other tests stub out, run against fakes: the IEEE OUI download fallback,
// the ESXi /ui/ check and its worker with a fake HTTP transport, and the
// capture report handlers reading a saved session.
func TestGoldenScenarioNetwork(t *testing.T) {
	resetState(t)
	rec := map[string]any{
		"oui_fallback":    ouiFallback(t),
		"esxi_ui_check":   esxiUICheck(),
		"esxi_worker":     esxiWorker(),
		"capture_reports": captureReports(t),
	}
	checkGolden(t, "scenario_network.json", goldenJSON(t, rec, 3))
}

// ouiFallback runs initOUIDatabase with oui.txt missing, once with an IEEE
// download that returns a page without OUI records (an error page) and once
// with a download that fails, and records what lookupVendor answers. The
// database loaded by TestMain is put back afterwards. This is the one place
// that swaps a seam after installSeams (ouiOpenHTTP): only TestMain and this
// test call initOUIDatabase, so no goroutine reads it meanwhile.
func ouiFallback(t *testing.T) map[string]any {
	prevDB, prevOK, prevOpen := ouiDB, ouiDBOk, ouiOpenHTTP
	defer func() {
		ouiDB, ouiDBOk, ouiOpenHTTP, ouiFile = prevDB, prevOK, prevOpen, "oui.txt"
		ouiDBOnce = sync.Once{}
		ouiDBOnce.Do(func() {})
	}()
	ouiFile = filepath.Join(t.TempDir(), "oui.txt")
	downloads := map[string]func(string) (oui.StaticDB, error){
		"download_returns_error_page": func(string) (oui.StaticDB, error) {
			return oui.OpenStatic(strings.NewReader("<html><body><h1>404 Not Found</h1></body></html>\n"))
		},
		"download_fails": func(string) (oui.StaticDB, error) {
			return nil, errors.New("dial tcp: lookup standards-oui.ieee.org: no such host")
		},
	}
	out := map[string]any{}
	for name, download := range downloads {
		var urls []string
		ouiOpenHTTP = func(url string) (oui.StaticDB, error) {
			urls = append(urls, url)
			return download(url)
		}
		ouiDB, ouiDBOk = nil, false
		ouiDBOnce = sync.Once{}
		initOUIDatabase()
		r := map[string]any{"downloaded_urls": urls, "loaded": ouiDBOk}
		if raw, ok := ouiDB.(oui.RawGetter); ok {
			r["entries"] = len(raw.RawDB())
		}
		vendors := map[string]string{}
		for _, mac := range []string{"00:00:0c:07:ac:01", "4c:ae:a3:8e:42:11", "52:54:00:12:34:56", "aa:bb:cc:dd:ee:ff"} {
			vendors[mac] = lookupVendor(mac)
		}
		r["lookupVendor"] = vendors
		out[name] = r
	}
	return out
}

// fakeTransport answers HTTP requests in place of the network and records
// them.
type fakeTransport struct {
	mu       sync.Mutex
	requests []string
	answer   func(*http.Request) (*http.Response, error)
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req.Method+" "+req.URL.String())
	f.mu.Unlock()
	return f.answer(req)
}

func (f *fakeTransport) taken() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.requests
	f.requests = nil
	return out
}

func httpAnswer(req *http.Request, status int, body string, header map[string]string) *http.Response {
	resp := &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
	for k, v := range header {
		resp.Header.Set(k, v)
	}
	return resp
}

// fakeESXiNetwork answers the ESXi /ui/ check per host: an ESXi host, a 404
// page that mentions ESXi, a redirect within the host, a redirect to another
// site, a host that is down, and a vCenter page.
func fakeESXiNetwork() *fakeTransport {
	return &fakeTransport{answer: func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host + req.URL.Path {
		case "10.9.9.1/ui/":
			return httpAnswer(req, 200, `<html><body ng-app="esxUiApp"></body></html>`, nil), nil
		case "10.9.9.2/ui/":
			return httpAnswer(req, 404, "<h1>Not Found</h1><p>VMware ESXi Host Client is not installed</p>", nil), nil
		case "10.9.9.3/ui/":
			return httpAnswer(req, 302, "", map[string]string{"Location": "https://10.9.9.3/ui/login"}), nil
		case "10.9.9.3/ui/login":
			return httpAnswer(req, 200, "<title>VMware ESXi</title>", nil), nil
		case "10.9.9.4/ui/":
			return httpAnswer(req, 302, "", map[string]string{"Location": "https://sso.example.test/login"}), nil
		case "sso.example.test/login":
			return httpAnswer(req, 200, "Sign in to manage your VMware ESXi and vSphere hosts", nil), nil
		case "10.9.9.6/ui/":
			return httpAnswer(req, 200, "<title>VMware vCenter Server</title>", nil), nil
		}
		return nil, errors.New("connect: connection refused")
	}}
}

// esxiUICheck runs esxiUIAnswers (the HTTP part of probeESXiHost) with the
// worker's client settings and a fake transport.
func esxiUICheck() map[string]any {
	transport := fakeESXiNetwork()
	client := newESXiClient(transport)
	out := map[string]any{}
	for _, ip := range []string{"10.9.9.1", "10.9.9.2", "10.9.9.3", "10.9.9.4", "10.9.9.5", "10.9.9.6"} {
		ok := esxiUIAnswers(client, ip)
		out[ip] = map[string]any{"confirmed": ok, "requests": transport.taken()}
	}
	return out
}

// esxiWorker feeds four jobs to runESXiWorker, one of them for a host that is
// down, and records how often each IP was probed and which MACs ended up
// confirmed.
func esxiWorker() map[string]any {
	clearConfirmedESXi()
	defer clearConfirmedESXi()
	client := newESXiClient(fakeESXiNetwork())
	jobs := make(chan esxiJob, 4)
	for _, j := range []esxiJob{
		{mac: "00:0c:29:99:00:01", ip: "10.9.9.1"},
		{mac: "00:0c:29:99:00:05", ip: "10.9.9.5"},
		{mac: "00:0c:29:99:00:02", ip: "10.9.9.2"},
		{mac: "00:0c:29:99:00:06", ip: "10.9.9.6"},
	} {
		jobs <- j
	}
	close(jobs)
	probes := map[string]int{}
	runESXiWorker(jobs, func(ip string) bool {
		probes[ip]++
		return esxiUIAnswers(client, ip)
	})
	var confirmed []string
	ConfirmedESXiMACs.Range(func(k, _ any) bool {
		confirmed = append(confirmed, k.(string))
		return true
	})
	slices.Sort(confirmed)
	return map[string]any{"probes": probes, "confirmed": confirmed}
}

// captureReports saves a capture session (topology only, as StopCapture
// writes it), sets the live report values, and calls the capture report
// handlers; it records the responses and the live values /api/graph serves
// after each call.
func captureReports(t *testing.T) map[string]any {
	resetBot()
	capturesDir = t.TempDir()
	session := FullCaptureData{
		Session: CaptureSession{ID: "cap1", Name: "lunch", StartTime: fixedTime, EndTime: fixedTime.Add(time.Hour), Status: "completed"},
		Topology: GraphData{Nodes: []GraphNode{
			{ID: "4c:ae:a3:09:00:41", Group: "switch", NodeType: "switch", SysName: "sw-41\n172.20.230.41"},
			{ID: "00:1b:21:09:41:01", Group: "endpoint", NodeType: "endpoint", SysName: "[ENDPOINT] Intel"},
		}, Links: []GraphLink{{Source: "4c:ae:a3:09:00:41", Target: "00:1b:21:09:41:01", Label: "GE1/0/1|"}}},
	}
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(capturesDir, "cap1_full_data.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	live := func() { SetLastReport(70, map[string][]string{"172.20.230.4": {"shadow_it"}}, 107756) }

	call := func(handler http.HandlerFunc, method, target string) map[string]any {
		live()
		rr := httptest.NewRecorder()
		handler(rr, httptest.NewRequest(method, target, nil))
		r := map[string]any{"status": rr.Code, "content_type": rr.Header().Get("Content-Type"), "live_after": lastReportRecord("")}
		var body struct {
			Report *Report `json:"report"`
		}
		if json.Unmarshal(rr.Body.Bytes(), &body) == nil && body.Report != nil {
			r["report_health"] = body.Report.HealthScore
			r["report_summary"] = body.Report.Summary
		}
		return r
	}
	live()
	return map[string]any{
		"live_before":     lastReportRecord(""),
		"generate":        call(reportGenerateHandler, http.MethodPost, "/api/report/generate?id=cap1"),
		"download":        call(reportDownloadHandler, http.MethodGet, "/api/report/download?id=cap1"),
		"missing_session": call(reportGenerateHandler, http.MethodPost, "/api/report/generate?id=nope"),
		"bot_messages":    bot.taken(),
	}
}
