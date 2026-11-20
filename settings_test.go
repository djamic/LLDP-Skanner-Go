package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestClassifySettings checks that a saved file without a classification
// choice gets its default, that a POST of the settings keeps the choices it
// leaves out and rebuilds the graph only when a choice changed, and that the
// settings modal has a checkbox for every choice.
func TestClassifySettings(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	currentSettingsMutex.RLock()
	saved := currentSettings
	currentSettingsMutex.RUnlock()
	t.Cleanup(func() {
		currentSettingsMutex.Lock()
		currentSettings = saved
		currentSettingsMutex.Unlock()
	})
	rebuilds := 0
	before := classifySettingsChanged
	classifySettingsChanged = func() { rebuilds++ }
	t.Cleanup(func() { classifySettingsChanged = before })
	t.Chdir(t.TempDir())

	lldpCapsOff := DefaultClassifySettings()
	lldpCapsOff.LLDPCaps = false
	for body, want := range map[string]ClassifySettings{
		`{"settings":{"community":"x"}}`:                               DefaultClassifySettings(),
		`{"settings":{"community":"x","classify":{}}}`:                 DefaultClassifySettings(),
		`{"settings":{"community":"x","classify":{"lldpCaps":false}}}`: lldpCapsOff,
		`{"settings":{"community":"x","classify":{"lldpCaps":true}}}`:  DefaultClassifySettings(),
		`{"settings":{"community":"x","classify":{"lldpCaps":false,"lldpHubs":false,"apHubAlert":true,"wifiClientsCountOnly":false,"mobileGroup":false}}}`: {APHubAlert: true},
	} {
		if err := os.WriteFile(savedDataFile, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := LoadSavedData()
		if err != nil {
			t.Fatal(err)
		}
		if got.Settings.Classify != want || got.Settings.Community != "x" {
			t.Errorf("%s: settings %+v, want classify %+v", body, got.Settings, want)
		}
	}

	SetCurrentSettings(DefaultSettings())
	post := func(body string) {
		t.Helper()
		rec := httptest.NewRecorder()
		settingsHandler(rec, httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s: %d %s", body, rec.Code, rec.Body)
		}
	}
	post(`{"ipRanges":["10.0.0.0/24"],"community":"c","timeout":20,"maxWorkers":50,"usePing":false}`)
	if got := GetCurrentSettings(); got.Classify != DefaultClassifySettings() || got.Community != "c" || rebuilds != 0 {
		t.Errorf("a POST without classify: %+v, %d rebuilds", got, rebuilds)
	}
	post(`{"ipRanges":["10.0.0.0/24"],"community":"c","classify":{"lldpCaps":false}}`)
	if got := GetCurrentSettings(); got.Classify.LLDPCaps || got.Timeout != 20 || rebuilds != 1 {
		t.Errorf("a POST turning lldpCaps off: %+v, %d rebuilds", got, rebuilds)
	}
	post(`{"ipRanges":["10.0.0.0/24"],"community":"c","classify":{"lldpCaps":false}}`)
	if rebuilds != 1 {
		t.Errorf("a POST with the same choices rebuilt the graph")
	}

	indexHTML, err := os.ReadFile(filepath.Join(root, "static", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	appJS, err := os.ReadFile(filepath.Join(root, "static", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	choices := reflect.TypeFor[ClassifySettings]()
	for i := range choices.NumField() {
		tag := strings.Split(choices.Field(i).Tag.Get("json"), ",")[0]
		if !strings.Contains(string(indexHTML), `id="settingsClassify-`+tag+`"`) {
			t.Errorf("index.html: no checkbox settingsClassify-%s", tag)
		}
		if !strings.Contains(string(appJS), "'"+tag+"'") {
			t.Errorf("app.js: uiClassifyChoices has no %q", tag)
		}
	}
}
