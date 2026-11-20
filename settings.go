package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// ScanSettings holds scanner configuration
type ScanSettings struct {
	IPRanges   []string         `json:"ipRanges"`
	Community  string           `json:"community"`
	Timeout    int              `json:"timeout"` // seconds
	MaxWorkers int              `json:"maxWorkers"`
	UsePing    bool             `json:"usePing"`
	Classify   ClassifySettings `json:"classify"`
}

// ClassifySettings are the owner's choices of how nodes are classified
// (Settings → Classification, classify.go): each turns one rule on, and
// off gives the rule's behaviour before it. The defaults are the
// recommended choices; a saved file without a choice gets its default.
type ClassifySettings struct {
	// LLDPCaps groups an unpolled LLDP neighbor by its LLDP capabilities
	// when its vendor tells no kind: a wireless access point is an access
	// point, a bridge or router (no phone) an unpolled switch (lldp_switch).
	LLDPCaps bool `json:"lldpCaps"`
	// LLDPHubs draws a port with several LLDP neighbors (no polled switch
	// or router, no unpolled switch among them: an unmanaged switch that
	// passes LLDP on) behind a hub node (lldpPortPlans): a Shadow-IT hub,
	// an AP hub when they are all access points, or, for a phone and one
	// device, the device behind the phone (its PC port).
	LLDPHubs bool `json:"lldpHubs"`
	// APHubAlert makes an AP hub a Shadow-IT hub (an alert) too.
	APHubAlert bool `json:"apHubAlert"`
	// WiFiClientsCountOnly counts the FDB MACs behind an AP hub (its access
	// points' clients) in its label instead of drawing them.
	WiFiClientsCountOnly bool `json:"wifiClientsCountOnly"`
	// MobileGroup gives the smartphones and tablets of their makers' OUIs
	// (Apple, Samsung, Xiaomi, ...: OUI category "mobile") their own group,
	// mobile, instead of phone, the IP phones' group.
	MobileGroup bool `json:"mobileGroup"`
	// ControllerKindWins groups a node by what the owner or a controller
	// tells, above its tags and its OUI (classifyNode): the device type the
	// Credentials logins for its IP declare, else the kind a controller
	// manages its MAC as (a UniFi access point, switch or gateway, a
	// vCenter host, a Kerio phone); a PBX's phone known by its IP only
	// makes an endpoint a phone. Off, only /api/graph gives a PBX's phone
	// its group, as before, and the reports, the analyzer and Telegram do
	// not see it.
	ControllerKindWins bool `json:"controllerKindWins"`
}

// DefaultClassifySettings are the recommended classification choices.
func DefaultClassifySettings() ClassifySettings {
	return ClassifySettings{LLDPCaps: true, LLDPHubs: true, WiFiClientsCountOnly: true, MobileGroup: true, ControllerKindWins: true}
}

// SavedData holds all persistent data
type SavedData struct {
	Hosts     map[string]*DeviceData `json:"hosts"`
	Settings  ScanSettings           `json:"settings"`
	Timestamp time.Time              `json:"timestamp"`
}

const savedDataFile = "network_data.json"

var (
	currentSettings      ScanSettings
	currentSettingsMutex sync.RWMutex
)

// DefaultSettings returns default scan settings
func DefaultSettings() ScanSettings {
	return ScanSettings{
		IPRanges:   []string{},
		Community:  "public",
		Timeout:    20,
		MaxWorkers: 50,
		UsePing:    false,
		Classify:   DefaultClassifySettings(),
	}
}

// GetCurrentSettings returns current settings
// Falls back to reading swich_ips file if IPRanges is empty
func GetCurrentSettings() ScanSettings {
	currentSettingsMutex.RLock()
	settings := currentSettings
	currentSettingsMutex.RUnlock()

	// If no saved IP ranges, read from swich_ips file
	if len(settings.IPRanges) == 0 {
		if ranges, err := readSwitchIPsFile(); err == nil && len(ranges) > 0 {
			settings.IPRanges = ranges
		}
	}

	return settings
}

// currentClassify is the classification choices of the current settings.
func currentClassify() ClassifySettings {
	currentSettingsMutex.RLock()
	defer currentSettingsMutex.RUnlock()
	return currentSettings.Classify
}

// SetCurrentSettings updates current settings and syncs swich_ips file
func SetCurrentSettings(s ScanSettings) {
	currentSettingsMutex.Lock()
	currentSettings = s
	currentSettingsMutex.Unlock()

	// Sync IP ranges to swich_ips file
	if len(s.IPRanges) > 0 {
		writeSwitchIPsFile(s.IPRanges)
	}
}

// readSwitchIPsFile reads IP ranges from swich_ips file
func readSwitchIPsFile() ([]string, error) {
	data, err := os.ReadFile("swich_ips")
	if err != nil {
		return nil, err
	}
	var ranges []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			ranges = append(ranges, line)
		}
	}
	return ranges, nil
}

// writeSwitchIPsFile writes IP ranges to swich_ips file
func writeSwitchIPsFile(ranges []string) {
	content := strings.Join(ranges, "\n") + "\n"
	os.WriteFile("swich_ips", []byte(content), 0644)
}

// appendToSwitchIPs adds a single IP to swich_ips file if not already present.
// Thread-safe with duplicate check. Used by LLDP auto-discovery.
func appendToSwitchIPs(newIP string) bool {
	newIP = strings.TrimSpace(newIP)
	if newIP == "" {
		return false
	}

	// Read existing entries and check for duplicates
	existing, _ := readSwitchIPsFile()
	for _, entry := range existing {
		if entry == newIP {
			return false // already exists
		}
	}

	// Append to file
	f, err := os.OpenFile("swich_ips", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("⚠️ [Discovery] Cannot append to swich_ips: %v\n", err)
		return false
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\n", newIP)
	fmt.Printf("📝 [Discovery] Added %s to swich_ips\n", newIP)
	return true
}

// LoadSavedData loads saved hosts and settings from file
func LoadSavedData() (*SavedData, error) {
	data, err := os.ReadFile(savedDataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No saved data
		}
		return nil, err
	}

	// A choice the file does not have keeps its default
	saved := SavedData{Settings: ScanSettings{Classify: DefaultClassifySettings()}}
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, err
	}

	return &saved, nil
}

// SaveData saves hosts and settings to file
func SaveData(hosts map[string]*DeviceData, settings ScanSettings) error {
	saved := SavedData{
		Hosts:     hosts,
		Settings:  settings,
		Timestamp: time.Now(),
	}

	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(savedDataFile, data, 0644)
}

// ClearSavedData removes saved data file
func ClearSavedData() error {
	err := os.Remove(savedDataFile)
	if os.IsNotExist(err) {
		return nil // Already doesn't exist
	}
	return err
}

// HasSavedData checks if saved data exists
func HasSavedData() bool {
	_, err := os.Stat(savedDataFile)
	return err == nil
}

func init() {
	// Initialize with defaults
	currentSettings = DefaultSettings()

	// Load the gateway IPs from file (one or several, gateways.go)
	loadGatewayIPs(gatewayFile)

	// Try to load saved settings
	if saved, err := LoadSavedData(); err == nil && saved != nil {
		currentSettings = saved.Settings
		fmt.Printf("📂 Loaded settings from %s\n", savedDataFile)
	}
}
