package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"lldp_scanner/modules"
)

// ─── Device inventories ───────────────────────────────────────────────────────
//
// A module whose devices manage others (modules.Inventorier: a UniFi
// controller and its access points) is read every inventoryInterval with
// the device's login: the devices it manages, by MAC, with the clients on
// each. /api/graph gives a node the managed device of its MAC
// (GraphNode.Managed), so the tree and the info panel name an access point
// as its controller does ("A 1 qavat 118" for the LLDP name A1qavat118),
// with its state and its clients. The last inventory of each device is
// kept in inventoryFile, so a restart shows it at once.

const inventoryInterval = 5 * time.Minute

// inventoryFile holds the last inventories (a variable for tests).
var inventoryFile = "modules_inventory.json"

// inventoryRecord is the last inventory read from one device.
type inventoryRecord struct {
	Module    string            `json:"module"`
	IP        string            `json:"ip"`
	Time      time.Time         `json:"time"`
	Inventory modules.Inventory `json:"inventory"`
}

// inventories holds the records by "module|ip", managedByMAC the devices
// they manage by canonical MAC, inventoryNotices the failures already
// logged; inventoryMu guards them.
var (
	inventoryMu      sync.Mutex
	inventories      = make(map[string]inventoryRecord)
	managedByMAC     = make(map[string]ManagedView)
	inventoryNotices = make(map[string]string)
)

// ManagedView is the device a controller manages under a graph node's MAC,
// as /api/graph shows it.
type ManagedView struct {
	Source     string                  `json:"source"`     // the module's label, "UniFi Network controller"
	Controller string                  `json:"controller"` // its IP
	Name       string                  `json:"name"`
	Model      string                  `json:"model,omitempty"`
	IP         string                  `json:"ip,omitempty"`
	State      string                  `json:"state,omitempty"`
	Firmware   string                  `json:"firmware,omitempty"`
	Updated    time.Time               `json:"updated"`
	Clients    []modules.ManagedClient `json:"clients,omitempty"`
}

// inventoryIndex rebuilds managedByMAC from the records, the newest record
// of a MAC winning (inventoryMu held).
func inventoryIndex() {
	keys := make([]string, 0, len(inventories))
	for k := range inventories {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return inventories[a].Time.Compare(inventories[b].Time) })
	index := make(map[string]ManagedView)
	for _, k := range keys {
		rec := inventories[k]
		label := rec.Module
		if m := modules.Find(rec.Module); m != nil {
			label = m.Label()
		}
		for _, d := range rec.Inventory.Devices {
			mac := canonicalMAC(d.MAC)
			if mac == "" {
				continue
			}
			index[mac] = ManagedView{Source: label, Controller: rec.IP, Name: d.Name, Model: d.Model, IP: d.IP,
				State: d.State, Firmware: d.Firmware, Updated: rec.Time, Clients: d.Clients}
		}
	}
	managedByMAC = index
}

// managedViewOf returns the managed device under a node id, or nil.
func managedViewOf(id string) *ManagedView {
	mac := canonicalMAC(id)
	if mac == "" {
		return nil
	}
	inventoryMu.Lock()
	defer inventoryMu.Unlock()
	if v, ok := managedByMAC[mac]; ok {
		return &v
	}
	return nil
}

// addManaged gives the graph data's nodes their managed devices.
func addManaged(data *GraphData) {
	for i := range data.Nodes {
		data.Nodes[i].Managed = managedViewOf(data.Nodes[i].ID)
	}
}

// inventoryLoad reads inventoryFile (none is no record).
func inventoryLoad() {
	data, err := os.ReadFile(inventoryFile)
	if err != nil {
		return
	}
	var recs []inventoryRecord
	if err := json.Unmarshal(data, &recs); err != nil {
		fmt.Printf("⚠️  [Inventory] %s: %v\n", inventoryFile, err)
		return
	}
	inventoryMu.Lock()
	defer inventoryMu.Unlock()
	for _, r := range recs {
		inventories[r.Module+"|"+r.IP] = r
	}
	inventoryIndex()
}

// inventorySave writes the records (inventoryMu held), atomically and for
// the scanner only: client names and addresses are the network's.
func inventorySave() {
	recs := make([]inventoryRecord, 0, len(inventories))
	for _, r := range inventories {
		recs = append(recs, r)
	}
	slices.SortFunc(recs, func(a, b inventoryRecord) int { return strings.Compare(a.Module+"|"+a.IP, b.Module+"|"+b.IP) })
	data, err := json.MarshalIndent(recs, "", "  ")
	if err == nil {
		tmp := inventoryFile + ".tmp"
		if err = os.WriteFile(tmp, data, 0o600); err == nil {
			err = os.Rename(tmp, inventoryFile)
		}
	}
	if err != nil {
		fmt.Printf("⚠️  [Inventory] %s: %v\n", inventoryFile, err)
	}
}

// inventoryTargets lists the devices to read, by module: the IPs the
// Credentials window declares of the module's type, those whose probe
// recognized the module's device, those it ran an action on, and those
// read before.
func inventoryTargets(m modules.Module) []string {
	var ips []string
	add := func(ip string) {
		if ip != "" && !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	credentialsMu.Lock()
	entries, _ := credentialsLoad()
	credentialsMu.Unlock()
	for _, e := range entries {
		if e.Target.Kind == "ip" && e.DeviceType == m.Type() {
			add(e.Target.Value)
		}
	}
	moduleProbeMu.Lock()
	for key, a := range moduleProbes {
		if ip, ok := strings.CutPrefix(key, m.ID()+"|"); ok && a.is {
			add(ip)
		}
	}
	moduleProbeMu.Unlock()
	moduleRunMu.Lock()
	for key, last := range moduleLast {
		if ip, ok := strings.CutPrefix(key, m.ID()+"|"); ok && last.OK {
			add(ip)
		}
	}
	moduleRunMu.Unlock()
	inventoryMu.Lock()
	for _, r := range inventories {
		if r.Module == m.ID() {
			add(r.IP)
		}
	}
	inventoryMu.Unlock()
	slices.Sort(ips)
	return ips
}

// inventoryRead reads the inventory of one device with its logins, in
// order, and keeps it; a failure keeps the record read before and is
// logged once until it changes.
func inventoryRead(ctx context.Context, m modules.Module, inv modules.Inventorier, ip string) {
	notice := func(text string) {
		inventoryMu.Lock()
		changed := inventoryNotices[m.ID()+"|"+ip] != text
		inventoryNotices[m.ID()+"|"+ip] = text
		inventoryMu.Unlock()
		if changed && text != "" {
			fmt.Printf("⚠️  [Inventory %s] %s: %s\n", m.ID(), ip, text)
		}
	}
	types := deviceTypesOf(ctx, ip)
	if !slices.Contains(types, m.Type()) {
		notice("no " + m.Label() + " answers there now")
		return
	}
	logins, err := credentialsFor(ip, m.Protocol(), types)
	if err != nil || len(logins) == 0 {
		notice("no " + m.Protocol() + " login for it in Credentials")
		return
	}
	for _, l := range logins {
		got, err := inv.Inventory(ctx, modules.Request{IP: ip, Login: modules.Login{Username: l.Username, Password: l.Password}})
		if errors.Is(err, modules.ErrLoginRejected) {
			continue
		}
		if err != nil {
			notice(err.Error())
			return
		}
		credentialsWorked(ip, m.Protocol(), l.ID)
		clients := 0
		for _, d := range got.Devices {
			clients += len(d.Clients)
		}
		inventoryMu.Lock()
		first := inventories[m.ID()+"|"+ip].Time.IsZero()
		inventories[m.ID()+"|"+ip] = inventoryRecord{Module: m.ID(), IP: ip, Time: time.Now(), Inventory: got}
		inventoryIndex()
		inventorySave()
		inventoryMu.Unlock()
		notice("")
		if first {
			fmt.Printf("🧩 [Inventory %s] %s: %d devices, %d clients\n", m.ID(), ip, len(got.Devices), clients)
		}
		return
	}
	notice(fmt.Sprintf("it refused all %d logins of Credentials", len(logins)))
}

// inventoryRound reads every device of every module with an inventory.
func inventoryRound() {
	for _, m := range modules.All() {
		inv, ok := m.(modules.Inventorier)
		if !ok {
			continue
		}
		for _, ip := range inventoryTargets(m) {
			ctx, cancel := context.WithTimeout(context.Background(), moduleRunTimeout)
			inventoryRead(ctx, m, inv, ip)
			cancel()
		}
	}
}

// startModuleInventory loads the kept inventories and reads them again
// every inventoryInterval, the first time soon after the start.
func startModuleInventory() {
	inventoryLoad()
	go func() {
		time.Sleep(30 * time.Second)
		for {
			inventoryRound()
			time.Sleep(inventoryInterval)
		}
	}()
}
