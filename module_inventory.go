package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
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
// they manage by canonical MAC, inventoryNotices what was logged (the
// failures and notes by "module|ip", the lines of inventoryNotice);
// inventoryMu guards them.
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
	Kind       string                  `json:"kind,omitempty"` // "access_point", "switch", "gateway"
	Uplink     *modules.ManagedUplink  `json:"uplink,omitempty"`
	Updated    time.Time               `json:"updated"`
	Clients    []modules.ManagedClient `json:"clients,omitempty"`
}

// ClientView is a client of a managed device, as /api/graph shows its
// node: what the controller tells of it, and the device's name.
type ClientView struct {
	modules.ManagedClient
	Device string `json:"device"` // "A 1 qavat 118", the gateway's name
}

// inventoryAPsChanged runs when a read changed the access points the
// graph build draws (addManagedAPNodes): it builds the graph again, so they
// show at once (a variable for tests).
var inventoryAPsChanged = func() { go rebuildGraph() }

// inventoryAPs is what of managedByMAC the graph build draws: each access
// point with its IP, state and uplink (inventoryMu held).
func inventoryAPs() string {
	var lines []string
	for mac, v := range managedByMAC {
		if v.Kind == "access_point" {
			line := strings.Join([]string{mac, v.Name, v.IP, v.State}, "|")
			if v.Uplink != nil {
				line += fmt.Sprintf("|%+v", *v.Uplink)
			}
			lines = append(lines, line)
		}
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
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
				State: d.State, Firmware: d.Firmware, Kind: d.Kind, Uplink: d.Uplink, Updated: rec.Time, Clients: d.Clients}
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

// addManagedAPNodes adds to the graph the access points the controllers
// manage that it has no node for, by MAC or IP (the build's step 3c): a
// node by the access point's MAC (group access_point, graphManaged) with
// its name and IP, unreachable when its controller has it offline, linked
// where it is connected. Its controller tells where (ManagedView.Uplink):
// the switch port its LLDP sees, the UniFi switch, or the access point of
// a mesh link, when that device is a node (the port of a polled switch that
// the controller does not name, or names by a MAC, is the one of its FDB
// that learns the access point's MAC, with the fewest MACs); else the link
// is the switch port its MAC is learned on, by the rule of a gateway's
// router node (gatewayPort: no other switch or gateway learned there, the
// fewest MACs; a [MAC-REF] link); else it has none, and the tree shows it
// under "Not connected".
func addManagedAPNodes(graph *DJGraph, snapshot map[string]*DeviceData, switchMACs map[string]string) {
	known := map[string]bool{} // the IPs of the nodes
	for id := range graph.Nodes {
		known[id] = true
		for _, line := range strings.Split(graph.SwitchInfo[id], "\n") {
			if parseIPv4(line) != "" {
				known[line] = true
			}
		}
	}
	inventoryMu.Lock()
	var macs []string
	views := map[string]ManagedView{}
	for mac, v := range managedByMAC {
		if v.Kind == "access_point" && !graph.Nodes[mac] && (v.IP == "" || !known[v.IP]) {
			macs = append(macs, mac)
			views[mac] = v
		}
	}
	inventoryMu.Unlock()
	if len(macs) == 0 {
		return
	}
	slices.Sort(macs)
	if graph.graphManaged == nil {
		graph.graphManaged = make(map[string]bool)
	}
	for _, mac := range macs {
		v := views[mac]
		graph.AddNode(mac)
		graph.graphManaged[mac] = true
		graph.SwitchInfo[mac] = strings.Trim(v.Name+"\n"+v.IP, "\n")
		if strings.EqualFold(v.State, "OFFLINE") {
			graph.NodeStatus[mac] = "unreachable"
		}
	}

	// The switches and gateways, for the FDB port (gatewayPort)
	infra := make(map[string]string, len(switchMACs)+len(graph.graphRouters)+1)
	for m, id := range switchMACs {
		infra[m] = id
	}
	for m := range graph.graphRouters {
		infra[m] = m
	}
	byUplink, byFDB, none := 0, 0, 0
	for _, mac := range macs {
		v := views[mac]
		where := ""
		if up := v.Uplink; up != nil {
			parent := canonicalMAC(up.MAC)
			if id, ok := switchMACs[parent]; ok {
				parent = id
			}
			switch {
			case parent == "" || parent == mac || !graph.Nodes[parent]:
			case up.Wireless:
				graph.AddEdge(parent, mac, "mesh|mesh")
				where = "linked by a mesh link from " + parent
			default:
				port := strings.TrimSpace(up.Port)
				if port == "" || canonicalMAC(port) != "" {
					port = managedFDBPort(snapshot, parent, mac)
				}
				graph.AddEdge(parent, mac, port+"|"+strings.TrimSpace(up.LocalPort))
				where = strings.TrimSpace(fmt.Sprintf("linked by its uplink %s %s", parent, port))
			}
		}
		if where != "" {
			byUplink++
		} else {
			infra[mac] = mac
			link, ok := gatewayPort(snapshot, mac, infra)
			delete(infra, mac)
			if ok {
				switchID := graphDeviceNodeID(link.dev)
				portName := normalizePortName(getFDBPortName(link.dev, link.port))
				graph.AddEdge(switchID, mac, portName+" [MAC-REF]|")
				where = fmt.Sprintf("linked by the FDB of %s %s (%s on the port)", link.dev.IP, portName, switchSkipCount(link.macs, "MAC"))
				byFDB++
			} else {
				where = "not linked: its uplink is no node, and no switch port learns its MAC without another switch"
				none++
			}
		}
		inventoryNotice(fmt.Sprintf("📡 [Inventory] %s %s (%s) drawn from %s %s, %s", v.Name, mac, cmp.Or(v.IP, "no IP"), v.Source, v.Controller, where))
	}
	inventoryNotice(fmt.Sprintf("📡 [Inventory] %d access points no switch shows drawn from their controllers: %d linked by their uplink, %d by the FDB, %d not linked", len(macs), byUplink, byFDB, none))
}

// managedFDBPort is the port of the polled switch with node id switchID
// whose FDB learns mac, the one with the fewest MACs (then the lower
// port), normalized; "" when it learns mac on none.
func managedFDBPort(snapshot map[string]*DeviceData, switchID, mac string) string {
	for _, ip := range sortedDeviceIPs(snapshot) {
		d := snapshot[ip]
		if graphDeviceNodeID(d) != switchID {
			continue
		}
		macs := map[int]int{} // port → the MACs learned there, for the ports that learn mac
		for _, e := range d.MACTable {
			if usableMAC(e.MACAddress) == mac {
				macs[e.PortNumber] = 0
			}
		}
		for _, e := range d.MACTable {
			if n, ok := macs[e.PortNumber]; ok && usableMAC(e.MACAddress) != "" {
				macs[e.PortNumber] = n + 1
			}
		}
		best := -1
		for _, port := range slices.Sorted(maps.Keys(macs)) {
			if !isNullInterface(getFDBPortName(d, port)) && (best < 0 || macs[port] < macs[best]) {
				best = port
			}
		}
		if best >= 0 {
			return normalizePortName(getFDBPortName(d, best))
		}
	}
	return ""
}

// inventoryNotice prints a line once in a run.
func inventoryNotice(line string) {
	inventoryMu.Lock()
	printed := inventoryNotices["line|"+line] != ""
	inventoryNotices["line|"+line] = "printed"
	inventoryMu.Unlock()
	if !printed {
		fmt.Println(line)
	}
}

// addManagedClients adds the clients of the managed devices to the graph
// data, for the canvas: a node per client that is no node yet (group
// wifi_client: its name, from its controller, else its DHCP host name,
// else its DNS name, and its IP), and a link from its device unless the
// two are linked already: "WLAN" from an access point, "ARP" from a
// gateway (addGatewayWLANHosts). A client's node, new or not, gets what the
// controller tells of it (GraphNode.Client). A wired client (on a UniFi
// switch) is left out: the switch FDB shows it. The UI shows the clients on
// demand: their WLAN filter starts off, and a device's "Show Connected"
// shows its own.
func addManagedClients(data *GraphData) {
	have := make(map[string]int, len(data.Nodes)) // node id → its index
	for i, n := range data.Nodes {
		have[n.ID] = i
	}
	linked := make(map[string]bool, 2*len(data.Links))
	for _, l := range data.Links {
		linked[l.Source+"|"+l.Target], linked[l.Target+"|"+l.Source] = true, true
	}
	devices := len(data.Nodes)
	for i := 0; i < devices; i++ {
		dev := data.Nodes[i]
		if dev.Managed == nil {
			continue
		}
		label, near := "WLAN|wlan", "WLAN"
		if dev.Managed.Source == gatewayARPSource {
			label, near = "ARP|wlan", "ARP"
		}
		devName := cmp.Or(dev.Managed.Name, strings.Split(dev.SysName, "\n")[0], dev.ID)
		for _, c := range dev.Managed.Clients {
			mac := canonicalMAC(c.MAC)
			if mac == "" || mac == dev.ID || c.Kind == "wired" || c.Kind == "vm" {
				continue // a VM: addManagedVMNames
			}
			if at, ok := have[mac]; ok {
				if data.Nodes[at].Client == nil {
					data.Nodes[at].Client = &ClientView{ManagedClient: c, Device: devName}
				}
			} else {
				have[mac] = len(data.Nodes)
				name, hostname := c.Name, ""
				if name == "" || strings.EqualFold(name, mac) {
					name = c.Hostname
				}
				if name == "" {
					name, hostname = wlanDNSName(c.IP), wlanDNSName(c.IP)
				}
				var lines []string
				if name != "" {
					lines = append(lines, name)
				}
				if c.IP != "" {
					lines = append(lines, c.IP)
				}
				info := strings.Join(lines, "\n")
				data.Nodes = append(data.Nodes, GraphNode{ID: mac, Label: strings.TrimPrefix(info+"\n"+mac, "\n"), Group: "wifi_client",
					NodeType: "wifi_client", SysName: info, IP: c.IP, Hostname: hostname, Client: &ClientView{ManagedClient: c, Device: devName}})
			}
			if !linked[dev.ID+"|"+mac] {
				linked[dev.ID+"|"+mac], linked[mac+"|"+dev.ID] = true, true
				data.Links = append(data.Links, GraphLink{Source: dev.ID, Target: mac, Label: label, SourceLabel: near, TargetLabel: "wlan", Kind: "wlan"})
			}
		}
	}
}

// addManagedVMNames gives the nodes of the virtual machines the vCenters
// list (clients of kind "vm" of their hosts) what vCenter tells of them
// (GraphNode.Client: the VM's name, guest OS, power, ...), whether or not
// their host is a node: the UI names a VM's node by its vCenter name. No
// node or link is added: the graph places the VMs by the switches' FDBs.
func addManagedVMNames(data *GraphData) {
	at := make(map[string]int, len(data.Nodes))
	for i, n := range data.Nodes {
		at[n.ID] = i
	}
	inventoryMu.Lock()
	defer inventoryMu.Unlock()
	for _, dev := range managedByMAC {
		for _, c := range dev.Clients {
			if c.Kind != "vm" {
				continue
			}
			if i, ok := at[canonicalMAC(c.MAC)]; ok && data.Nodes[i].Client == nil {
				data.Nodes[i].Client = &ClientView{ManagedClient: c, Device: dev.Name}
			}
		}
	}
}

// wlanDNSName is the short DNS name of a client's IP from the scanner's
// cache ("Elliot" for Elliot.dhcp.tuit.uz), "" when there is none or it is
// only the IP spelt out (a provider's 172-15-182-169.lightspeed...):
// inventoryResolveNames starts the lookups.
func wlanDNSName(ip string) string {
	if ip == "" {
		return ""
	}
	name, _ := cachedHostname(ip)
	if strings.Contains(name, strings.ReplaceAll(ip, ".", "-")) {
		return ""
	}
	return name
}

// gatewayARPSource is the source of the clients addGatewayWLANHosts gives
// a gateway's router node.
const gatewayARPSource = "Gateway ARP"

// addGatewayWLANHosts gives each gateway's router node the hosts of its
// WLAN subnets that the graph shows nowhere else, as the clients of a
// managed device (GraphNode.Managed, source "Gateway ARP"), so
// addManagedClients draws them below it and the tree lists them. A WLAN
// subnet is a subnet of the gateway that holds a Wi-Fi client of a managed device
// (172.15.0.0/16 of the pfSense 172.15.1.254: the UniFi clients' subnet),
// unless the IP of another gateway is in it and its own is not: debian216
// 172.20.1.254 has 172.15.1.253 in it too, and the hosts it talked to in
// its ARP table, but the pfSense is that WLAN's gateway. A host goes to one
// gateway only, the first in gateway_ip order.
// Left out are the hosts the graph has as nodes or as clients of a device
// in it, the managed devices themselves (the access points), their
// controllers and the gateway. A client its controller lists on a device the graph does not
// have keeps what the controller tells of it. The gateway decides who is on the
// WLAN (its ARP table), the controller where and by which name.
func addGatewayWLANHosts(data *GraphData) {
	have := make(map[string]bool, len(data.Nodes))
	shown := map[string]bool{} // the clients of devices in the graph
	for _, n := range data.Nodes {
		have[n.ID] = true
		if n.Managed != nil {
			for _, c := range n.Managed.Clients {
				shown[canonicalMAC(c.MAC)] = true
			}
		}
	}
	// Every client the controllers list, with its device, and their IPs
	inventoryMu.Lock()
	known := map[string]modules.ManagedClient{}
	var clientIPs []netip.Addr
	managedMAC := map[string]bool{}
	controllers := map[string]bool{} // their IPs
	for _, rec := range inventories {
		controllers[rec.IP] = true
	}
	for mac, dev := range managedByMAC {
		managedMAC[mac] = true
		for _, c := range dev.Clients {
			known[canonicalMAC(c.MAC)] = c
			if a, err := netip.ParseAddr(c.IP); err == nil && c.Kind == "wireless" {
				clientIPs = append(clientIPs, a)
			}
		}
	}
	inventoryMu.Unlock()
	if len(clientIPs) == 0 {
		return
	}
	tables := gatewayHostTables()
	var gatewayAddrs []netip.Addr
	for _, gw := range tables {
		if a, err := netip.ParseAddr(gw.IP); err == nil {
			gatewayAddrs = append(gatewayAddrs, a)
		}
	}
	taken := map[string]bool{} // the hosts a gateway before has
	for _, gw := range tables {
		own, _ := netip.ParseAddr(gw.IP)
		var wlan []netip.Prefix
		for _, p := range gw.Subnets {
			if p.Bits() < 31 && slices.ContainsFunc(clientIPs, p.Contains) &&
				(p.Contains(own) || !slices.ContainsFunc(gatewayAddrs, p.Contains)) {
				wlan = append(wlan, p)
			}
		}
		if len(wlan) == 0 {
			continue
		}
		router := slices.IndexFunc(data.Nodes, func(n GraphNode) bool {
			return n.Group == "router" && slices.Contains(strings.Split(n.SysName, "\n"), gw.IP)
		})
		if router < 0 || data.Nodes[router].Managed != nil {
			continue
		}
		var hosts []modules.ManagedClient
		seen := map[string]bool{}
		for _, e := range gw.ARP {
			mac := usableMAC(e.MACAddress)
			addr, err := netip.ParseAddr(e.IPAddress)
			if mac == "" || err != nil || seen[mac] || taken[mac] || have[mac] || shown[mac] || managedMAC[mac] || controllers[e.IPAddress] || mac == data.Nodes[router].ID ||
				!slices.ContainsFunc(wlan, func(p netip.Prefix) bool { return p.Contains(addr) }) {
				continue
			}
			seen[mac] = true
			h := modules.ManagedClient{MAC: mac, IP: e.IPAddress, Kind: "arp"}
			if c, ok := known[mac]; ok {
				h = c // with what its controller tells of it
				h.MAC, h.IP = mac, e.IPAddress
			}
			hosts = append(hosts, h)
		}
		if len(hosts) == 0 {
			continue
		}
		for mac := range seen {
			taken[mac] = true
		}
		slices.SortFunc(hosts, func(a, b modules.ManagedClient) int { return compareIPs(a.IP, b.IP) })
		data.Nodes[router].Managed = &ManagedView{Source: gatewayARPSource, Controller: gw.IP, Clients: hosts}
	}
}

// inventoryResolveNames starts the reverse DNS lookups of the clients'
// IPs, the controllers' and the WLAN hosts' of the gateways, so their
// nodes get names (wlanDNSName); it waits a little, the rest fill the
// cache later.
func inventoryResolveNames() {
	var ips []string
	inventoryMu.Lock()
	for _, dev := range managedByMAC {
		for _, c := range dev.Clients {
			if c.IP != "" && c.Kind != "vm" { // the graph build looks up the VMs it has
				ips = append(ips, c.IP)
			}
		}
	}
	inventoryMu.Unlock()
	if len(ips) == 0 {
		return
	}
	for _, gw := range gatewayHostTables() {
		for _, e := range gw.ARP {
			ips = append(ips, e.IPAddress)
		}
	}
	slices.Sort(ips)
	resolveHostnames(slices.Compact(ips), 20*time.Second)
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
	for i, l := range logins {
		login, others := moduleLogins(logins, i)
		got, err := inv.Inventory(ctx, modules.Request{IP: ip, Login: login, Others: others})
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
		aps := inventoryAPs()
		inventories[m.ID()+"|"+ip] = inventoryRecord{Module: m.ID(), IP: ip, Time: time.Now(), Inventory: got}
		inventoryIndex()
		inventorySave()
		apsChanged := inventoryAPs() != aps
		inventoryMu.Unlock()
		if apsChanged {
			inventoryAPsChanged()
		}
		notice("")
		if first {
			fmt.Printf("🧩 [Inventory %s] %s: %d devices, %d clients\n", m.ID(), ip, len(got.Devices), clients)
		}
		// What it could not read, once until it changes
		notes := strings.Join(got.Notes, "; ")
		inventoryMu.Lock()
		changed := inventoryNotices[m.ID()+"|"+ip+"|notes"] != notes
		inventoryNotices[m.ID()+"|"+ip+"|notes"] = notes
		inventoryMu.Unlock()
		if changed && notes != "" {
			fmt.Printf("ℹ️  [Inventory %s] %s: %s\n", m.ID(), ip, notes)
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
	inventoryResolveNames()
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
