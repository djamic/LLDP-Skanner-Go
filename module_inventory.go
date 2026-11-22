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
// with its state and its clients. A PBX (Kerio Operator) manages the
// phones: a phone it knows by the address its extension registered from
// (no MAC) is given to the node of that IP, and a node it names a phone is
// one (group "phone"), named by its extensions and user. The last
// inventory of each device is kept in inventoryFile, so a restart shows it
// at once.

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
// they manage by canonical MAC, managedByIP those with no MAC by IP,
// inventoryNotices what was logged (the failures and notes by
// "module|ip", the lines of inventoryNotice); inventoryMu guards them.
var (
	inventoryMu      sync.Mutex
	inventories      = make(map[string]inventoryRecord)
	managedByMAC     = make(map[string]ManagedView)
	managedByIP      = make(map[string]ManagedView)
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
	Kind       string                  `json:"kind,omitempty"` // "access_point", "switch", "gateway", "hypervisor", "phone"
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

// inventoryAPsChanged runs when a read changed what of the inventories the
// graph build reads (inventoryAPs): it builds the graph again, so it shows
// at once (a variable for tests).
var inventoryAPsChanged = func() { go rebuildGraph() }

// inventoryAPs is what of managedByMAC the graph build reads (inventoryMu
// held): each access point with its IP, state and uplink (addManagedAPNodes
// draws them, lldpPortPlans reads their uplinks), and each hypervisor's
// MAC (a vCenter host's VMkernel NIC is no VM, graphVCenterHostNIC). The
// kinds GetGraphData reads (classifyFacts) need no build.
func inventoryAPs() string {
	var lines []string
	for mac, v := range managedByMAC {
		switch v.Kind {
		case modules.KindAccessPoint:
			line := strings.Join([]string{mac, v.Name, v.IP, v.State}, "|")
			if v.Uplink != nil {
				line += fmt.Sprintf("|%+v", *v.Uplink)
			}
			lines = append(lines, line)
		case modules.KindHypervisor:
			lines = append(lines, mac+"|"+v.Kind)
		}
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

// inventoryIndex rebuilds managedByMAC and managedByIP from the records,
// the newest record of a MAC (an IP) winning (inventoryMu held).
func inventoryIndex() {
	keys := make([]string, 0, len(inventories))
	for k := range inventories {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return inventories[a].Time.Compare(inventories[b].Time) })
	index := make(map[string]ManagedView)
	byIP := make(map[string]ManagedView)
	for _, k := range keys {
		rec := inventories[k]
		label := rec.Module
		if m := modules.Find(rec.Module); m != nil {
			label = m.Label()
		}
		for _, d := range rec.Inventory.Devices {
			v := ManagedView{Source: label, Controller: rec.IP, Name: d.Name, Model: d.Model, IP: d.IP,
				State: d.State, Firmware: d.Firmware, Kind: d.Kind, Uplink: d.Uplink, Updated: rec.Time, Clients: d.Clients}
			if mac := canonicalMAC(d.MAC); mac != "" {
				index[mac] = v
			} else if ip := parseIPv4(d.IP); ip != "" {
				byIP[ip] = v
			}
		}
	}
	managedByMAC, managedByIP = index, byIP
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

// managedViewByIP returns the managed device known by ip only, or nil.
func managedViewByIP(ip string) *ManagedView {
	if ip == "" {
		return nil
	}
	inventoryMu.Lock()
	defer inventoryMu.Unlock()
	if v, ok := managedByIP[ip]; ok {
		return &v
	}
	return nil
}

// addManaged gives the graph data's nodes their managed devices: by the
// node's MAC, else, for a node that is no switch or router, the device
// known by the node's IP only. A node a PBX names a phone is one when its
// own data made it no more than an endpoint.
func addManaged(data *GraphData) {
	for i := range data.Nodes {
		n := &data.Nodes[i]
		n.Managed = managedViewOf(n.ID)
		if n.Managed == nil && n.Group != "switch" && n.Group != "router" {
			n.Managed = managedViewByIP(cmp.Or(n.IP, graphLabelIP(n.SysName)))
		}
		if n.Managed != nil {
			n.Group = managedGroup(n.Group, n.Managed.Kind)
		}
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
		if v.Kind == modules.KindAccessPoint && !graph.Nodes[mac] && (v.IP == "" || !known[v.IP]) {
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
		graphSetTags(graph, mac)
		if strings.EqualFold(v.State, modules.StateOffline) {
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
// else its DNS name, and its IP), and a "WLAN" link from its access point
// unless the two are linked already. A client's node, new or not, gets what the
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
				data.Links = append(data.Links, GraphLink{Source: dev.ID, Target: mac, Label: "WLAN|wlan", SourceLabel: "WLAN", TargetLabel: "wlan", Kind: "wlan"})
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

// WLANView is what the scanner tells of a gateway's Wi-Fi clients, as
// /api/graph shows its router node (addGatewayWLAN).
type WLANView struct {
	Clients int `json:"clients"` // the access points' clients it serves
}

// addGatewayWLAN joins the Wi-Fi clients of the managed access points in
// the graph with the gateways' ARP tables. The gateway of a client is one
// whose ARP table has its MAC: the one whose own IP is in the subnet of
// the client's IP first (the pfSense 172.15.1.254 of its 172.15.0.0/16, not
// debian216, which has 172.15.1.253 in it too), else the first in
// gateway_ip order. A client gets its gateway's name
// (ManagedClient.Gateway) and, when its controller tells no IP, the IP of
// the ARP table; the gateway's router node gets the count of its clients
// (GraphNode.WLAN). The clients stay below their access points: a host
// only an ARP table shows, which no controller lists, is left out, its
// access point unknown (the owner's choice).
func addGatewayWLAN(data *GraphData) {
	tables := gatewayHostTables()
	if len(tables) == 0 {
		return
	}
	type arpSeen struct {
		gateway int
		ip      string
		own     bool // the gateway's own IP is in the subnet of ip
	}
	byMAC := map[string]arpSeen{}
	names := make([]string, len(tables))
	routers := make([]int, len(tables))
	for i, gw := range tables {
		own, _ := netip.ParseAddr(gw.IP)
		routers[i] = slices.IndexFunc(data.Nodes, func(n GraphNode) bool {
			return n.Group == "router" && slices.Contains(strings.Split(n.SysName, "\n"), gw.IP)
		})
		names[i] = gw.IP
		if r := routers[i]; r >= 0 {
			if first := strings.Split(data.Nodes[r].SysName, "\n")[0]; first != gw.IP {
				names[i] = first + " " + gw.IP
			}
		}
		for _, e := range gw.ARP {
			mac := usableMAC(e.MACAddress)
			addr, err := netip.ParseAddr(e.IPAddress)
			if mac == "" || err != nil {
				continue
			}
			inOwn := slices.ContainsFunc(gw.Subnets, func(p netip.Prefix) bool { return p.Bits() < 31 && p.Contains(addr) && p.Contains(own) })
			if prev, ok := byMAC[mac]; !ok || (inOwn && !prev.own) {
				byMAC[mac] = arpSeen{gateway: i, ip: e.IPAddress, own: inOwn}
			}
		}
	}
	counts := make([]int, len(tables))
	for i := range data.Nodes {
		m := data.Nodes[i].Managed
		if m == nil {
			continue
		}
		var clients []modules.ManagedClient // a copy: the slice is the index's
		for j, c := range m.Clients {
			seen, ok := byMAC[canonicalMAC(c.MAC)]
			if !ok || c.Kind != "wireless" {
				continue
			}
			if clients == nil {
				clients = slices.Clone(m.Clients)
			}
			clients[j].Gateway = names[seen.gateway]
			if clients[j].IP == "" {
				clients[j].IP = seen.ip
			}
			counts[seen.gateway]++
		}
		if clients != nil {
			view := *m
			view.Clients = clients
			data.Nodes[i].Managed = &view
		}
	}
	for i, n := range counts {
		if r := routers[i]; r >= 0 && n > 0 {
			data.Nodes[r].WLAN = &WLANView{Clients: n}
		}
	}
}

// inventoryResolveNames starts the reverse DNS lookups of the IPs of the
// controllers' clients, their own or, for those they tell none, the
// gateways' ARP tables' (addGatewayWLAN), so their nodes get names
// (wlanDNSName); it waits a little, the rest fill the cache later.
func inventoryResolveNames() {
	var ips []string
	noIP := map[string]bool{}
	inventoryMu.Lock()
	for _, dev := range managedByMAC {
		for _, c := range dev.Clients {
			switch {
			case c.Kind == "vm": // the graph build looks up the VMs it has
			case c.IP != "":
				ips = append(ips, c.IP)
			default:
				noIP[canonicalMAC(c.MAC)] = true
			}
		}
	}
	inventoryMu.Unlock()
	for _, gw := range gatewayHostTables() {
		for _, e := range gw.ARP {
			if noIP[usableMAC(e.MACAddress)] {
				ips = append(ips, e.IPAddress)
			}
		}
	}
	if len(ips) == 0 {
		return
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

// startModuleInventory reads the inventories again every inventoryInterval,
// the first time soon after the start (loadStartupData loads the kept ones,
// before the first graph).
func startModuleInventory() {
	go func() {
		time.Sleep(30 * time.Second)
		for {
			inventoryRound()
			time.Sleep(inventoryInterval)
		}
	}()
}
