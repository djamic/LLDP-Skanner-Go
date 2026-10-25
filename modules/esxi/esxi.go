// Package esxi is the device module of VMware ESXi hosts: over the host's
// vSphere API (a login of protocol "vsphere") it detects the host (name,
// version, license, server, physical and VMkernel NICs with what CDP or
// LLDP tells of their switch ports, virtual machines, SNMP state) and
// enables its SNMP agent with the scanner's community.
package esxi

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"lldp_scanner/modules"
)

func init() { modules.Register(Module{}) }

// Module is the ESXi device module.
type Module struct{}

func (Module) ID() string       { return "esxi" }
func (Module) Label() string    { return "VMware ESXi" }
func (Module) Type() string     { return "esxi" }
func (Module) Protocol() string { return "vsphere" }

func (Module) Actions() []modules.Action {
	return []modules.Action{
		{ID: "detect", Label: "🔎 Detect"},
		{ID: "enable-snmp", Label: "📡 Enable SNMP", Changes: true, VerifySNMP: true,
			Confirm: "Enable the SNMP agent of this ESXi host with the scanner's community, open its 'snmp' firewall rule and start snmpd (on with the host)?"},
	}
}

// Run logs in to the host, runs the action and logs out.
func (Module) Run(ctx context.Context, req modules.Request) (modules.Result, error) {
	c := newVimClient(req.IP)
	if err := c.connect(ctx); err != nil {
		return modules.Result{}, err
	}
	if err := c.login(ctx, req.Login); err != nil {
		return modules.Result{}, err
	}
	defer c.logout(context.WithoutCancel(ctx))
	switch req.Action {
	case "detect":
		return detect(ctx, c)
	case "enable-snmp":
		return enableSNMP(ctx, c, req.Community)
	}
	return modules.Result{}, fmt.Errorf("unknown action %q", req.Action)
}

// The host of a standalone ESXi API
var hostRef = moRef{Type: "HostSystem", Value: "ha-host"}

// ─── The values the API sends ─────────────────────────────────────────────────

type hardwareSummary struct {
	Vendor               string `xml:"vendor"`
	Model                string `xml:"model"`
	OtherIdentifyingInfo []struct {
		Value string `xml:"identifierValue"`
		Type  struct {
			Key string `xml:"key"`
		} `xml:"identifierType"`
	} `xml:"otherIdentifyingInfo"`
	MemorySize    int64  `xml:"memorySize"`
	CPUModel      string `xml:"cpuModel"`
	NumCPUPkgs    int    `xml:"numCpuPkgs"`
	NumCPUCores   int    `xml:"numCpuCores"`
	NumCPUThreads int    `xml:"numCpuThreads"`
}

type productInfo struct {
	FullName string `xml:"fullName"`
}

type physicalNic struct {
	Key       string `xml:"key"`
	Device    string `xml:"device"`
	Driver    string `xml:"driver"`
	Mac       string `xml:"mac"`
	LinkSpeed *struct {
		SpeedMb int  `xml:"speedMb"`
		Duplex  bool `xml:"duplex"`
	} `xml:"linkSpeed"`
}

type virtualNic struct {
	Device    string `xml:"device"`
	Portgroup string `xml:"portgroup"`
	Spec      struct {
		Mac string `xml:"mac"`
		IP  struct {
			Address string `xml:"ipAddress"`
			DHCP    bool   `xml:"dhcp"`
		} `xml:"ip"`
	} `xml:"spec"`
}

type virtualSwitch struct {
	Name string   `xml:"name"`
	Pnic []string `xml:"pnic"` // "key-vim.host.PhysicalNic-vmnic0"
}

type nicHint struct {
	Device string `xml:"device"`
	CDP    *struct {
		DevID      string `xml:"devId"`
		PortID     string `xml:"portId"`
		Address    string `xml:"address"`
		SystemName string `xml:"systemName"`
	} `xml:"connectedSwitchPort"`
	LLDP *struct {
		ChassisID string `xml:"chassisId"`
		PortID    string `xml:"portId"`
		Parameter []struct {
			Key   string `xml:"key"`
			Value string `xml:"value"`
		} `xml:"parameter"`
	} `xml:"lldpInfo"`
}

type snmpConfig struct {
	Enabled     bool       `xml:"enabled"`
	Port        int        `xml:"port"`
	Communities []string   `xml:"readOnlyCommunities"`
	TrapTargets []rawValue `xml:"trapTargets"`
	Options     []rawValue `xml:"option"`
}

type firewallRuleset struct {
	Key     string `xml:"key"`
	Enabled bool   `xml:"enabled"`
}

type guestNic struct {
	Network    string   `xml:"network"`
	IPAddress  []string `xml:"ipAddress"`
	MacAddress string   `xml:"macAddress"`
}

type virtualDevice struct {
	MacAddress string `xml:"macAddress"`
}

// decodeString reads a string value; "" when it is missing.
func decodeString(p map[string]rawValue, path string) string {
	var s string
	if v, ok := p[path]; ok {
		v.decode(&s)
	}
	return strings.TrimSpace(s)
}

// ─── Detect ───────────────────────────────────────────────────────────────────

var hostPaths = []string{
	"name", "summary.hardware", "summary.config.product", "hardware.systemInfo.serialNumber",
	"config.network.dnsConfig", "config.network.pnic", "config.network.vnic", "config.network.vswitch",
	"configManager.networkSystem", "configManager.snmpSystem", "configManager.firewallSystem",
	"configManager.serviceSystem", "vm",
}

var vmPaths = []string{
	"name", "runtime.powerState", "summary.config.guestFullName", "guest.hostName", "guest.net", "config.hardware.device",
}

func detect(ctx context.Context, c *vimClient) (modules.Result, error) {
	var r modules.Result
	p, err := c.retrieveOne(ctx, hostRef, hostPaths...)
	if err != nil {
		return r, fmt.Errorf("host properties: %w", err)
	}

	var dns struct {
		HostName   string `xml:"hostName"`
		DomainName string `xml:"domainName"`
	}
	p["config.network.dnsConfig"].decode(&dns)
	name := dns.HostName
	if name != "" && dns.DomainName != "" {
		name += "." + dns.DomainName
	}
	if name == "" {
		name = decodeString(p, "name")
	}
	var product productInfo
	p["summary.config.product"].decode(&product)
	if product.FullName == "" {
		product.FullName = c.content.About.FullName
	}
	r.AddFact("Host name", name)
	r.AddFact("Product", product.FullName)
	r.AddFact("License", licenseName(ctx, c))

	var hw hardwareSummary
	p["summary.hardware"].decode(&hw)
	r.AddFact("Server", strings.TrimSpace(hw.Vendor+" "+hw.Model))
	serial := decodeString(p, "hardware.systemInfo.serialNumber")
	for _, id := range hw.OtherIdentifyingInfo {
		if serial == "" && (id.Type.Key == "SerialNumberTag" || id.Type.Key == "ServiceTag" || id.Type.Key == "EnclosureSerialNumberTag") {
			serial = strings.TrimSpace(id.Value)
		}
	}
	r.AddFact("Serial number", serial)
	if hw.CPUModel != "" {
		r.AddFact("CPU", fmt.Sprintf("%s (%d × %d cores, %d threads)", strings.Join(strings.Fields(hw.CPUModel), " "),
			hw.NumCPUPkgs, max(hw.NumCPUCores/max(hw.NumCPUPkgs, 1), 1), hw.NumCPUThreads))
	}
	if hw.MemorySize > 0 {
		r.AddFact("Memory", fmt.Sprintf("%.0f GiB", float64(hw.MemorySize)/(1<<30)))
	}

	// Physical NICs, the vSwitch of each, and what CDP or LLDP tells of the
	// switch port it is cabled to
	var pnics struct {
		Items []physicalNic `xml:"PhysicalNic"`
	}
	p["config.network.pnic"].decode(&pnics)
	var vswitches struct {
		Items []virtualSwitch `xml:"HostVirtualSwitch"`
	}
	p["config.network.vswitch"].decode(&vswitches)
	vswitchOf := map[string]string{}
	for _, vs := range vswitches.Items {
		for _, key := range vs.Pnic {
			vswitchOf[key] = vs.Name
		}
	}
	hints := nicHints(ctx, c, decodeString(p, "configManager.networkSystem"), pnics.Items)
	nics := modules.Table{Title: "Physical NICs", Columns: []string{"NIC", "MAC", "Speed", "vSwitch", "Switch", "Switch port"}}
	for _, n := range pnics.Items {
		speed := "down"
		if n.LinkSpeed != nil {
			speed = linkSpeed(n.LinkSpeed.SpeedMb)
		}
		sw, port := "", ""
		if h, ok := hints[n.Device]; ok {
			sw, port = h[0], h[1]
		}
		nics.Rows = append(nics.Rows, []string{n.Device, n.Mac, speed, vswitchOf[n.Key], sw, port})
	}
	r.Tables = append(r.Tables, nics)

	var vnics struct {
		Items []virtualNic `xml:"HostVirtualNic"`
	}
	p["config.network.vnic"].decode(&vnics)
	vmk := modules.Table{Title: "VMkernel NICs", Columns: []string{"NIC", "MAC", "IP", "Port group"}}
	for _, n := range vnics.Items {
		ip := n.Spec.IP.Address
		if n.Spec.IP.DHCP {
			ip += " (DHCP)"
		}
		vmk.Rows = append(vmk.Rows, []string{n.Device, n.Spec.Mac, ip, n.Portgroup})
	}
	r.Tables = append(r.Tables, vmk)

	// SNMP: the agent, its firewall rule and the snmpd service
	snmp := snmpState(ctx, c, decodeString(p, "configManager.snmpSystem"),
		decodeString(p, "configManager.firewallSystem"), decodeString(p, "configManager.serviceSystem"))
	r.AddFact("SNMP agent", snmp.agent)
	r.AddFact("SNMP firewall rule", snmp.firewall)
	r.AddFact("snmpd service", snmp.service)

	// Virtual machines
	vms, on := vmTable(ctx, c)
	r.Tables = append(r.Tables, vms)
	r.Summary = fmt.Sprintf("%s: %s, %d physical NICs, %d VMs (%d on)", name, product.FullName, len(pnics.Items), len(vms.Rows), on)
	return r, nil
}

// licenseName is the name of the host's license ("" when it is not read).
func licenseName(ctx context.Context, c *vimClient) string {
	if c.content.LicenseManager == "" {
		return ""
	}
	p, err := c.retrieveOne(ctx, moRef{Type: "LicenseManager", Value: c.content.LicenseManager}, "licenses")
	if err != nil {
		return ""
	}
	var lic struct {
		Items []struct {
			Name       string `xml:"name"`
			EditionKey string `xml:"editionKey"`
		} `xml:"LicenseManagerLicenseInfo"`
	}
	p["licenses"].decode(&lic)
	var names []string
	for _, l := range lic.Items {
		if l.Name != "" {
			names = append(names, l.Name)
		}
	}
	return strings.Join(names, ", ")
}

// nicHints asks the host what CDP or LLDP tells of the switch port of each
// physical NIC: device → [switch, port]. A host that does not listen to
// the switch's protocol tells nothing.
func nicHints(ctx context.Context, c *vimClient, networkSystem string, nics []physicalNic) map[string][2]string {
	out := map[string][2]string{}
	if networkSystem == "" || len(nics) == 0 {
		return out
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<QueryNetworkHint xmlns="urn:vim25"><_this type="HostNetworkSystem">%s</_this>`, text(networkSystem))
	for _, n := range nics {
		fmt.Fprintf(&b, `<device>%s</device>`, text(n.Device))
	}
	b.WriteString(`</QueryNetworkHint>`)
	var resp struct {
		Returnval []nicHint `xml:"returnval"`
	}
	if c.call(ctx, b.String(), &resp) != nil {
		return out
	}
	for _, h := range resp.Returnval {
		switch {
		case h.CDP != nil && (h.CDP.DevID != "" || h.CDP.PortID != ""):
			sw := h.CDP.DevID
			if h.CDP.Address != "" {
				sw += " (" + h.CDP.Address + ")"
			}
			out[h.Device] = [2]string{"CDP: " + sw, h.CDP.PortID}
		case h.LLDP != nil && (h.LLDP.ChassisID != "" || h.LLDP.PortID != ""):
			sw := h.LLDP.ChassisID
			for _, prm := range h.LLDP.Parameter {
				if prm.Key == "System Name" && strings.TrimSpace(prm.Value) != "" {
					sw = strings.TrimSpace(prm.Value) + " (" + h.LLDP.ChassisID + ")"
				}
			}
			out[h.Device] = [2]string{"LLDP: " + sw, h.LLDP.PortID}
		}
	}
	return out
}

func linkSpeed(mb int) string {
	if mb >= 1000 && mb%1000 == 0 {
		return strconv.Itoa(mb/1000) + "G"
	}
	return strconv.Itoa(mb) + "M"
}

// snmpView is the SNMP state of a host as text.
type snmpView struct {
	agent, firewall, service string
	config                   *snmpConfig
	firewallOpen, running    bool
	policy                   string // when snmpd starts: "on" with the host, "off", "automatic"
}

func snmpState(ctx context.Context, c *vimClient, snmpSystem, firewallSystem, serviceSystem string) snmpView {
	v := snmpView{agent: "?", firewall: "?", service: "?"}
	if snmpSystem != "" {
		if p, err := c.retrieveOne(ctx, moRef{Type: "HostSnmpSystem", Value: snmpSystem}, "configuration"); err == nil {
			var cfg snmpConfig
			p["configuration"].decode(&cfg)
			v.config = &cfg
			v.agent = "disabled"
			if cfg.Enabled {
				v.agent = "enabled, communities: " + strings.Join(cfg.Communities, ", ")
				if len(cfg.Communities) == 0 {
					v.agent = "enabled, no community"
				}
			}
		}
	}
	if firewallSystem != "" {
		if p, err := c.retrieveOne(ctx, moRef{Type: "HostFirewallSystem", Value: firewallSystem}, "firewallInfo"); err == nil {
			var fw struct {
				Ruleset []firewallRuleset `xml:"ruleset"`
			}
			p["firewallInfo"].decode(&fw)
			for _, rs := range fw.Ruleset {
				if rs.Key == "snmp" {
					v.firewallOpen = rs.Enabled
					v.firewall = map[bool]string{true: "open", false: "closed"}[rs.Enabled]
				}
			}
		}
	}
	if serviceSystem != "" {
		if p, err := c.retrieveOne(ctx, moRef{Type: "HostServiceSystem", Value: serviceSystem}, "serviceInfo"); err == nil {
			var si struct {
				Service []struct {
					Key     string `xml:"key"`
					Running bool   `xml:"running"`
					Policy  string `xml:"policy"`
				} `xml:"service"`
			}
			p["serviceInfo"].decode(&si)
			for _, s := range si.Service {
				if s.Key == "snmpd" {
					v.running, v.policy = s.Running, s.Policy
					v.service = map[bool]string{true: "running", false: "stopped"}[s.Running] + ", starts: " + s.Policy
				}
			}
		}
	}
	return v
}

// vmTable lists the host's virtual machines, and how many are on.
func vmTable(ctx context.Context, c *vimClient) (modules.Table, int) {
	t := modules.Table{Title: "Virtual machines", Columns: []string{"Name", "Power", "Guest OS", "Guest name", "IP", "MAC"}}
	objs, err := c.retrieve(ctx, hostRef, "VirtualMachine", "vm", vmPaths)
	if err != nil {
		t.Title += " (not read: " + err.Error() + ")"
		return t, 0
	}
	on := 0
	for _, o := range objs {
		p := o.props()
		power := strings.TrimPrefix(decodeString(p, "runtime.powerState"), "powered")
		if power == "On" {
			on++
		}
		var nics struct {
			Items []guestNic `xml:"GuestNicInfo"`
		}
		p["guest.net"].decode(&nics)
		var devices struct {
			Items []virtualDevice `xml:"VirtualDevice"`
		}
		p["config.hardware.device"].decode(&devices)
		var ips, macs []string
		for _, n := range nics.Items {
			for _, ip := range n.IPAddress {
				if !strings.Contains(ip, ":") { // IPv4 only: the link-local IPv6 says nothing
					ips = append(ips, ip)
				}
			}
		}
		for _, d := range devices.Items {
			if d.MacAddress != "" {
				macs = append(macs, d.MacAddress)
			}
		}
		t.Rows = append(t.Rows, []string{decodeString(p, "name"), power, decodeString(p, "summary.config.guestFullName"),
			decodeString(p, "guest.hostName"), strings.Join(ips, ", "), strings.Join(macs, ", ")})
	}
	slices.SortFunc(t.Rows, func(a, b []string) int { return strings.Compare(strings.ToLower(a[0]), strings.ToLower(b[0])) })
	return t, on
}

// ─── Enable SNMP ──────────────────────────────────────────────────────────────

// enableSNMP turns the host's SNMP agent on with the community (kept with
// the communities and trap targets it has), opens the 'snmp' firewall
// rule and starts snmpd, on with the host. The result lists what changed,
// also when a later step fails.
func enableSNMP(ctx context.Context, c *vimClient, community string) (modules.Result, error) {
	var r modules.Result
	if community == "" {
		community = "public"
	}
	p, err := c.retrieveOne(ctx, hostRef, "configManager.snmpSystem", "configManager.firewallSystem", "configManager.serviceSystem")
	if err != nil {
		return r, fmt.Errorf("host properties: %w", err)
	}
	snmpSystem, firewallSystem, serviceSystem := decodeString(p, "configManager.snmpSystem"),
		decodeString(p, "configManager.firewallSystem"), decodeString(p, "configManager.serviceSystem")
	if snmpSystem == "" {
		return r, fmt.Errorf("the host has no SNMP system in its API")
	}
	state := snmpState(ctx, c, snmpSystem, firewallSystem, serviceSystem)
	if state.config == nil {
		return r, fmt.Errorf("the host's SNMP configuration could not be read")
	}
	cfg := *state.config

	// The agent, with the community added to those it has
	communities := cfg.Communities
	if !slices.Contains(communities, community) {
		communities = append(slices.Clone(communities), community)
	}
	port := cfg.Port
	if port == 0 {
		port = 161
	}
	changed := !cfg.Enabled || len(communities) != len(cfg.Communities)
	if changed {
		var b strings.Builder
		fmt.Fprintf(&b, `<ReconfigureSnmpAgent xmlns="urn:vim25"><_this type="HostSnmpSystem">%s</_this><spec><enabled>true</enabled><port>%d</port>`, text(snmpSystem), port)
		for _, cm := range communities {
			fmt.Fprintf(&b, `<readOnlyCommunities>%s</readOnlyCommunities>`, text(cm))
		}
		for _, t := range cfg.TrapTargets {
			fmt.Fprintf(&b, `<trapTargets>%s</trapTargets>`, t.Inner)
		}
		for _, o := range cfg.Options {
			fmt.Fprintf(&b, `<option>%s</option>`, o.Inner)
		}
		b.WriteString(`</spec></ReconfigureSnmpAgent>`)
		if err := c.call(ctx, b.String(), nil); err != nil {
			if faultKind(err) == "RestrictedVersion" {
				return r, fmt.Errorf("the host's license (%s) does not let the API change its settings (the free vSphere Hypervisor license is read-only): "+
					"on the host run: esxcli system snmp set --communities %s --enable true", licenseName(ctx, c), community)
			}
			return r, fmt.Errorf("the SNMP agent was not changed: %w", err)
		}
		r.Changes = append(r.Changes, fmt.Sprintf("SNMP agent enabled on port %d, communities: %s", port, strings.Join(communities, ", ")))
	} else {
		r.Changes = append(r.Changes, "SNMP agent already enabled with community "+community)
	}

	if firewallSystem != "" && !state.firewallOpen {
		if err := c.call(ctx, fmt.Sprintf(`<EnableRuleset xmlns="urn:vim25"><_this type="HostFirewallSystem">%s</_this><id>snmp</id></EnableRuleset>`, text(firewallSystem)), nil); err != nil {
			return r, fmt.Errorf("the 'snmp' firewall rule was not opened: %w", err)
		}
		r.Changes = append(r.Changes, "firewall rule 'snmp' opened")
	}

	// snmpd: on with the host, started, or restarted for a new configuration
	if serviceSystem != "" {
		if state.policy != "on" {
			if err := c.call(ctx, fmt.Sprintf(`<UpdateServicePolicy xmlns="urn:vim25"><_this type="HostServiceSystem">%s</_this><id>snmpd</id><policy>on</policy></UpdateServicePolicy>`, text(serviceSystem)), nil); err != nil {
				return r, fmt.Errorf("snmpd was not set to start with the host: %w", err)
			}
			r.Changes = append(r.Changes, "snmpd set to start with the host")
		}
		verb, done := "", ""
		switch {
		case !state.running:
			verb, done = "StartService", "snmpd started"
		case changed:
			verb, done = "RestartService", "snmpd restarted for the new configuration"
		}
		if verb != "" {
			if err := c.call(ctx, fmt.Sprintf(`<%s xmlns="urn:vim25"><_this type="HostServiceSystem">%s</_this><id>snmpd</id></%s>`, verb, text(serviceSystem), verb), nil); err != nil {
				return r, fmt.Errorf("%s snmpd: %w", verb, err)
			}
			r.Changes = append(r.Changes, done)
		}
	}
	r.Summary = "SNMP is on, community " + community
	return r, nil
}
