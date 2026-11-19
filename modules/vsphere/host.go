package vsphere

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"lldp_scanner/modules/kit"
)

// ─── What an ESXi host tells ──────────────────────────────────────────────────
//
// The same on the host's own API (its HostSystem "ha-host") and through a
// vCenter (each host's HostSystem).

// HostPaths are the host properties ParseHost reads.
var HostPaths = []string{
	"name", "summary.hardware", "summary.config.product", "hardware.systemInfo.serialNumber",
	"config.network.dnsConfig", "config.network.pnic", "config.network.vnic", "config.network.vswitch",
	"configManager.networkSystem", "configManager.snmpSystem", "configManager.firewallSystem",
	"configManager.serviceSystem",
}

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

// PhysicalNic is one physical NIC of a host.
type PhysicalNic struct {
	Key       string `xml:"key"`
	Device    string `xml:"device"`
	Driver    string `xml:"driver"`
	Mac       string `xml:"mac"`
	LinkSpeed *struct {
		SpeedMb int  `xml:"speedMb"`
		Duplex  bool `xml:"duplex"`
	} `xml:"linkSpeed"`
}

// Speed is the NIC's link speed ("1G"), "down" with no link.
func (n PhysicalNic) Speed() string {
	if n.LinkSpeed == nil {
		return "down"
	}
	return LinkSpeed(n.LinkSpeed.SpeedMb)
}

// VirtualNic is one VMkernel NIC of a host.
type VirtualNic struct {
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

// Host is what ParseHost reads of a host.
type Host struct {
	Name     string // its DNS name, "esx01.lab.local", else its name in the API
	Product  string // "VMware ESXi 8.0.3 build-24022510"
	Server   string // "HPE ProLiant DL380 Gen10"
	Serial   string
	CPU      string // "Intel(R) Xeon(R) Gold 6130 CPU @ 2.10GHz (2 × 16 cores, 64 threads)"
	Memory   string // "256 GiB"
	PNICs    []PhysicalNic
	VNICs    []VirtualNic
	VSwitch  map[string]string // the vSwitch of each physical NIC, by its key
	Managers struct {
		Network, SNMP, Firewall, Service string // the host's managed objects
	}
}

// ParseHost reads the properties HostPaths of a host.
func ParseHost(p map[string]RawValue) Host {
	var h Host
	var dns struct {
		HostName   string `xml:"hostName"`
		DomainName string `xml:"domainName"`
	}
	p["config.network.dnsConfig"].Decode(&dns)
	h.Name = dns.HostName
	if h.Name != "" && dns.DomainName != "" {
		h.Name += "." + dns.DomainName
	}
	if h.Name == "" {
		h.Name = DecodeString(p, "name")
	}
	var product struct {
		FullName string `xml:"fullName"`
	}
	p["summary.config.product"].Decode(&product)
	h.Product = product.FullName

	var hw hardwareSummary
	p["summary.hardware"].Decode(&hw)
	h.Server = strings.TrimSpace(hw.Vendor + " " + hw.Model)
	h.Serial = DecodeString(p, "hardware.systemInfo.serialNumber")
	for _, id := range hw.OtherIdentifyingInfo {
		if h.Serial == "" && (id.Type.Key == "SerialNumberTag" || id.Type.Key == "ServiceTag" || id.Type.Key == "EnclosureSerialNumberTag") {
			h.Serial = strings.TrimSpace(id.Value)
		}
	}
	if hw.CPUModel != "" {
		h.CPU = fmt.Sprintf("%s (%d × %d cores, %d threads)", strings.Join(strings.Fields(hw.CPUModel), " "),
			hw.NumCPUPkgs, max(hw.NumCPUCores/max(hw.NumCPUPkgs, 1), 1), hw.NumCPUThreads)
	}
	if hw.MemorySize > 0 {
		h.Memory = fmt.Sprintf("%.0f GiB", float64(hw.MemorySize)/(1<<30))
	}

	var pnics struct {
		Items []PhysicalNic `xml:"PhysicalNic"`
	}
	p["config.network.pnic"].Decode(&pnics)
	h.PNICs = pnics.Items
	var vnics struct {
		Items []VirtualNic `xml:"HostVirtualNic"`
	}
	p["config.network.vnic"].Decode(&vnics)
	h.VNICs = vnics.Items
	var vswitches struct {
		Items []virtualSwitch `xml:"HostVirtualSwitch"`
	}
	p["config.network.vswitch"].Decode(&vswitches)
	h.VSwitch = map[string]string{}
	for _, vs := range vswitches.Items {
		for _, key := range vs.Pnic {
			h.VSwitch[key] = vs.Name
		}
	}
	h.Managers.Network = DecodeString(p, "configManager.networkSystem")
	h.Managers.SNMP = DecodeString(p, "configManager.snmpSystem")
	h.Managers.Firewall = DecodeString(p, "configManager.firewallSystem")
	h.Managers.Service = DecodeString(p, "configManager.serviceSystem")
	return h
}

// ManagementIP is the IP of the host's first VMkernel NIC with one, "".
func (h Host) ManagementIP() string {
	for _, n := range h.VNICs {
		if n.Spec.IP.Address != "" {
			return n.Spec.IP.Address
		}
	}
	return ""
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

// DecodeString reads a string value; "" when it is missing.
func DecodeString(p map[string]RawValue, path string) string {
	var s string
	if v, ok := p[path]; ok {
		v.Decode(&s)
	}
	return strings.TrimSpace(s)
}

// LicenseName is the name of the licenses of the API's license manager
// ("" when they are not read).
func LicenseName(ctx context.Context, c *Client) string {
	if c.Content.LicenseManager == "" {
		return ""
	}
	p, err := c.RetrieveOne(ctx, MoRef{Type: "LicenseManager", Value: c.Content.LicenseManager}, "licenses")
	if err != nil {
		return ""
	}
	var lic struct {
		Items []struct {
			Name       string `xml:"name"`
			EditionKey string `xml:"editionKey"`
		} `xml:"LicenseManagerLicenseInfo"`
	}
	p["licenses"].Decode(&lic)
	var names []string
	for _, l := range lic.Items {
		if l.Name != "" && !slices.Contains(names, l.Name) {
			names = append(names, l.Name)
		}
	}
	return strings.Join(names, ", ")
}

// NicHints asks a host (its network system) what CDP or LLDP tells of the
// switch port of each physical NIC: device → [switch, port]. A host that
// does not listen to the switch's protocol tells nothing.
func NicHints(ctx context.Context, c *Client, networkSystem string, nics []PhysicalNic) map[string][2]string {
	out := map[string][2]string{}
	if networkSystem == "" || len(nics) == 0 {
		return out
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<QueryNetworkHint xmlns="urn:vim25"><_this type="HostNetworkSystem">%s</_this>`, Text(networkSystem))
	for _, n := range nics {
		fmt.Fprintf(&b, `<device>%s</device>`, Text(n.Device))
	}
	b.WriteString(`</QueryNetworkHint>`)
	var resp struct {
		Returnval []nicHint `xml:"returnval"`
	}
	if c.Call(ctx, b.String(), &resp) != nil {
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

// LinkSpeed is a speed in Mbit/s as "100M", "1G", "10G".
func LinkSpeed(mb int) string {
	if mb >= 1000 && mb%1000 == 0 {
		return strconv.Itoa(mb/1000) + "G"
	}
	return strconv.Itoa(mb) + "M"
}

// ─── SNMP ─────────────────────────────────────────────────────────────────────

type snmpConfig struct {
	Enabled     bool       `xml:"enabled"`
	Port        int        `xml:"port"`
	Communities []string   `xml:"readOnlyCommunities"`
	TrapTargets []RawValue `xml:"trapTargets"`
	Options     []RawValue `xml:"option"`
}

type firewallRuleset struct {
	Key     string `xml:"key"`
	Enabled bool   `xml:"enabled"`
}

// SNMPView is the SNMP state of a host: as text, and what EnableSNMP
// needs of it.
type SNMPView struct {
	Agent, Firewall, Service string
	config                   *snmpConfig
	firewallOpen, running    bool
	policy                   string // when snmpd starts: "on" with the host, "off", "automatic"
}

// Short is the state in a few words: "on, public" when all is on, else
// the parts that are not.
func (v SNMPView) Short() string {
	if v.config != nil && v.config.Enabled && v.firewallOpen && v.running {
		return "on, " + strings.Join(v.config.Communities, ", ")
	}
	return fmt.Sprintf("agent %s; firewall %s; snmpd %s", v.Agent, v.Firewall, v.Service)
}

// SNMPState reads the SNMP state of a host from its managers.
func SNMPState(ctx context.Context, c *Client, snmpSystem, firewallSystem, serviceSystem string) SNMPView {
	v := SNMPView{Agent: "?", Firewall: "?", Service: "?"}
	if snmpSystem != "" {
		if p, err := c.RetrieveOne(ctx, MoRef{Type: "HostSnmpSystem", Value: snmpSystem}, "configuration"); err == nil {
			var cfg snmpConfig
			p["configuration"].Decode(&cfg)
			v.config = &cfg
			v.Agent = "disabled"
			if cfg.Enabled {
				v.Agent = "enabled, communities: " + strings.Join(cfg.Communities, ", ")
				if len(cfg.Communities) == 0 {
					v.Agent = "enabled, no community"
				}
			}
		}
	}
	if firewallSystem != "" {
		if p, err := c.RetrieveOne(ctx, MoRef{Type: "HostFirewallSystem", Value: firewallSystem}, "firewallInfo"); err == nil {
			var fw struct {
				Ruleset []firewallRuleset `xml:"ruleset"`
			}
			p["firewallInfo"].Decode(&fw)
			for _, rs := range fw.Ruleset {
				if rs.Key == "snmp" {
					v.firewallOpen = rs.Enabled
					v.Firewall = map[bool]string{true: "open", false: "closed"}[rs.Enabled]
				}
			}
		}
	}
	if serviceSystem != "" {
		if p, err := c.RetrieveOne(ctx, MoRef{Type: "HostServiceSystem", Value: serviceSystem}, "serviceInfo"); err == nil {
			var si struct {
				Service []struct {
					Key     string `xml:"key"`
					Running bool   `xml:"running"`
					Policy  string `xml:"policy"`
				} `xml:"service"`
			}
			p["serviceInfo"].Decode(&si)
			for _, s := range si.Service {
				if s.Key == "snmpd" {
					v.running, v.policy = s.Running, s.Policy
					v.Service = map[bool]string{true: "running", false: "stopped"}[s.Running] + ", starts: " + s.Policy
				}
			}
		}
	}
	return v
}

// EnableSNMP turns the SNMP agent of a host on with the community (kept
// with the communities and trap targets it has), opens the 'snmp'
// firewall rule and starts snmpd, on with the host. It returns what
// changed, also when a later step fails.
func EnableSNMP(ctx context.Context, c *Client, host MoRef, community string) ([]string, error) {
	var changes []string
	if community == "" {
		community = "public"
	}
	p, err := c.RetrieveOne(ctx, host, "configManager.snmpSystem", "configManager.firewallSystem", "configManager.serviceSystem")
	if err != nil {
		return changes, fmt.Errorf("host properties: %w", err)
	}
	snmpSystem, firewallSystem, serviceSystem := DecodeString(p, "configManager.snmpSystem"),
		DecodeString(p, "configManager.firewallSystem"), DecodeString(p, "configManager.serviceSystem")
	if snmpSystem == "" {
		return changes, fmt.Errorf("the host has no SNMP system in its API")
	}
	state := SNMPState(ctx, c, snmpSystem, firewallSystem, serviceSystem)
	if state.config == nil {
		return changes, fmt.Errorf("the host's SNMP configuration could not be read")
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
		fmt.Fprintf(&b, `<ReconfigureSnmpAgent xmlns="urn:vim25"><_this type="HostSnmpSystem">%s</_this><spec><enabled>true</enabled><port>%d</port>`, Text(snmpSystem), port)
		for _, cm := range communities {
			fmt.Fprintf(&b, `<readOnlyCommunities>%s</readOnlyCommunities>`, Text(cm))
		}
		for _, t := range cfg.TrapTargets {
			fmt.Fprintf(&b, `<trapTargets>%s</trapTargets>`, t.Inner)
		}
		for _, o := range cfg.Options {
			fmt.Fprintf(&b, `<option>%s</option>`, o.Inner)
		}
		b.WriteString(`</spec></ReconfigureSnmpAgent>`)
		if err := c.Call(ctx, b.String(), nil); err != nil {
			if FaultKind(err) == "RestrictedVersion" {
				return changes, fmt.Errorf("the host's license (%s) does not let the API change its settings (the free vSphere Hypervisor license is read-only): "+
					"on the host run: esxcli system snmp set --communities %s --enable true", LicenseName(ctx, c), community)
			}
			return changes, fmt.Errorf("the SNMP agent was not changed: %w", err)
		}
		changes = append(changes, fmt.Sprintf("SNMP agent enabled on port %d, communities: %s", port, strings.Join(communities, ", ")))
	} else {
		changes = append(changes, "SNMP agent already enabled with community "+community)
	}

	if firewallSystem != "" && !state.firewallOpen {
		if err := c.Call(ctx, fmt.Sprintf(`<EnableRuleset xmlns="urn:vim25"><_this type="HostFirewallSystem">%s</_this><id>snmp</id></EnableRuleset>`, Text(firewallSystem)), nil); err != nil {
			return changes, fmt.Errorf("the 'snmp' firewall rule was not opened: %w", err)
		}
		changes = append(changes, "firewall rule 'snmp' opened")
	}

	// snmpd: on with the host, started, or restarted for a new configuration
	if serviceSystem != "" {
		if state.policy != "on" {
			if err := c.Call(ctx, fmt.Sprintf(`<UpdateServicePolicy xmlns="urn:vim25"><_this type="HostServiceSystem">%s</_this><id>snmpd</id><policy>on</policy></UpdateServicePolicy>`, Text(serviceSystem)), nil); err != nil {
				return changes, fmt.Errorf("snmpd was not set to start with the host: %w", err)
			}
			changes = append(changes, "snmpd set to start with the host")
		}
		verb, done := "", ""
		switch {
		case !state.running:
			verb, done = "StartService", "snmpd started"
		case changed:
			verb, done = "RestartService", "snmpd restarted for the new configuration"
		}
		if verb != "" {
			if err := c.Call(ctx, fmt.Sprintf(`<%s xmlns="urn:vim25"><_this type="HostServiceSystem">%s</_this><id>snmpd</id></%s>`, verb, Text(serviceSystem), verb), nil); err != nil {
				return changes, fmt.Errorf("%s snmpd: %w", verb, err)
			}
			changes = append(changes, done)
		}
	}
	return changes, nil
}

// ─── Virtual machines ─────────────────────────────────────────────────────────

// VMPaths are the virtual machine properties ParseVM reads.
var VMPaths = []string{
	"name", "runtime.powerState", "summary.config.guestFullName", "guest.hostName", "guest.net", "config.hardware.device",
}

type guestNic struct {
	Network    string   `xml:"network"`
	IPAddress  []string `xml:"ipAddress"`
	MacAddress string   `xml:"macAddress"`
}

type virtualDevice struct {
	MacAddress string `xml:"macAddress"`
	Backing    struct {
		DeviceName string `xml:"deviceName"` // a standard port group's name
	} `xml:"backing"`
}

// VMNic is one virtual NIC of a virtual machine.
type VMNic struct {
	MAC     string
	Network string   // its port group, "VM Network"
	IPs     []string // IPv4, as its guest tools tell
}

// VM is what ParseVM reads of a virtual machine.
type VM struct {
	Name      string
	Power     string // "On", "Off", "Suspended"
	GuestOS   string // "Ubuntu Linux (64-bit)"
	GuestName string // the guest's host name, as its tools tell
	NICs      []VMNic
}

// IPs are the IPv4 addresses of all its NICs.
func (v VM) IPs() []string {
	var ips []string
	for _, n := range v.NICs {
		ips = append(ips, n.IPs...)
	}
	return ips
}

// MACs are the MACs of its NICs.
func (v VM) MACs() []string {
	var macs []string
	for _, n := range v.NICs {
		macs = append(macs, n.MAC)
	}
	return macs
}

// ParseVM reads the properties VMPaths of a virtual machine: a NIC per
// virtual device with a MAC, with the guest's IPv4 addresses on it (the
// link-local IPv6 says nothing).
func ParseVM(p map[string]RawValue) VM {
	v := VM{Name: DecodeString(p, "name"), Power: strings.TrimPrefix(DecodeString(p, "runtime.powerState"), "powered"),
		GuestOS: DecodeString(p, "summary.config.guestFullName"), GuestName: DecodeString(p, "guest.hostName")}
	var guest struct {
		Items []guestNic `xml:"GuestNicInfo"`
	}
	p["guest.net"].Decode(&guest)
	var devices struct {
		Items []virtualDevice `xml:"VirtualDevice"`
	}
	p["config.hardware.device"].Decode(&devices)
	for _, d := range devices.Items {
		if d.MacAddress == "" {
			continue
		}
		n := VMNic{MAC: strings.ToLower(d.MacAddress), Network: strings.TrimSpace(d.Backing.DeviceName)}
		for _, g := range guest.Items {
			if !strings.EqualFold(g.MacAddress, d.MacAddress) {
				continue
			}
			n.Network = kit.FirstOf(n.Network, g.Network)
			for _, ip := range g.IPAddress {
				if !strings.Contains(ip, ":") {
					n.IPs = append(n.IPs, ip)
				}
			}
		}
		v.NICs = append(v.NICs, n)
	}
	return v
}
