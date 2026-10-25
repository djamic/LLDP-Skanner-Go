// Package vcenter is the device module of VMware vCenter Server: over its
// vSphere API (a login of protocol "vsphere", a vCenter user such as
// administrator@vsphere.local; modules/vsphere) it detects the vCenter
// (version, clusters, every ESXi host it manages with its NICs and SNMP
// state, every virtual machine), enables the SNMP agent of all its hosts
// with the scanner's community, and gives the scanner its inventory: the
// hosts by MAC, with their virtual machines, so the graph and the tree
// name them as vCenter does. It recognizes a vCenter with no login
// (Probe) by the API's service content.
package vcenter

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"lldp_scanner/modules"
	"lldp_scanner/modules/vsphere"
)

func init() { modules.Register(Module{}) }

// Module is the vCenter Server device module.
type Module struct{}

func (Module) ID() string       { return "vcenter" }
func (Module) Label() string    { return "VMware vCenter" }
func (Module) Type() string     { return "vcenter" }
func (Module) Protocol() string { return "vsphere" }

func (Module) Actions() []modules.Action {
	return []modules.Action{
		{ID: "detect", Label: "🔎 Detect"},
		{ID: "enable-snmp-all", Label: "📡 Enable SNMP on all hosts", Changes: true,
			Confirm: "Enable the SNMP agent of every connected ESXi host of this vCenter with the scanner's community, open their 'snmp' firewall rule and start snmpd (on with each host)?"},
	}
}

// probeTimeout bounds Probe.
const probeTimeout = 3 * time.Second

// connect finds the vCenter's API at ip: an API of another kind (an ESXi
// host) is an error.
func connect(ctx context.Context, ip string) (*vsphere.Client, error) {
	c := vsphere.NewClient(ip)
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	if t := c.Content.About.APIType; t != "VirtualCenter" {
		return nil, fmt.Errorf("%s is a %s (%s), not a vCenter Server", c.URL(), cmp.Or(t, "device of no API type"), c.Content.About.FullName)
	}
	return c, nil
}

// Run logs in to the vCenter, runs the action and logs out.
func (Module) Run(ctx context.Context, req modules.Request) (modules.Result, error) {
	c, err := connect(ctx, req.IP)
	if err != nil {
		return modules.Result{}, err
	}
	if err := c.Login(ctx, req.Login); err != nil {
		return modules.Result{}, err
	}
	defer c.Logout(context.WithoutCancel(ctx))
	switch req.Action {
	case "detect":
		return detect(ctx, c)
	case "enable-snmp-all":
		return enableSNMPAll(ctx, c, cmp.Or(req.Community, "public"))
	}
	return modules.Result{}, fmt.Errorf("unknown action %q", req.Action)
}

// Probe tells, with no login, whether a vCenter Server answers at ip: its
// API's service content says so.
func (Module) Probe(ctx context.Context, ip string) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	c := vsphere.NewClient(ip)
	return c.Connect(ctx) == nil && c.Content.About.APIType == "VirtualCenter"
}

// ─── What the vCenter tells ───────────────────────────────────────────────────

// host is one ESXi host of the vCenter.
type host struct {
	ref string // its HostSystem ("host-12")
	vsphere.Host
	state   string // "ONLINE", "MAINTENANCE", "DISCONNECTED", "NOT_RESPONDING", "STANDBY", ...
	cluster string
	vms     []vsphere.VM
	vmsOn   int
}

// connected tells whether the vCenter talks to the host.
func (h host) connected() bool { return h.state == "ONLINE" || h.state == "MAINTENANCE" }

var hostStates = map[string]string{"disconnected": "DISCONNECTED", "notResponding": "NOT_RESPONDING"}

// hostState is a host's state from its connection, power and maintenance.
func hostState(connection, power string, maintenance bool) string {
	switch {
	case connection != "" && connection != "connected":
		return cmp.Or(hostStates[connection], strings.ToUpper(connection))
	case maintenance:
		return "MAINTENANCE"
	case power != "" && power != "poweredOn":
		return strings.ToUpper(strings.TrimPrefix(power, "powered"))
	}
	return "ONLINE"
}

// readAll reads every host of the vCenter, with its cluster and its
// virtual machines (templates left out), hosts and VMs sorted by name.
func readAll(ctx context.Context, c *vsphere.Client) ([]host, error) {
	hostView, err := c.ContainerView(ctx, "HostSystem")
	if err != nil {
		return nil, fmt.Errorf("hosts: %w", err)
	}
	defer c.DestroyView(context.WithoutCancel(ctx), hostView)
	objs, err := c.Retrieve(ctx, hostView, "HostSystem", "view",
		append(slices.Clone(vsphere.HostPaths), "runtime.connectionState", "runtime.powerState", "runtime.inMaintenanceMode", "parent"))
	if err != nil {
		return nil, fmt.Errorf("hosts: %w", err)
	}

	// The clusters, by their ComputeResource (a standalone host's own
	// ComputeResource is no cluster)
	clusters := map[string]string{}
	if view, err := c.ContainerView(ctx, "ComputeResource"); err == nil {
		if crs, err := c.Retrieve(ctx, view, "ComputeResource", "view", []string{"name"}); err == nil {
			for _, cr := range crs {
				if cr.Obj.Type == "ClusterComputeResource" {
					clusters[cr.Obj.Value] = vsphere.DecodeString(cr.Props(), "name")
				}
			}
		}
		c.DestroyView(context.WithoutCancel(ctx), view)
	}

	var hosts []host
	byRef := map[string]int{}
	for _, o := range objs {
		p := o.Props()
		h := host{ref: o.Obj.Value, Host: vsphere.ParseHost(p), cluster: clusters[vsphere.DecodeString(p, "parent")]}
		maintenance := vsphere.DecodeString(p, "runtime.inMaintenanceMode") == "true"
		h.state = hostState(vsphere.DecodeString(p, "runtime.connectionState"), vsphere.DecodeString(p, "runtime.powerState"), maintenance)
		byRef[h.ref] = len(hosts)
		hosts = append(hosts, h)
	}

	vmView, err := c.ContainerView(ctx, "VirtualMachine")
	if err != nil {
		return nil, fmt.Errorf("virtual machines: %w", err)
	}
	defer c.DestroyView(context.WithoutCancel(ctx), vmView)
	vms, err := c.Retrieve(ctx, vmView, "VirtualMachine", "view", append(slices.Clone(vsphere.VMPaths), "runtime.host", "config.template"))
	if err != nil {
		return nil, fmt.Errorf("virtual machines: %w", err)
	}
	for _, o := range vms {
		p := o.Props()
		if vsphere.DecodeString(p, "config.template") == "true" {
			continue
		}
		i, ok := byRef[vsphere.DecodeString(p, "runtime.host")]
		if !ok {
			continue
		}
		vm := vsphere.ParseVM(p)
		hosts[i].vms = append(hosts[i].vms, vm)
		if vm.Power == "On" {
			hosts[i].vmsOn++
		}
	}
	for i := range hosts {
		slices.SortFunc(hosts[i].vms, func(a, b vsphere.VM) int { return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	}
	slices.SortFunc(hosts, func(a, b host) int { return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return hosts, nil
}

// ─── Detect ───────────────────────────────────────────────────────────────────

func detect(ctx context.Context, c *vsphere.Client) (modules.Result, error) {
	var r modules.Result
	hosts, err := readAll(ctx, c)
	if err != nil {
		return r, err
	}
	about := c.Content.About
	r.AddFact("Product", about.FullName)
	r.AddFact("API version", about.APIVersion)
	r.AddFact("License", vsphere.LicenseName(ctx, c))

	hostTable := modules.Table{Title: "ESXi hosts", Columns: []string{"Name", "Cluster", "Server", "Version", "State", "Management IP", "VMs (on)", "SNMP"}}
	nics := modules.Table{Title: "Physical NICs", Columns: []string{"Host", "NIC", "MAC", "Speed", "vSwitch", "Switch", "Switch port"}}
	vmTable := modules.Table{Title: "Virtual machines", Columns: []string{"Name", "Host", "Power", "Guest OS", "Guest name", "IP", "MAC"}}
	var clusters []string
	connected, maintenance, vmCount, vmsOn := 0, 0, 0, 0
	for _, h := range hosts {
		if h.cluster != "" && !slices.Contains(clusters, h.cluster) {
			clusters = append(clusters, h.cluster)
		}
		snmp := ""
		if h.connected() {
			connected++
			snmp = vsphere.SNMPState(ctx, c, h.Managers.SNMP, h.Managers.Firewall, h.Managers.Service).Short()
			hints := vsphere.NicHints(ctx, c, h.Managers.Network, h.PNICs)
			for _, n := range h.PNICs {
				hint := hints[n.Device]
				nics.Rows = append(nics.Rows, []string{h.Name, n.Device, n.Mac, n.Speed(), h.VSwitch[n.Key], hint[0], hint[1]})
			}
		}
		if h.state == "MAINTENANCE" {
			maintenance++
		}
		hostTable.Rows = append(hostTable.Rows, []string{h.Name, h.cluster, h.Server, h.Product, h.state, h.ManagementIP(),
			fmt.Sprintf("%d (%d)", len(h.vms), h.vmsOn), snmp})
		for _, vm := range h.vms {
			vmTable.Rows = append(vmTable.Rows, []string{vm.Name, h.Name, vm.Power, vm.GuestOS, vm.GuestName, strings.Join(vm.IPs(), ", "), strings.Join(vm.MACs(), ", ")})
		}
		vmCount += len(h.vms)
		vmsOn += h.vmsOn
	}
	slices.SortFunc(vmTable.Rows, func(a, b []string) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a[0]), strings.ToLower(b[0])), cmp.Compare(a[1], b[1]))
	})
	slices.Sort(clusters)
	r.AddFact("Clusters", strings.Join(clusters, ", "))
	hostFact := fmt.Sprintf("%d (%d connected", len(hosts), connected)
	if maintenance > 0 {
		hostFact += fmt.Sprintf(", %d in maintenance", maintenance)
	}
	r.AddFact("ESXi hosts", hostFact+")")
	r.AddFact("Virtual machines", fmt.Sprintf("%d (%d on)", vmCount, vmsOn))
	r.Tables = append(r.Tables, hostTable, nics, vmTable)
	r.Summary = fmt.Sprintf("%s: %s (%d connected), %s (%d on)", about.FullName, plural(len(hosts), "host"), connected, plural(vmCount, "VM"), vmsOn)
	return r, nil
}

// plural is "1 host", "2 hosts".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// ─── Enable SNMP on all hosts ─────────────────────────────────────────────────

// enableSNMPAll enables SNMP on every connected host (vsphere.EnableSNMP),
// one after the other: a host that fails does not stop the others. The
// result lists each host's outcome and the changes made.
func enableSNMPAll(ctx context.Context, c *vsphere.Client, community string) (modules.Result, error) {
	var r modules.Result
	hosts, err := readAll(ctx, c)
	if err != nil {
		return r, err
	}
	outcome := modules.Table{Title: "ESXi hosts", Columns: []string{"Name", "Management IP", "Result"}}
	on, failed := 0, 0
	for _, h := range hosts {
		if !h.connected() {
			outcome.Rows = append(outcome.Rows, []string{h.Name, h.ManagementIP(), "skipped: " + h.state})
			continue
		}
		changes, err := vsphere.EnableSNMP(ctx, c, vsphere.MoRef{Type: "HostSystem", Value: h.ref}, community)
		for _, ch := range changes {
			r.Changes = append(r.Changes, h.Name+": "+ch)
		}
		result := strings.Join(changes, "; ")
		if err != nil {
			failed++
			result = strings.TrimPrefix(result+"; failed: "+err.Error(), "; ")
		} else {
			on++
		}
		outcome.Rows = append(outcome.Rows, []string{h.Name, h.ManagementIP(), result})
		if ctx.Err() != nil {
			break
		}
	}
	r.Tables = append(r.Tables, outcome)
	r.Summary = fmt.Sprintf("SNMP is on, community %s, on %d of %s", community, on, plural(len(hosts), "host"))
	if failed > 0 {
		r.Summary += fmt.Sprintf("; %d failed", failed)
	}
	return r, nil
}

// ─── Inventory ────────────────────────────────────────────────────────────────

// Inventory gives the scanner the vCenter's hosts (modules.Inventorier):
// a managed device per MAC of each host (its VMkernel NICs', the first
// with an IP first, then its physical NICs'), named as vCenter does, of
// kind "hypervisor"; the one with the first MAC lists the host's virtual
// machines as clients of kind "vm", one per virtual NIC, so the graph and
// the tree name them. A host whose configuration vCenter does not have
// (disconnected) has no MAC, and is left out.
func (Module) Inventory(ctx context.Context, req modules.Request) (modules.Inventory, error) {
	var inv modules.Inventory
	c, err := connect(ctx, req.IP)
	if err != nil {
		return inv, err
	}
	if err := c.Login(ctx, req.Login); err != nil {
		return inv, err
	}
	defer c.Logout(context.WithoutCancel(ctx))
	hosts, err := readAll(ctx, c)
	if err != nil {
		return inv, err
	}
	for _, h := range hosts {
		var macs []string
		add := func(mac string) {
			if mac = strings.ToLower(strings.TrimSpace(mac)); mac != "" && !slices.Contains(macs, mac) {
				macs = append(macs, mac)
			}
		}
		for _, n := range h.VNICs {
			if n.Spec.IP.Address != "" {
				add(n.Spec.Mac)
			}
		}
		for _, n := range h.VNICs {
			add(n.Spec.Mac)
		}
		for _, n := range h.PNICs {
			add(n.Mac)
		}
		var clients []modules.ManagedClient
		for _, vm := range h.vms {
			for _, n := range vm.NICs {
				cl := modules.ManagedClient{MAC: n.MAC, Name: vm.Name, Kind: "vm", Hostname: vm.GuestName, Network: n.Network,
					OS: vm.GuestOS, Power: vm.Power}
				if len(n.IPs) > 0 {
					cl.IP = n.IPs[0]
				}
				clients = append(clients, cl)
			}
		}
		for i, mac := range macs {
			d := modules.ManagedDevice{MAC: mac, Name: h.Name, Model: h.Server, IP: h.ManagementIP(), State: h.state,
				Firmware: h.Product, Kind: "hypervisor"}
			if i == 0 {
				d.Clients = clients
			}
			inv.Devices = append(inv.Devices, d)
		}
	}
	return inv, nil
}
