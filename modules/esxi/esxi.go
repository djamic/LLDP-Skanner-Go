// Package esxi is the device module of VMware ESXi hosts: over the host's
// vSphere API (a login of protocol "vsphere"; modules/vsphere) it detects
// the host (name, version, license, server, physical and VMkernel NICs
// with what CDP or LLDP tells of their switch ports, virtual machines,
// SNMP state) and enables its SNMP agent with the scanner's community. A
// vCenter Server is modules/vcenter's.
package esxi

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"lldp_scanner/modules"
	"lldp_scanner/modules/vsphere"
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
	c := vsphere.NewClient(req.IP)
	if err := c.Connect(ctx); err != nil {
		return modules.Result{}, err
	}
	if t := c.Content.About.APIType; t != vsphere.APIHostAgent {
		return modules.Result{}, fmt.Errorf("%s is a %s (%s), not an ESXi host", c.URL(), cmp.Or(t, "device of no API type"), c.Content.About.FullName)
	}
	if err := c.Login(ctx, req.Login); err != nil {
		return modules.Result{}, err
	}
	defer c.Logout(context.WithoutCancel(ctx))
	switch req.Action {
	case "detect":
		return detect(ctx, c)
	case "enable-snmp":
		var r modules.Result
		changes, err := vsphere.EnableSNMP(ctx, c, hostRef, req.Community)
		r.Changes = changes
		if err != nil {
			return r, err
		}
		r.Summary = "SNMP is on, community " + cmp.Or(req.Community, "public")
		return r, nil
	}
	return modules.Result{}, fmt.Errorf("unknown action %q", req.Action)
}

// The host of a standalone ESXi API
var hostRef = vsphere.MoRef{Type: "HostSystem", Value: "ha-host"}

// ─── Detect ───────────────────────────────────────────────────────────────────

func detect(ctx context.Context, c *vsphere.Client) (modules.Result, error) {
	var r modules.Result
	p, err := c.RetrieveOne(ctx, hostRef, vsphere.HostPaths...)
	if err != nil {
		return r, fmt.Errorf("host properties: %w", err)
	}
	h := vsphere.ParseHost(p)
	if h.Product == "" {
		h.Product = c.Content.About.FullName
	}
	r.AddFact("Host name", h.Name)
	r.AddFact("Product", h.Product)
	r.AddFact("License", vsphere.LicenseName(ctx, c))
	r.AddFact("Server", h.Server)
	r.AddFact("Serial number", h.Serial)
	r.AddFact("CPU", h.CPU)
	r.AddFact("Memory", h.Memory)

	// Physical NICs, the vSwitch of each, and what CDP or LLDP tells of the
	// switch port it is cabled to
	hints := vsphere.NicHints(ctx, c, h.Managers.Network, h.PNICs)
	nics := modules.Table{Title: "Physical NICs", Columns: []string{"NIC", "MAC", "Speed", "vSwitch", "Switch", "Switch port"}}
	for _, n := range h.PNICs {
		hint := hints[n.Device]
		nics.Rows = append(nics.Rows, []string{n.Device, n.Mac, n.Speed(), h.VSwitch[n.Key], hint[0], hint[1]})
	}
	r.Tables = append(r.Tables, nics)

	vmk := modules.Table{Title: "VMkernel NICs", Columns: []string{"NIC", "MAC", "IP", "Port group"}}
	for _, n := range h.VNICs {
		ip := n.Spec.IP.Address
		if n.Spec.IP.DHCP {
			ip += " (DHCP)"
		}
		vmk.Rows = append(vmk.Rows, []string{n.Device, n.Spec.Mac, ip, n.Portgroup})
	}
	r.Tables = append(r.Tables, vmk)

	// SNMP: the agent, its firewall rule and the snmpd service
	snmp := vsphere.SNMPState(ctx, c, h.Managers.SNMP, h.Managers.Firewall, h.Managers.Service)
	r.AddFact("SNMP agent", snmp.Agent)
	r.AddFact("SNMP firewall rule", snmp.Firewall)
	r.AddFact("snmpd service", snmp.Service)

	// Virtual machines
	vms, on := vmTable(ctx, c)
	r.Tables = append(r.Tables, vms)
	r.Summary = fmt.Sprintf("%s: %s, %d physical NICs, %d VMs (%d on)", h.Name, h.Product, len(h.PNICs), len(vms.Rows), on)
	return r, nil
}

// vmTable lists the host's virtual machines, and how many are on.
func vmTable(ctx context.Context, c *vsphere.Client) (modules.Table, int) {
	t := modules.Table{Title: "Virtual machines", Columns: []string{"Name", "Power", "Guest OS", "Guest name", "IP", "MAC"}}
	objs, err := c.Retrieve(ctx, hostRef, "VirtualMachine", "vm", vsphere.VMPaths)
	if err != nil {
		t.Title += " (not read: " + err.Error() + ")"
		return t, 0
	}
	on := 0
	for _, o := range objs {
		vm := vsphere.ParseVM(o.Props())
		if vm.Power == "On" {
			on++
		}
		t.Rows = append(t.Rows, []string{vm.Name, vm.Power, vm.GuestOS, vm.GuestName, strings.Join(vm.IPs(), ", "), strings.Join(vm.MACs(), ", ")})
	}
	slices.SortFunc(t.Rows, func(a, b []string) int { return strings.Compare(strings.ToLower(a[0]), strings.ToLower(b[0])) })
	return t, on
}
