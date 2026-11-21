package vcenter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"lldp_scanner/modules"
	"lldp_scanner/modules/vsphere"
)

// Tests of the vCenter module against a fake vCenter API: the answers are
// shaped as those of vCenter Server 8.0.3 (vim25 SOAP), with made-up
// names and addresses. Every name, address and password here is made up.

// fakeVC is a vCenter API with three hosts: esx-a (cluster Prod, SNMP
// off), esx-b (standalone, a license that refuses changes) and esx-c
// (disconnected, no configuration).
type fakeVC struct {
	t          *testing.T
	user, pass string

	mu     sync.Mutex
	calls  []string
	bodies []string
	views  map[string]string // view → its type
}

func newFakeVC(t *testing.T) *fakeVC {
	f := &fakeVC{t: t, user: "administrator@vsphere.local", pass: "S3cret<&>", views: map[string]string{}}
	srv := httptest.NewTLSServer(f)
	old := vsphere.SDKURL
	vsphere.SDKURL = func(string) string { return srv.URL + "/sdk" }
	t.Cleanup(func() { vsphere.SDKURL = old; srv.Close() })
	return f
}

var fakeMethod = regexp.MustCompile(`<soapenv:Body><(\w+)`)

const fakeEnvelope = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<soapenv:Body>%s</soapenv:Body></soapenv:Envelope>`

func fault(kind, text string) string {
	return fmt.Sprintf(`<soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>%s</faultstring><detail><%sFault xmlns="urn:vim25" xsi:type="%s"></%sFault></detail></soapenv:Fault>`,
		text, kind, kind, kind)
}

const serviceContent = `<RetrieveServiceContentResponse xmlns="urn:vim25"><returnval><rootFolder type="Folder">group-d1</rootFolder>` +
	`<propertyCollector type="PropertyCollector">propertyCollector</propertyCollector><viewManager type="ViewManager">ViewManager</viewManager>` +
	`<about><name>VMware vCenter Server</name><fullName>VMware vCenter Server 8.0.3 build-24022515</fullName><version>8.0.3</version>` +
	`<apiType>VirtualCenter</apiType><apiVersion>8.0.3.0</apiVersion></about>` +
	`<sessionManager type="SessionManager">SessionManager</sessionManager><licenseManager type="LicenseManager">LicenseManager</licenseManager>` +
	`</returnval></RetrieveServiceContentResponse>`

func (f *fakeVC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	body := string(data)
	m := fakeMethod.FindStringSubmatch(body)
	if m == nil {
		http.Error(w, "no SOAP body", 400)
		return
	}
	method := m[1]
	f.mu.Lock()
	f.calls = append(f.calls, method)
	f.bodies = append(f.bodies, body)
	f.mu.Unlock()
	reply := func(s string) { w.Header().Set("Content-Type", "text/xml"); fmt.Fprintf(w, fakeEnvelope, s) }
	switch method {
	case "RetrieveServiceContent":
		reply(serviceContent)
		return
	case "Login":
		if !strings.Contains(body, "<userName>"+f.user+"</userName>") || !strings.Contains(body, "<password>S3cret&lt;&amp;&gt;</password>") {
			reply(fault("InvalidLogin", "Cannot complete login due to an incorrect user name or password."))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "vmware_soap_session", Value: "vc1", Path: "/"})
		reply(`<LoginResponse xmlns="urn:vim25"><returnval><userName>VSPHERE.LOCAL\Administrator</userName></returnval></LoginResponse>`)
		return
	}
	if c, err := r.Cookie("vmware_soap_session"); err != nil || c.Value != "vc1" {
		reply(fault("NotAuthenticated", "The session is not authenticated."))
		return
	}
	switch method {
	case "CreateContainerView":
		kind := regexp.MustCompile(`<type>(\w+)</type>`).FindStringSubmatch(body)[1]
		f.mu.Lock()
		view := fmt.Sprintf("session[vc1]view-%d", len(f.views)+1)
		f.views[view] = kind
		f.mu.Unlock()
		reply(`<CreateContainerViewResponse xmlns="urn:vim25"><returnval type="ContainerView">` + view + `</returnval></CreateContainerViewResponse>`)
	case "DestroyView":
		f.mu.Lock()
		delete(f.views, regexp.MustCompile(`<_this type="ContainerView">([^<]*)</_this>`).FindStringSubmatch(body)[1])
		f.mu.Unlock()
		reply(`<DestroyViewResponse xmlns="urn:vim25"></DestroyViewResponse>`)
	case "RetrieveProperties":
		reply(`<RetrievePropertiesResponse xmlns="urn:vim25">` + f.properties(body) + `</RetrievePropertiesResponse>`)
	case "QueryNetworkHint":
		reply(`<QueryNetworkHintResponse xmlns="urn:vim25"><returnval><device>vmnic0</device><lldpInfo><chassisId>4c:ae:a3:00:00:02</chassisId>` +
			`<portId>GigabitEthernet1/0/26</portId><parameter><key>System Name</key><value xsi:type="xsd:string">sw-core</value></parameter></lldpInfo></returnval></QueryNetworkHintResponse>`)
	case "ReconfigureSnmpAgent":
		if strings.Contains(body, ">snmp-b<") {
			reply(fault("RestrictedVersion", "Current license or ESXi version prohibits execution of the requested operation."))
			return
		}
		reply(`<ReconfigureSnmpAgentResponse xmlns="urn:vim25"></ReconfigureSnmpAgentResponse>`)
	case "EnableRuleset", "UpdateServicePolicy", "StartService", "RestartService", "Logout":
		reply(`<` + method + `Response xmlns="urn:vim25"></` + method + `Response>`)
	default:
		reply(fault("NotSupported", "unexpected "+method))
	}
}

func prop(name, val string) string { return "<propSet><name>" + name + "</name>" + val + "</propSet>" }

func str(s string) string { return `<val xsi:type="xsd:string">` + s + `</val>` }

func ref(kind, v string) string {
	return `<val type="` + kind + `" xsi:type="ManagedObjectReference">` + v + `</val>`
}

// hostProps are the properties of a connected host.
func hostProps(name, mac, ip, snmp string) []string {
	return []string{
		prop("name", str(name)),
		prop("summary.hardware", `<val xsi:type="HostHardwareSummary"><vendor>HPE</vendor><model>ProLiant DL380 Gen10</model><memorySize>274877906944</memorySize>`+
			`<cpuModel>Intel(R) Xeon(R) Gold 6130 CPU</cpuModel><numCpuPkgs>2</numCpuPkgs><numCpuCores>32</numCpuCores><numCpuThreads>64</numCpuThreads></val>`),
		prop("summary.config.product", `<val xsi:type="AboutInfo"><fullName>VMware ESXi 8.0.3 build-24022510</fullName></val>`),
		prop("hardware.systemInfo.serialNumber", str("CZJ-"+name)),
		prop("config.network.dnsConfig", `<val xsi:type="HostDnsConfig"><hostName>`+name+`</hostName><domainName>lab.local</domainName></val>`),
		prop("config.network.pnic", `<val xsi:type="ArrayOfPhysicalNic"><PhysicalNic><key>key-vim.host.PhysicalNic-vmnic0</key><device>vmnic0</device>`+
			`<linkSpeed><speedMb>10000</speedMb><duplex>true</duplex></linkSpeed><mac>`+mac+`</mac></PhysicalNic>`+
			`<PhysicalNic><key>key-vim.host.PhysicalNic-vmnic1</key><device>vmnic1</device><mac>`+strings.Replace(mac, ":01", ":02", 1)+`</mac></PhysicalNic></val>`),
		prop("config.network.vnic", `<val xsi:type="ArrayOfHostVirtualNic"><HostVirtualNic><device>vmk1</device><portgroup>vMotion</portgroup><spec><ip><dhcp>false</dhcp></ip>`+
			`<mac>00:50:56:6a:00:`+mac[len(mac)-5:len(mac)-3]+`</mac></spec></HostVirtualNic><HostVirtualNic><device>vmk0</device><portgroup>Management Network</portgroup>`+
			`<spec><ip><dhcp>false</dhcp><ipAddress>`+ip+`</ipAddress></ip><mac>`+mac+`</mac></spec></HostVirtualNic></val>`),
		prop("config.network.vswitch", `<val xsi:type="ArrayOfHostVirtualSwitch"><HostVirtualSwitch><name>vSwitch0</name><pnic>key-vim.host.PhysicalNic-vmnic0</pnic></HostVirtualSwitch></val>`),
		prop("configManager.networkSystem", ref("HostNetworkSystem", "networkSystem-"+name)),
		prop("configManager.snmpSystem", ref("HostSnmpSystem", snmp)),
		prop("configManager.firewallSystem", ref("HostFirewallSystem", "firewall-"+name)),
		prop("configManager.serviceSystem", ref("HostServiceSystem", "service-"+name)),
	}
}

func object(kind, id string, props ...string) string {
	return `<returnval><obj type="` + kind + `">` + id + `</obj>` + strings.Join(props, "") + `</returnval>`
}

// properties answers RetrieveProperties: the objects of a view by its
// type, or one manager of a host.
func (f *fakeVC) properties(body string) string {
	obj := regexp.MustCompile(`<obj type="(\w+)">([^<]*)</obj>`).FindStringSubmatch(body)
	f.mu.Lock()
	kind := f.views[obj[2]]
	f.mu.Unlock()
	switch {
	case obj[1] == "ContainerView" && kind == "HostSystem":
		a := append(hostProps("esx-a", "48:df:37:00:0a:01", "10.9.0.41", "snmp-a"),
			prop("runtime.connectionState", `<val xsi:type="HostSystemConnectionState">connected</val>`),
			prop("runtime.powerState", `<val xsi:type="HostSystemPowerState">poweredOn</val>`),
			prop("runtime.inMaintenanceMode", `<val xsi:type="xsd:boolean">false</val>`), prop("parent", ref("ClusterComputeResource", "domain-c8")))
		b := append(hostProps("esx-b", "48:df:37:00:0b:01", "10.9.0.42", "snmp-b"),
			prop("runtime.connectionState", `<val xsi:type="HostSystemConnectionState">connected</val>`),
			prop("runtime.powerState", `<val xsi:type="HostSystemPowerState">poweredOn</val>`),
			prop("runtime.inMaintenanceMode", `<val xsi:type="xsd:boolean">true</val>`), prop("parent", ref("ComputeResource", "domain-s20")))
		c := []string{prop("name", str("10.9.0.43")), prop("runtime.connectionState", `<val xsi:type="HostSystemConnectionState">notResponding</val>`),
			prop("runtime.powerState", `<val xsi:type="HostSystemPowerState">unknown</val>`), prop("parent", ref("ClusterComputeResource", "domain-c8"))}
		return object("HostSystem", "host-12", a...) + object("HostSystem", "host-20", b...) + object("HostSystem", "host-30", c...)
	case obj[1] == "ContainerView" && kind == "ComputeResource":
		return object("ClusterComputeResource", "domain-c8", prop("name", str("Prod"))) + object("ComputeResource", "domain-s20", prop("name", str("esx-b.lab.local")))
	case obj[1] == "ContainerView" && kind == "VirtualMachine":
		vm := func(id, name, host, power, os, guest, nics, template string) string {
			return object("VirtualMachine", id, prop("name", str(name)), prop("runtime.host", ref("HostSystem", host)),
				prop("runtime.powerState", `<val xsi:type="VirtualMachinePowerState">`+power+`</val>`), prop("summary.config.guestFullName", str(os)),
				prop("guest.hostName", str(guest)), prop("config.template", `<val xsi:type="xsd:boolean">`+template+`</val>`), nics)
		}
		web := prop("config.hardware.device", `<val xsi:type="ArrayOfVirtualDevice"><VirtualDevice xsi:type="VirtualIDEController"><key>200</key></VirtualDevice>`+
			`<VirtualDevice xsi:type="VirtualVmxnet3"><key>4000</key><backing xsi:type="VirtualEthernetCardNetworkBackingInfo"><deviceName>VM Network</deviceName></backing>`+
			`<macAddress>00:50:56:AA:00:01</macAddress></VirtualDevice><VirtualDevice xsi:type="VirtualVmxnet3"><key>4001</key><macAddress>00:50:56:aa:00:02</macAddress></VirtualDevice></val>`) +
			prop("guest.net", `<val xsi:type="ArrayOfGuestNicInfo"><GuestNicInfo><network>VM Network</network><ipAddress>10.9.1.10</ipAddress><ipAddress>fe80::1</ipAddress>`+
				`<macAddress>00:50:56:aa:00:01</macAddress></GuestNicInfo><GuestNicInfo><network>Backup</network><ipAddress>10.20.1.10</ipAddress><macAddress>00:50:56:aa:00:02</macAddress></GuestNicInfo></val>`)
		db := prop("config.hardware.device", `<val xsi:type="ArrayOfVirtualDevice"><VirtualDevice xsi:type="VirtualE1000"><key>4000</key><macAddress>00:0c:29:aa:00:03</macAddress></VirtualDevice></val>`)
		tpl := prop("config.hardware.device", `<val xsi:type="ArrayOfVirtualDevice"><VirtualDevice xsi:type="VirtualE1000"><key>4000</key><macAddress>00:50:56:aa:00:09</macAddress></VirtualDevice></val>`)
		return vm("vm-1", "Web &amp; App", "host-12", "poweredOn", "Ubuntu Linux (64-bit)", "web01", web, "false") +
			vm("vm-2", "db", "host-12", "poweredOff", "Microsoft Windows Server 2019 (64-bit)", "", db, "false") +
			vm("vm-3", "tpl-ubuntu", "host-12", "poweredOff", "Ubuntu Linux (64-bit)", "", tpl, "true") +
			vm("vm-4", "mail", "host-20", "poweredOn", "Rocky Linux (64-bit)", "mail", prop("config.hardware.device",
				`<val xsi:type="ArrayOfVirtualDevice"><VirtualDevice xsi:type="VirtualVmxnet3"><key>4000</key><macAddress>00:50:56:aa:00:04</macAddress></VirtualDevice></val>`), "false")
	case obj[1] == "HostSystem":
		// EnableSNMP's managers of a host
		h := map[string]string{"host-12": "esx-a", "host-20": "esx-b"}[obj[2]]
		return object("HostSystem", obj[2], prop("configManager.snmpSystem", ref("HostSnmpSystem", "snmp-"+h[len(h)-1:])),
			prop("configManager.firewallSystem", ref("HostFirewallSystem", "firewall-"+h)), prop("configManager.serviceSystem", ref("HostServiceSystem", "service-"+h)))
	case obj[1] == "HostSnmpSystem":
		return object(obj[1], obj[2], prop("configuration", `<val xsi:type="HostSnmpConfigSpec"><enabled>false</enabled><port>161</port><readOnlyCommunities>monitor</readOnlyCommunities></val>`))
	case obj[1] == "HostFirewallSystem":
		return object(obj[1], obj[2], prop("firewallInfo", `<val xsi:type="HostFirewallInfo"><ruleset><key>snmp</key><enabled>false</enabled></ruleset></val>`))
	case obj[1] == "HostServiceSystem":
		return object(obj[1], obj[2], prop("serviceInfo", `<val xsi:type="HostServiceInfo"><service><key>snmpd</key><running>false</running><policy>off</policy></service></val>`))
	case obj[1] == "LicenseManager":
		return object(obj[1], obj[2], prop("licenses", `<val xsi:type="ArrayOfLicenseManagerLicenseInfo"><LicenseManagerLicenseInfo><name>VMware vCenter Server 8 Standard</name></LicenseManagerLicenseInfo>`+
			`<LicenseManagerLicenseInfo><name>VMware vSphere 8 Enterprise Plus</name></LicenseManagerLicenseInfo><LicenseManagerLicenseInfo><name>VMware vSphere 8 Enterprise Plus</name></LicenseManagerLicenseInfo></val>`))
	}
	f.t.Errorf("RetrieveProperties of an unknown object %v (%s)", obj, kind)
	return ""
}

func (f *fakeVC) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeVC) login() modules.Login { return modules.Login{Username: f.user, Password: f.pass} }

func fact(r modules.Result, label string) string {
	for _, f := range r.Facts {
		if f.Label == label {
			return f.Value
		}
	}
	return ""
}

func table(t *testing.T, r modules.Result, title string) modules.Table {
	t.Helper()
	for _, tb := range r.Tables {
		if tb.Title == title {
			return tb
		}
	}
	t.Fatalf("no table %q", title)
	return modules.Table{}
}

func TestDetect(t *testing.T) {
	f := newFakeVC(t)
	r, err := Module{}.Run(context.Background(), modules.Request{IP: "10.9.0.7", Action: "detect", Login: f.login()})
	if err != nil {
		t.Fatal(err)
	}
	for label, want := range map[string]string{
		"Product":          "VMware vCenter Server 8.0.3 build-24022515",
		"API version":      "8.0.3.0",
		"License":          "VMware vCenter Server 8 Standard, VMware vSphere 8 Enterprise Plus",
		"Clusters":         "Prod",
		"ESXi hosts":       "3 (2 connected, 1 in maintenance)",
		"Virtual machines": "3 (2 on)",
	} {
		if got := fact(r, label); got != want {
			t.Errorf("fact %s = %q, want %q", label, got, want)
		}
	}
	wantHosts := [][]string{
		{"10.9.0.43", "Prod", "", "", "NOT_RESPONDING", "", "0 (0)", ""},
		{"esx-a.lab.local", "Prod", "HPE ProLiant DL380 Gen10", "VMware ESXi 8.0.3 build-24022510", "ONLINE", "10.9.0.41", "2 (1)", "agent disabled; firewall closed; snmpd stopped, starts: off"},
		{"esx-b.lab.local", "", "HPE ProLiant DL380 Gen10", "VMware ESXi 8.0.3 build-24022510", "MAINTENANCE", "10.9.0.42", "1 (1)", "agent disabled; firewall closed; snmpd stopped, starts: off"},
	}
	if got := table(t, r, "ESXi hosts").Rows; !reflect.DeepEqual(got, wantHosts) {
		t.Errorf("hosts\n got %q\nwant %q", got, wantHosts)
	}
	nics := table(t, r, "Physical NICs").Rows
	if len(nics) != 4 || !reflect.DeepEqual(nics[0], []string{"esx-a.lab.local", "vmnic0", "48:df:37:00:0a:01", "10G", "vSwitch0", "LLDP: sw-core (4c:ae:a3:00:00:02)", "GigabitEthernet1/0/26"}) ||
		nics[1][3] != "down" {
		t.Errorf("physical NICs %q", nics)
	}
	wantVMs := [][]string{
		{"db", "esx-a.lab.local", "Off", "Microsoft Windows Server 2019 (64-bit)", "", "", "00:0c:29:aa:00:03"},
		{"mail", "esx-b.lab.local", "On", "Rocky Linux (64-bit)", "mail", "", "00:50:56:aa:00:04"},
		{"Web & App", "esx-a.lab.local", "On", "Ubuntu Linux (64-bit)", "web01", "10.9.1.10, 10.20.1.10", "00:50:56:aa:00:01, 00:50:56:aa:00:02"},
	}
	if got := table(t, r, "Virtual machines").Rows; !reflect.DeepEqual(got, wantVMs) {
		t.Errorf("VMs\n got %q\nwant %q", got, wantVMs)
	}
	if want := "VMware vCenter Server 8.0.3 build-24022515: 3 hosts (2 connected), 3 VMs (2 on)"; r.Summary != want {
		t.Errorf("summary %q, want %q", r.Summary, want)
	}
	calls := f.called()
	if calls[len(calls)-1] != "Logout" || slices.Contains(calls, "ReconfigureSnmpAgent") {
		t.Errorf("calls %v: want no change and a logout last", calls)
	}
	f.mu.Lock()
	if len(f.views) != 0 {
		t.Errorf("views left: %v", f.views)
	}
	f.mu.Unlock()
}

func TestInventory(t *testing.T) {
	f := newFakeVC(t)
	inv, err := Module{}.Inventory(context.Background(), modules.Request{IP: "10.9.0.7", Login: f.login()})
	if err != nil {
		t.Fatal(err)
	}
	var macs []string
	for _, d := range inv.Devices {
		macs = append(macs, d.MAC+" "+d.Name+" "+d.State+" "+d.Kind+" "+d.IP+fmt.Sprintf(" %d", len(d.Clients)))
	}
	// the host's management MAC first, with the VMs; the not-responding
	// host has no MAC
	want := []string{
		"48:df:37:00:0a:01 esx-a.lab.local ONLINE hypervisor 10.9.0.41 3", "00:50:56:6a:00:0a esx-a.lab.local ONLINE hypervisor 10.9.0.41 0",
		"48:df:37:00:0a:02 esx-a.lab.local ONLINE hypervisor 10.9.0.41 0",
		"48:df:37:00:0b:01 esx-b.lab.local MAINTENANCE hypervisor 10.9.0.42 1", "00:50:56:6a:00:0b esx-b.lab.local MAINTENANCE hypervisor 10.9.0.42 0",
		"48:df:37:00:0b:02 esx-b.lab.local MAINTENANCE hypervisor 10.9.0.42 0",
	}
	if !slices.Equal(macs, want) {
		t.Errorf("devices\n got %q\nwant %q", macs, want)
	}
	wantVMs := []modules.ManagedClient{
		{MAC: "00:0c:29:aa:00:03", Name: "db", Kind: "vm", OS: "Microsoft Windows Server 2019 (64-bit)", Power: "Off"},
		{MAC: "00:50:56:aa:00:01", Name: "Web & App", IP: "10.9.1.10", Kind: "vm", Hostname: "web01", Network: "VM Network", OS: "Ubuntu Linux (64-bit)", Power: "On"},
		{MAC: "00:50:56:aa:00:02", Name: "Web & App", IP: "10.20.1.10", Kind: "vm", Hostname: "web01", Network: "Backup", OS: "Ubuntu Linux (64-bit)", Power: "On"},
	}
	if got := inv.Devices[0].Clients; !slices.Equal(got, wantVMs) {
		t.Errorf("VMs of esx-a\n got %+v\nwant %+v", got, wantVMs)
	}
	// a physical NIC's uplink: the switch port its LLDP tells (vmnic0's);
	// a VMkernel NIC has none
	uplinks := map[string]string{}
	for _, d := range inv.Devices {
		if d.Uplink != nil {
			uplinks[d.MAC] = d.Uplink.MAC + " " + d.Uplink.Port + " " + d.Uplink.LocalPort
		}
	}
	for mac, up := range uplinks {
		if strings.HasPrefix(mac, "00:50:56") || up != "4c:ae:a3:00:00:02 GigabitEthernet1/0/26 vmnic0" {
			t.Errorf("uplink of %s: %q", mac, up)
		}
	}
	if len(uplinks) == 0 {
		t.Error("no physical NIC has the uplink its LLDP tells")
	}
	for _, c := range []struct{ state, want string }{
		{modules.StateOnline, modules.StateOnline}, {"MAINTENANCE", "MAINTENANCE"},
		{"NOT_RESPONDING", modules.StateOffline}, {"DISCONNECTED", modules.StateOffline}, {"OFF", modules.StateOffline}, {"STANDBY", modules.StateOffline},
	} {
		if got := (host{state: c.state}).managedState(); got != c.want {
			t.Errorf("managedState of a %s host = %q, want %q", c.state, got, c.want)
		}
	}
	if _, err := (Module{}).Inventory(context.Background(), modules.Request{IP: "10.9.0.7", Login: modules.Login{Username: "root", Password: "x"}}); !errors.Is(err, modules.ErrLoginRejected) {
		t.Errorf("a wrong login: %v", err)
	}
}

// TestEnableSNMPAll checks SNMP enabled host by host: the one that refuses
// (its license) does not stop the others, and the host vCenter does not
// talk to is skipped.
func TestEnableSNMPAll(t *testing.T) {
	f := newFakeVC(t)
	r, err := Module{}.Run(context.Background(), modules.Request{IP: "10.9.0.7", Action: "enable-snmp-all", Login: f.login(), Community: "public"})
	if err != nil {
		t.Fatal(err)
	}
	rows := table(t, r, "ESXi hosts").Rows
	if len(rows) != 3 || rows[0][2] != "skipped: NOT_RESPONDING" ||
		rows[1][2] != "SNMP agent enabled on port 161, communities: monitor, public; firewall rule 'snmp' opened; snmpd set to start with the host; snmpd started" ||
		!strings.HasPrefix(rows[2][2], "failed: the host's license (VMware vCenter Server 8 Standard, VMware vSphere 8 Enterprise Plus) does not let the API change its settings") {
		t.Errorf("outcome %q", rows)
	}
	if r.Summary != "SNMP is on, community public, on 1 of 3 hosts; 1 failed" || len(r.Changes) != 4 || !strings.HasPrefix(r.Changes[0], "esx-a.lab.local: SNMP agent enabled") {
		t.Errorf("summary %q, changes %q", r.Summary, r.Changes)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.bodies {
		if strings.Contains(b, "<ReconfigureSnmpAgent") && strings.Contains(b, ">snmp-a<") &&
			!strings.Contains(b, "<readOnlyCommunities>monitor</readOnlyCommunities><readOnlyCommunities>public</readOnlyCommunities>") {
			t.Errorf("the spec of esx-a %s", b)
		}
	}
}

func TestProbeAndKind(t *testing.T) {
	newFakeVC(t)
	if !(Module{}).Probe(context.Background(), "10.9.0.7") {
		t.Error("the vCenter is not recognized")
	}
	esx := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, fakeEnvelope, `<RetrieveServiceContentResponse xmlns="urn:vim25"><returnval><about><fullName>VMware ESXi 8.0.3</fullName><apiType>HostAgent</apiType></about></returnval></RetrieveServiceContentResponse>`)
	}))
	defer esx.Close()
	vsphere.SDKURL = func(string) string { return esx.URL + "/sdk" }
	if (Module{}).Probe(context.Background(), "10.9.0.40") {
		t.Error("an ESXi host is taken for a vCenter")
	}
	if _, err := (Module{}).Run(context.Background(), modules.Request{IP: "10.9.0.40", Action: "detect"}); err == nil || !strings.Contains(err.Error(), "not a vCenter Server") {
		t.Errorf("detect on an ESXi host: %v", err)
	}
	vsphere.SDKURL = func(string) string { return "https://127.0.0.1:1/sdk" }
	if (Module{}).Probe(context.Background(), "10.9.0.9") {
		t.Error("nothing there is a vCenter")
	}
}
