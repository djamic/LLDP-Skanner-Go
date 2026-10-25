package esxi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"lldp_scanner/modules"
)

// Tests of the ESXi module against a fake host API: the answers are those
// of an ESXi 8.0.3 host (vim25 SOAP), with made-up names and addresses.

// fakeHost is an ESXi host API: it checks the login and the session
// cookie, answers the calls the module makes and notes them.
type fakeHost struct {
	t          *testing.T
	user, pass string
	restricted bool // a free license: changes are refused
	snmp       string
	firewall   string
	service    string

	mu      sync.Mutex
	calls   []string // method names, in order
	bodies  map[string]string
	actions []string // SOAPAction headers
}

func newFakeHost(t *testing.T) (*fakeHost, func()) {
	h := &fakeHost{t: t, user: "root", pass: `S3cret<&>"`, bodies: map[string]string{},
		snmp: `<enabled>false</enabled><port>161</port><readOnlyCommunities>monitor</readOnlyCommunities>` +
			`<trapTargets><hostName>10.9.0.9</hostName><port>162</port><community>traps</community></trapTargets>`,
		firewall: `<ruleset><key>sshServer</key><label>SSH Server</label><required>false</required><rule><port>22</port></rule><enabled>true</enabled></ruleset>` +
			`<ruleset><key>snmp</key><label>SNMP Server</label><required>false</required><rule><port>161</port></rule><enabled>false</enabled></ruleset>`,
		service: `<service><key>snmpd</key><label>SNMP Server</label><required>false</required><running>false</running><ruleset>snmp</ruleset><policy>off</policy></service>`,
	}
	srv := httptest.NewTLSServer(h)
	old := sdkURL
	sdkURL = func(string) string { return srv.URL + "/sdk" }
	return h, func() { sdkURL = old; srv.Close() }
}

var fakeMethod = regexp.MustCompile(`<soapenv:Body><(\w+)`)

const fakeEnvelope = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<soapenv:Body>
%s
</soapenv:Body>
</soapenv:Envelope>`

func fault(kind, text string) string {
	return fmt.Sprintf(`<soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>%s</faultstring><detail><%sFault xmlns="urn:vim25" xsi:type="%s"></%sFault></detail></soapenv:Fault>`,
		text, kind, kind, kind)
}

func prop(name, val string) string {
	return "<propSet><name>" + name + "</name>" + val + "</propSet>"
}

func (h *fakeHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	body := string(data)
	m := fakeMethod.FindStringSubmatch(body)
	if m == nil {
		http.Error(w, "no SOAP body", 400)
		return
	}
	method := m[1]
	h.mu.Lock()
	h.calls = append(h.calls, method)
	h.bodies[method] = body
	h.actions = append(h.actions, r.Header.Get("SOAPAction"))
	h.mu.Unlock()
	reply := func(s string) { w.Header().Set("Content-Type", "text/xml"); fmt.Fprintf(w, fakeEnvelope, s) }

	if method == "RetrieveServiceContent" {
		reply(`<RetrieveServiceContentResponse xmlns="urn:vim25"><returnval><rootFolder type="Folder">ha-folder-root</rootFolder>` +
			`<propertyCollector type="PropertyCollector">ha-property-collector</propertyCollector>` +
			`<about><name>VMware ESXi</name><fullName>VMware ESXi 8.0.3 build-24022510</fullName><vendor>VMware, Inc.</vendor>` +
			`<version>8.0.3</version><build>24022510</build><apiType>HostAgent</apiType><apiVersion>8.0.3.0</apiVersion></about>` +
			`<sessionManager type="SessionManager">ha-sessionmgr</sessionManager><licenseManager type="LicenseManager">ha-license-manager</licenseManager>` +
			`</returnval></RetrieveServiceContentResponse>`)
		return
	}
	if method == "Login" {
		if !strings.Contains(body, "<userName>"+h.user+"</userName>") || !strings.Contains(body, "<password>S3cret&lt;&amp;&gt;&#34;</password>") {
			reply(fault("InvalidLogin", "Cannot complete login due to an incorrect user name or password."))
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "vmware_soap_session", Value: "s1", Path: "/"})
		reply(`<LoginResponse xmlns="urn:vim25"><returnval><key>52</key><userName>root</userName></returnval></LoginResponse>`)
		return
	}
	if c, err := r.Cookie("vmware_soap_session"); err != nil || c.Value != "s1" {
		reply(fault("NotAuthenticated", "The session is not authenticated."))
		return
	}

	switch method {
	case "RetrieveProperties":
		reply(h.properties(body))
	case "QueryNetworkHint":
		reply(`<QueryNetworkHintResponse xmlns="urn:vim25">` +
			`<returnval><device>vmnic0</device><lldpInfo><chassisId>4c:ae:a3:00:00:02</chassisId><portId>GigabitEthernet1/0/26</portId><timeToLive>120</timeToLive>` +
			`<parameter><key>System Name</key><value xsi:type="xsd:string">sw-core</value></parameter></lldpInfo></returnval>` +
			`<returnval><device>vmnic1</device><connectedSwitchPort><cdpVersion>2</cdpVersion><devId>sw-cisco</devId><address>10.9.0.2</address><portId>Gi0/7</portId></connectedSwitchPort></returnval>` +
			`<returnval><device>vmnic2</device></returnval></QueryNetworkHintResponse>`)
	case "ReconfigureSnmpAgent":
		if h.restricted {
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

// properties answers RetrieveProperties with the requested properties of
// the requested object (or of the host's VMs).
func (h *fakeHost) properties(body string) string {
	obj := regexp.MustCompile(`<obj type="(\w+)">([^<]*)</obj>`).FindStringSubmatch(body)
	var paths []string
	for _, m := range regexp.MustCompile(`<pathSet>([^<]*)</pathSet>`).FindAllStringSubmatch(body, -1) {
		paths = append(paths, m[1])
	}
	var all map[string]string
	ref := ""
	switch {
	case strings.Contains(body, "<type>VirtualMachine</type>"):
		return `<RetrievePropertiesResponse xmlns="urn:vim25">` + fakeVMs + `</RetrievePropertiesResponse>`
	case obj[1] == "HostSystem":
		all, ref = fakeHostProps, `<obj type="HostSystem">ha-host</obj>`
	case obj[1] == "HostSnmpSystem":
		all = map[string]string{"configuration": `<val xsi:type="HostSnmpConfigSpec">` + h.snmp + `</val>`}
	case obj[1] == "HostFirewallSystem":
		all = map[string]string{"firewallInfo": `<val xsi:type="HostFirewallInfo"><defaultPolicy><incomingBlocked>true</incomingBlocked></defaultPolicy>` + h.firewall + `</val>`}
	case obj[1] == "HostServiceSystem":
		all = map[string]string{"serviceInfo": `<val xsi:type="HostServiceInfo">` + h.service + `</val>`}
	case obj[1] == "LicenseManager":
		all = map[string]string{"licenses": `<val xsi:type="ArrayOfLicenseManagerLicenseInfo"><LicenseManagerLicenseInfo><licenseKey>00000-00000-00000-00000-00000</licenseKey>` +
			`<editionKey>esxEnterprisePlus</editionKey><name>VMware vSphere 8 Enterprise Plus</name><total>0</total></LicenseManagerLicenseInfo></val>`}
	}
	if ref == "" {
		ref = fmt.Sprintf(`<obj type="%s">%s</obj>`, obj[1], obj[2])
	}
	var b strings.Builder
	b.WriteString(`<RetrievePropertiesResponse xmlns="urn:vim25"><returnval>` + ref)
	for _, p := range paths {
		v, ok := all[p]
		if !ok {
			h.t.Errorf("RetrieveProperties of %s: unknown path %q", obj[1], p)
			continue
		}
		b.WriteString(prop(p, v))
	}
	b.WriteString(`</returnval></RetrievePropertiesResponse>`)
	return b.String()
}

var fakeHostProps = map[string]string{
	"name": `<val xsi:type="xsd:string">esx-test</val>`,
	"summary.hardware": `<val xsi:type="HostHardwareSummary"><vendor>HPE</vendor><model>ProLiant DL380 Gen10</model><uuid>30393137-3536-5a43-4a30-333430333032</uuid>` +
		`<otherIdentifyingInfo><identifierValue>CZJ0000001</identifierValue><identifierType><label>Service tag</label><summary>Service tag</summary><key>ServiceTag</key></identifierType></otherIdentifyingInfo>` +
		`<memorySize>274877906944</memorySize><cpuModel>Intel(R) Xeon(R) Gold 6130 CPU @ 2.10GHz</cpuModel><cpuMhz>2095</cpuMhz>` +
		`<numCpuPkgs>2</numCpuPkgs><numCpuCores>32</numCpuCores><numCpuThreads>64</numCpuThreads><numNics>3</numNics><numHBAs>3</numHBAs></val>`,
	"summary.config.product":           `<val xsi:type="AboutInfo"><name>VMware ESXi</name><fullName>VMware ESXi 8.0.3 build-24022510</fullName><version>8.0.3</version><build>24022510</build></val>`,
	"hardware.systemInfo.serialNumber": `<val xsi:type="xsd:string">CZJ0000002</val>`,
	"config.network.dnsConfig":         `<val xsi:type="HostDnsConfig"><dhcp>false</dhcp><hostName>esx-test</hostName><domainName>lab.local</domainName><address>10.9.0.53</address></val>`,
	"config.network.pnic": `<val xsi:type="ArrayOfPhysicalNic">` +
		`<PhysicalNic><key>key-vim.host.PhysicalNic-vmnic0</key><device>vmnic0</device><pci>0000:02:00.0</pci><driver>ntg3</driver><linkSpeed><speedMb>1000</speedMb><duplex>true</duplex></linkSpeed><mac>48:df:37:00:00:01</mac></PhysicalNic>` +
		`<PhysicalNic><key>key-vim.host.PhysicalNic-vmnic1</key><device>vmnic1</device><driver>i40en</driver><linkSpeed><speedMb>10000</speedMb><duplex>true</duplex></linkSpeed><mac>48:df:37:00:00:02</mac></PhysicalNic>` +
		`<PhysicalNic><key>key-vim.host.PhysicalNic-vmnic2</key><device>vmnic2</device><driver>ntg3</driver><mac>48:df:37:00:00:03</mac></PhysicalNic></val>`,
	"config.network.vnic": `<val xsi:type="ArrayOfHostVirtualNic"><HostVirtualNic><device>vmk0</device><key>key-vim.host.VirtualNic-vmk0</key><portgroup>Management Network</portgroup>` +
		`<spec><ip><dhcp>false</dhcp><ipAddress>10.9.0.40</ipAddress><subnetMask>255.255.0.0</subnetMask></ip><mac>48:df:37:00:00:01</mac><mtu>1500</mtu></spec></HostVirtualNic></val>`,
	"config.network.vswitch": `<val xsi:type="ArrayOfHostVirtualSwitch"><HostVirtualSwitch><name>vSwitch0</name><key>key-vim.host.VirtualSwitch-vSwitch0</key><numPorts>2560</numPorts>` +
		`<pnic>key-vim.host.PhysicalNic-vmnic0</pnic><pnic>key-vim.host.PhysicalNic-vmnic1</pnic></HostVirtualSwitch></val>`,
	"configManager.networkSystem":  `<val type="HostNetworkSystem" xsi:type="ManagedObjectReference">networkSystem</val>`,
	"configManager.snmpSystem":     `<val type="HostSnmpSystem" xsi:type="ManagedObjectReference">ha-snmp-agent</val>`,
	"configManager.firewallSystem": `<val type="HostFirewallSystem" xsi:type="ManagedObjectReference">firewallSystem</val>`,
	"configManager.serviceSystem":  `<val type="HostServiceSystem" xsi:type="ManagedObjectReference">serviceSystem</val>`,
	"vm": `<val xsi:type="ArrayOfManagedObjectReference"><ManagedObjectReference type="VirtualMachine" xsi:type="ManagedObjectReference">1</ManagedObjectReference>` +
		`<ManagedObjectReference type="VirtualMachine" xsi:type="ManagedObjectReference">2</ManagedObjectReference></val>`,
}

const fakeVMs = `<returnval><obj type="VirtualMachine">1</obj>` +
	`<propSet><name>config.hardware.device</name><val xsi:type="ArrayOfVirtualDevice"><VirtualDevice xsi:type="VirtualIDEController"><key>200</key><deviceInfo><label>IDE 0</label></deviceInfo><busNumber>0</busNumber></VirtualDevice>` +
	`<VirtualDevice xsi:type="VirtualVmxnet3"><key>4000</key><deviceInfo><label>Network adapter 1</label><summary>VM Network</summary></deviceInfo><backing xsi:type="VirtualEthernetCardNetworkBackingInfo"><deviceName>VM Network</deviceName></backing>` +
	`<addressType>generated</addressType><macAddress>00:0c:29:aa:bb:01</macAddress></VirtualDevice></val></propSet>` +
	`<propSet><name>guest.hostName</name><val xsi:type="xsd:string">web01</val></propSet>` +
	`<propSet><name>guest.net</name><val xsi:type="ArrayOfGuestNicInfo"><GuestNicInfo><network>VM Network</network><ipAddress>10.9.0.101</ipAddress><ipAddress>fe80::20c:29ff:feaa:bb01</ipAddress>` +
	`<macAddress>00:0c:29:aa:bb:01</macAddress><connected>true</connected><deviceConfigId>4000</deviceConfigId></GuestNicInfo></val></propSet>` +
	`<propSet><name>name</name><val xsi:type="xsd:string">Web &amp; DB</val></propSet>` +
	`<propSet><name>runtime.powerState</name><val xsi:type="VirtualMachinePowerState">poweredOn</val></propSet>` +
	`<propSet><name>summary.config.guestFullName</name><val xsi:type="xsd:string">Ubuntu Linux (64-bit)</val></propSet></returnval>` +
	`<returnval><obj type="VirtualMachine">2</obj>` +
	`<propSet><name>config.hardware.device</name><val xsi:type="ArrayOfVirtualDevice"><VirtualDevice xsi:type="VirtualE1000"><key>4000</key><macAddress>00:50:56:aa:bb:02</macAddress></VirtualDevice></val></propSet>` +
	`<propSet><name>name</name><val xsi:type="xsd:string">archive</val></propSet>` +
	`<propSet><name>runtime.powerState</name><val xsi:type="VirtualMachinePowerState">poweredOff</val></propSet>` +
	`<propSet><name>summary.config.guestFullName</name><val xsi:type="xsd:string">Microsoft Windows Server 2019 (64-bit)</val></propSet></returnval>`

func (h *fakeHost) called() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.calls)
}

func run(t *testing.T, action string, login modules.Login) (modules.Result, error) {
	t.Helper()
	return Module{}.Run(context.Background(), modules.Request{IP: "10.9.0.40", Action: action, Login: login, Community: "public"})
}

func fact(r modules.Result, label string) string {
	for _, f := range r.Facts {
		if f.Label == label {
			return f.Value
		}
	}
	return ""
}

func table(r modules.Result, title string) modules.Table {
	for _, t := range r.Tables {
		if t.Title == title {
			return t
		}
	}
	return modules.Table{}
}

func TestDetect(t *testing.T) {
	h, done := newFakeHost(t)
	defer done()
	r, err := run(t, "detect", modules.Login{Username: "root", Password: h.pass})
	if err != nil {
		t.Fatal(err)
	}
	for label, want := range map[string]string{
		"Host name":          "esx-test.lab.local",
		"Product":            "VMware ESXi 8.0.3 build-24022510",
		"License":            "VMware vSphere 8 Enterprise Plus",
		"Server":             "HPE ProLiant DL380 Gen10",
		"Serial number":      "CZJ0000002",
		"CPU":                "Intel(R) Xeon(R) Gold 6130 CPU @ 2.10GHz (2 × 16 cores, 64 threads)",
		"Memory":             "256 GiB",
		"SNMP agent":         "disabled",
		"SNMP firewall rule": "closed",
		"snmpd service":      "stopped, starts: off",
	} {
		if got := fact(r, label); got != want {
			t.Errorf("fact %q = %q, want %q", label, got, want)
		}
	}
	nics := table(r, "Physical NICs")
	want := [][]string{
		{"vmnic0", "48:df:37:00:00:01", "1G", "vSwitch0", "LLDP: sw-core (4c:ae:a3:00:00:02)", "GigabitEthernet1/0/26"},
		{"vmnic1", "48:df:37:00:00:02", "10G", "vSwitch0", "CDP: sw-cisco (10.9.0.2)", "Gi0/7"},
		{"vmnic2", "48:df:37:00:00:03", "down", "", "", ""},
	}
	if fmt.Sprint(nics.Rows) != fmt.Sprint(want) {
		t.Errorf("physical NICs\n%v\nwant\n%v", nics.Rows, want)
	}
	if vmk := table(r, "VMkernel NICs"); fmt.Sprint(vmk.Rows) != fmt.Sprint([][]string{{"vmk0", "48:df:37:00:00:01", "10.9.0.40", "Management Network"}}) {
		t.Errorf("VMkernel NICs %v", vmk.Rows)
	}
	vms := table(r, "Virtual machines")
	wantVMs := [][]string{
		{"archive", "Off", "Microsoft Windows Server 2019 (64-bit)", "", "", "00:50:56:aa:bb:02"},
		{"Web & DB", "On", "Ubuntu Linux (64-bit)", "web01", "10.9.0.101", "00:0c:29:aa:bb:01"},
	}
	if fmt.Sprint(vms.Rows) != fmt.Sprint(wantVMs) {
		t.Errorf("VMs\n%v\nwant\n%v", vms.Rows, wantVMs)
	}
	if r.Summary != "esx-test.lab.local: VMware ESXi 8.0.3 build-24022510, 3 physical NICs, 2 VMs (1 on)" {
		t.Errorf("summary %q", r.Summary)
	}
	if calls := h.called(); calls[len(calls)-1] != "Logout" || slices.Contains(calls, "ReconfigureSnmpAgent") {
		t.Errorf("calls %v: want no change and a logout last", calls)
	}
	h.mu.Lock()
	if h.actions[0] != `"urn:vim25/6.5"` || h.actions[1] != `"urn:vim25/8.0.3.0"` {
		t.Errorf("SOAPAction %v: want the host's API version after the first call", h.actions[:2])
	}
	h.mu.Unlock()
}

func TestLoginRejected(t *testing.T) {
	h, done := newFakeHost(t)
	defer done()
	_, err := run(t, "detect", modules.Login{Username: "root", Password: "wrong"})
	if !errors.Is(err, modules.ErrLoginRejected) {
		t.Fatalf("a wrong password: %v, want ErrLoginRejected", err)
	}
	if calls := h.called(); !slices.Equal(calls, []string{"RetrieveServiceContent", "Login"}) {
		t.Errorf("calls after a refused login %v", calls)
	}
}

func TestNotESXi(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, fakeEnvelope, `<RetrieveServiceContentResponse xmlns="urn:vim25"><returnval><about><fullName>VMware vCenter Server 8.0.3</fullName><apiType>VirtualCenter</apiType></about></returnval></RetrieveServiceContentResponse>`)
	}))
	defer srv.Close()
	old := sdkURL
	sdkURL = func(string) string { return srv.URL + "/sdk" }
	defer func() { sdkURL = old }()
	if _, err := run(t, "detect", modules.Login{Username: "root", Password: "x"}); err == nil || !strings.Contains(err.Error(), "not an ESXi host") {
		t.Errorf("a vCenter: %v", err)
	}
	sdkURL = func(string) string { return "https://127.0.0.1:1/sdk" }
	if _, err := run(t, "detect", modules.Login{}); err == nil || errors.Is(err, modules.ErrLoginRejected) {
		t.Errorf("no API: %v, want an error that is no refused login", err)
	}
}

func TestEnableSNMP(t *testing.T) {
	h, done := newFakeHost(t)
	defer done()
	r, err := run(t, "enable-snmp", modules.Login{Username: "root", Password: h.pass})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"SNMP agent enabled on port 161, communities: monitor, public", "firewall rule 'snmp' opened", "snmpd set to start with the host", "snmpd started"}
	if !slices.Equal(r.Changes, want) {
		t.Errorf("changes %q, want %q", r.Changes, want)
	}
	h.mu.Lock()
	spec := h.bodies["ReconfigureSnmpAgent"]
	h.mu.Unlock()
	for _, part := range []string{"<enabled>true</enabled>", "<port>161</port>", "<readOnlyCommunities>monitor</readOnlyCommunities><readOnlyCommunities>public</readOnlyCommunities>",
		"<trapTargets><hostName>10.9.0.9</hostName><port>162</port><community>traps</community></trapTargets>", `<_this type="HostSnmpSystem">ha-snmp-agent</_this>`} {
		if !strings.Contains(spec, part) {
			t.Errorf("the SNMP spec lacks %q:\n%s", part, spec)
		}
	}
	calls := h.called()
	for _, m := range []string{"ReconfigureSnmpAgent", "EnableRuleset", "UpdateServicePolicy", "StartService"} {
		if !slices.Contains(calls, m) {
			t.Errorf("calls %v lack %s", calls, m)
		}
	}
	if slices.Contains(calls, "RestartService") {
		t.Errorf("a stopped snmpd was restarted, not started: %v", calls)
	}
}

func TestEnableSNMPNothingToDo(t *testing.T) {
	h, done := newFakeHost(t)
	defer done()
	h.snmp = `<enabled>true</enabled><port>161</port><readOnlyCommunities>public</readOnlyCommunities>`
	h.firewall = `<ruleset><key>snmp</key><enabled>true</enabled></ruleset>`
	h.service = `<service><key>snmpd</key><running>true</running><policy>on</policy></service>`
	r, err := run(t, "enable-snmp", modules.Login{Username: "root", Password: h.pass})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Changes, []string{"SNMP agent already enabled with community public"}) {
		t.Errorf("changes %q", r.Changes)
	}
	for _, m := range []string{"ReconfigureSnmpAgent", "EnableRuleset", "UpdateServicePolicy", "StartService", "RestartService"} {
		if slices.Contains(h.called(), m) {
			t.Errorf("%s called on a host with SNMP on", m)
		}
	}
}

func TestEnableSNMPFreeLicense(t *testing.T) {
	h, done := newFakeHost(t)
	defer done()
	h.restricted = true
	_, err := run(t, "enable-snmp", modules.Login{Username: "root", Password: h.pass})
	if err == nil || !strings.Contains(err.Error(), "free vSphere Hypervisor") || !strings.Contains(err.Error(), "esxcli system snmp set --communities public --enable true") {
		t.Fatalf("a free license: %v", err)
	}
	if slices.Contains(h.called(), "EnableRuleset") {
		t.Error("the firewall was changed after the agent was refused")
	}
}
