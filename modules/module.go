// Package modules holds the device modules: one per kind of device (ESXi
// hosts, a UniFi controller, ...), each in its own directory
// (modules/esxi, ...), registered from its init function and loaded by a
// blank import in the scanner (device_modules.go).
//
// A module logs in to one device with a login of the Credentials window
// and runs one of its actions there: detect (read what the device tells of
// itself) or a change such as enabling SNMP. The scanner decides which
// devices are of a module's kind (Type) and which logins to try, in which
// order; a module only talks to the device it is given.
package modules

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
)

// Login is one login of the Credentials window, decrypted.
type Login struct {
	Username string
	Password string
}

// Action is something a module does on a device.
type Action struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Changes marks an action that changes the device's configuration;
	// the UI asks Confirm first
	Changes bool   `json:"changes"`
	Confirm string `json:"confirm,omitempty"`
	// VerifySNMP asks the scanner to poll the device with its community
	// after the action, and to show what it answered
	VerifySNMP bool `json:"verifySNMP,omitempty"`
}

// Request is one action to run on the device at IP with Login.
type Request struct {
	IP     string
	Action string
	Login  Login
	// Others are the device's other logins of the protocol, in the order
	// they are tried, for a module that needs a second kind of login (a
	// UniFi controller's local user, besides its API key)
	Others []Login
	// Community is the SNMP community the scanner polls with, for an
	// action that sets the device's SNMP
	Community string
}

// Result is what an action found or changed, as the UI shows it.
type Result struct {
	Summary string   `json:"summary"`
	Facts   []Fact   `json:"facts,omitempty"`
	Tables  []Table  `json:"tables,omitempty"`
	Changes []string `json:"changes,omitempty"`
}

// Fact is one label and value of a result.
type Fact struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Table is a list of a result (network ports, virtual machines, ...).
type Table struct {
	Title   string     `json:"title"`
	Columns []string   `json:"columns"`
	Rows    [][]string `json:"rows"`
}

// AddFact adds a fact, unless its value is empty.
func (r *Result) AddFact(label, value string) {
	if value != "" {
		r.Facts = append(r.Facts, Fact{label, value})
	}
}

// ErrLoginRejected wraps the error of a device that refused the login: the
// scanner then tries the next login. Any other error ends the action.
var ErrLoginRejected = errors.New("login rejected")

// Module is one kind of device.
type Module interface {
	ID() string    // "esxi"
	Label() string // "VMware ESXi"
	// Type is the device type the module serves, one of the Credentials
	// window's device types; the scanner gives it the devices of that type
	Type() string
	// Protocol is the protocol of the logins it uses ("vsphere")
	Protocol() string
	Actions() []Action
	Run(ctx context.Context, req Request) (Result, error)
}

// Prober is a module that recognizes its devices itself, with no login
// (a UniFi controller answers its status page): the scanner asks it about
// a device whose type it does not know from its own data. Probe must be
// quick (a few seconds at most) and change nothing.
type Prober interface {
	Probe(ctx context.Context, ip string) bool
}

// Inventory is what a device that manages others (a UniFi controller
// manages its access points and switches) tells of them, for the
// scanner's graph and tree: the devices, by MAC, with their clients.
type Inventory struct {
	Devices []ManagedDevice `json:"devices"`
	// Notes say what could not be read, the rest being there ("client
	// details: ..."); the scanner logs them
	Notes []string `json:"notes,omitempty"`
}

// ManagedDevice is one device of an Inventory.
type ManagedDevice struct {
	MAC      string `json:"mac"` // "70:a7:41:a8:a2:ff"
	Name     string `json:"name"`
	Model    string `json:"model,omitempty"`
	IP       string `json:"ip,omitempty"`
	State    string `json:"state,omitempty"` // "ONLINE", "OFFLINE", ...
	Firmware string `json:"firmware,omitempty"`
	// Kind is "access_point", "switch", "gateway" or "hypervisor", "" when
	// unknown
	Kind string `json:"kind,omitempty"`
	// Uplink is the device it is connected through, nil when unknown
	Uplink  *ManagedUplink  `json:"uplink,omitempty"`
	Clients []ManagedClient `json:"clients,omitempty"`
}

// ManagedUplink is the link of a managed device to the device it is
// connected through.
type ManagedUplink struct {
	// MAC is that device's: a switch's chassis MAC (its LLDP), the UniFi
	// switch's, or the access point's of a mesh link
	MAC       string `json:"mac"`
	Port      string `json:"port,omitempty"`      // its port, "GigabitEthernet1/0/10" or "5"
	LocalPort string `json:"localPort,omitempty"` // the device's own, "eth0"
	Wireless  bool   `json:"wireless,omitempty"`  // a mesh link
}

// ManagedClient is a client connected to a managed device: a Wi-Fi client
// of an access point, a virtual machine's NIC on its host. The fields after
// Kind are what the controller tells of it, when it can (a UniFi
// controller's older API, a vCenter): zero when unknown.
type ManagedClient struct {
	MAC  string `json:"mac"`
	Name string `json:"name,omitempty"`
	IP   string `json:"ip,omitempty"`
	Kind string `json:"kind,omitempty"` // "wireless", "wired", "vm", ...

	Hostname     string `json:"hostname,omitempty"` // the name it gave DHCP
	Vendor       string `json:"vendor,omitempty"`
	SSID         string `json:"ssid,omitempty"`
	Network      string `json:"network,omitempty"` // the controller's network (VLAN) name
	VLAN         int    `json:"vlan,omitempty"`
	Band         string `json:"band,omitempty"` // "2.4 GHz", "5 GHz", "6 GHz"
	Channel      int    `json:"channel,omitempty"`
	Standard     string `json:"standard,omitempty"` // "Wi-Fi 6 (ax)"
	Signal       int    `json:"signal,omitempty"`   // dBm, "-61"
	RxRate       int    `json:"rxRate,omitempty"`   // Mbit/s, of the last frames
	TxRate       int    `json:"txRate,omitempty"`
	RxBytes      int64  `json:"rxBytes,omitempty"` // since it connected
	TxBytes      int64  `json:"txBytes,omitempty"`
	Uptime       int64  `json:"uptime,omitempty"`       // seconds connected
	Satisfaction int    `json:"satisfaction,omitempty"` // the controller's 0-100 score
	OS           string `json:"os,omitempty"`           // a VM's guest OS, "Ubuntu Linux (64-bit)"
	Power        string `json:"power,omitempty"`        // a VM's "On", "Off", "Suspended"
	// Gateway is the scanner's, not the controller's: the gateway whose
	// ARP table has the client, "pfSense.home.arpa 172.15.1.254"
	Gateway string `json:"gateway,omitempty"`
}

// Inventorier is a module whose devices report the devices they manage;
// the scanner reads the inventory every few minutes with the device's
// login, as it runs an action.
type Inventorier interface {
	Inventory(ctx context.Context, req Request) (Inventory, error)
}

var (
	registryMu sync.Mutex
	registry   []Module
)

// Register adds a module; a module calls it from its init function.
func Register(m Module) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = append(registry, m)
}

// All returns the registered modules in ID order.
func All() []Module {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := slices.Clone(registry)
	slices.SortFunc(out, func(a, b Module) int { return strings.Compare(a.ID(), b.ID()) })
	return out
}

// Find returns the module with id, or nil.
func Find(id string) Module {
	for _, m := range All() {
		if m.ID() == id {
			return m
		}
	}
	return nil
}

// ActionOf returns a module's action with id.
func ActionOf(m Module, id string) (Action, bool) {
	i := slices.IndexFunc(m.Actions(), func(a Action) bool { return a.ID == id })
	if i < 0 {
		return Action{}, false
	}
	return m.Actions()[i], true
}
