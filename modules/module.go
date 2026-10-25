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
