package main

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Switch qualification. On 2026-10-22 the graph got isolated "switch" nodes
// for devices that are no switches. LLDP discovery added most of them: F62
// had made the LLDP management addresses readable, the capability filter
// (lldpDiscoverable) let the UniFi U6-Pro access points through (they
// enable bridge, not wlanAccessPoint), and their polls were a partial
// success (IF-MIB and ARP answer, the switch tables "No Such Object"), so
// storeCollectedDevice kept them and 47 lines were appended to swich_ips:
// 46 access points (172.15.1.x) and 172.15.101.0. The rescue scan polled
// every alive IP of the swich_ips ranges, so the FortiGate-600F firewall
// 172.20.0.1 and the ESXi host 172.20.0.67 became nodes the same way. SNMP
// on the gateway 172.20.1.254 played no part: the gateway did not answer
// at that start, so subnet discovery found no subnet.
//
// A device is a switch only when its agent shows a switch MIB: BRIDGE-MIB
// with at least one port (dot1dBaseNumPorts > 0) or LLDP-MIB's local
// chassis id (lldpLocChassisId). Every path that adds a device on its own
// asks checkSwitch before it polls or lists the device: subnet discovery,
// LLDP discovery, the rescue scan, the first scan and the UI rescan.
// storeCollectedDevice applies the same rule (switchMIBs.isSwitch) to what
// the poll of a device it has never stored read. The SNMP devices of the
// swich_ips ranges that fail it stay ARP sources (addARPSource).

// OIDs of the qualification. Both are scalars: snmpbulkwalk answers them
// with the value, or with "No Such Object" when the MIB is absent.
const (
	oidDot1dBaseNumPorts = ".1.3.6.1.2.1.17.1.2.0"   // BRIDGE-MIB dot1dBaseNumPorts
	oidLLDPLocChassisID  = ".1.0.8802.1.1.2.1.3.2.0" // LLDP-MIB lldpLocChassisId
	oidSysDescr          = ".1.3.6.1.2.1.1.1.0"
	oidSysName           = ".1.3.6.1.2.1.1.5.0"
)

// errNoLocalChassis is the lldpLocChassisId read of an agent that answered
// without a chassis id (exception text, no value): collectLocalChassisID
// wraps it, unlike the walk error of an agent that did not answer.
var errNoLocalChassis = errors.New("no lldpLocChassisId")

// switchMIBs is what an agent shows of the two switch MIBs.
type switchMIBs struct {
	BridgePorts int  // dot1dBaseNumPorts; 0 when absent or unreadable
	LLDPChassis bool // lldpLocChassisId holds a chassis id
}

// isSwitch is the qualification rule: BRIDGE-MIB with at least one port, or
// LLDP-MIB with a local chassis id.
func (m switchMIBs) isSwitch() bool {
	return m.BridgePorts > 0 || m.LLDPChassis
}

// String names the switch MIBs found, for log lines.
func (m switchMIBs) String() string {
	var found []string
	if m.BridgePorts > 0 {
		found = append(found, fmt.Sprintf("BRIDGE-MIB %d ports", m.BridgePorts))
	}
	if m.LLDPChassis {
		found = append(found, "LLDP-MIB chassis id")
	}
	if len(found) == 0 {
		return "no switch MIB"
	}
	return strings.Join(found, ", ")
}

// switchCheck is the qualification of one device: what its agent shows of
// the switch MIBs and, for a device that answered but is no switch, its
// sysName and sysDescr for the skip summary.
type switchCheck struct {
	IP       string
	SysName  string
	SysDescr string
	Answered bool // the agent answered SNMP at all
	switchMIBs
}

// checkSwitch is the qualification check of every automatic add path. It
// reads lldpLocChassisId and dot1dBaseNumPorts of ip at the same time (an
// agent that answers neither costs one timeout, not two), and sysName and
// sysDescr only of a device that answered and is no switch.
func (s *SNMPObject) checkSwitch(ip string) switchCheck {
	c := switchCheck{IP: ip}
	var chassisID string
	var chassisErr, portsErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		chassisID, chassisErr = s.collectLocalChassisID(ip)
	}()
	go func() {
		defer wg.Done()
		c.BridgePorts, portsErr = s.collectBaseNumPorts(ip)
	}()
	wg.Wait()
	c.LLDPChassis = chassisErr == nil && chassisID != ""
	c.Answered = chassisErr == nil || errors.Is(chassisErr, errNoLocalChassis) || portsErr == nil
	if c.Answered && !c.isSwitch() {
		c.SysName = s.collectSysText(ip, oidSysName)
		c.SysDescr = s.collectSysText(ip, oidSysDescr)
	}
	return c
}

// collectBaseNumPorts reads BRIDGE-MIB dot1dBaseNumPorts, the number of
// ports of the agent's bridge: 0 when the agent has no BRIDGE-MIB ("No Such
// Object") or the value is no number. err is the walk error of an agent
// that did not answer.
func (s *SNMPObject) collectBaseNumPorts(ip string) (int, error) {
	lines, err := s.runSNMPWalk(ip, oidDot1dBaseNumPorts)
	if err != nil {
		return 0, err
	}
	for _, line := range lines {
		oid, _, val, ok := collectSNMPValue(line)
		if !ok || strings.TrimPrefix(oid, ".") != strings.TrimPrefix(oidDot1dBaseNumPorts, ".") {
			continue
		}
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			return n, nil
		}
	}
	return 0, nil
}

// collectSysText reads sysName or sysDescr as plain text: the first line of
// the value without quotes, "" when the agent has none.
func (s *SNMPObject) collectSysText(ip, oid string) string {
	lines, err := s.runSNMPWalk(ip, oid)
	if err != nil || len(lines) == 0 {
		return ""
	}
	_, _, val, ok := collectSNMPValue(lines[0])
	if !ok || graphIsSNMPException(val) {
		return ""
	}
	return strings.TrimSpace(strings.Trim(val, "\""))
}

// ARP sources. The MAC-IP sweeps (collectARPFromAllSwitches) read the ARP
// tables of the gateway and of the stored switches. Before checkSwitch the
// rescue scan stored every SNMP device it found alive in the swich_ips
// ranges, so the sweeps read their ARP tables too, and one of them counts:
// on 2026-10-22 the FortiGate-600F 172.20.0.1 had 1,229 MACs in its ARP
// table, 1,066 of which were in neither the gateway 172.20.1.254's table
// nor the saved switch tables. Unread, those MAC-IP entries would expire
// (collectMACIPTTL). So an SNMP device of the ranges that checkSwitch
// rejects (in the rescue scan, the first scan or the UI rescan) is kept as
// an ARP source while swich_ips lists it (keepARPSources): it is never
// polled, stored or drawn, and every sweep reads its ARP table. The
// devices that LLDP and subnet discovery reject are no ARP sources: the
// owner did not list them, and every printer of the gateway's subnets
// would be one.
var (
	arpSourcesMu sync.Mutex
	arpSources   = make(map[string]bool)
)

// addARPSource keeps the device of c as an ARP source when it answered SNMP
// and is no switch.
func addARPSource(c switchCheck) {
	if !c.Answered || c.isSwitch() {
		return
	}
	arpSourcesMu.Lock()
	arpSources[c.IP] = true
	arpSourcesMu.Unlock()
}

// keepARPSources drops the ARP sources that are not in listed, the IPs of
// the swich_ips lines (rescueScan): a device stays an ARP source only while
// the owner lists it.
func keepARPSources(listed map[string]bool) {
	arpSourcesMu.Lock()
	maps.DeleteFunc(arpSources, func(ip string, _ bool) bool { return !listed[ip] })
	arpSourcesMu.Unlock()
}

// arpSourceIPs returns the ARP sources in IP order.
func arpSourceIPs() []string {
	arpSourcesMu.Lock()
	defer arpSourcesMu.Unlock()
	return slices.SortedFunc(maps.Keys(arpSources), compareIPs)
}

// switchSkipExamples is how many devices a skip summary names.
const switchSkipExamples = 3

// switchSkips collects the devices that one run of an add path did not add
// because they are no switches, for one summary line per run instead of a
// line per device. It is safe for concurrent use.
type switchSkips struct {
	mu     sync.Mutex
	checks []switchCheck
}

// add records a device that failed checkSwitch.
func (k *switchSkips) add(c switchCheck) {
	k.mu.Lock()
	k.checks = append(k.checks, c)
	k.mu.Unlock()
}

// count is the number of devices recorded.
func (k *switchSkips) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.checks)
}

// summary is the run's one log line about the devices not added ("" when
// there are none), tagged like the run's other lines: how many answered
// SNMP without a switch MIB, a few of them with sysName and sysDescr
// (different device types first), and how many did not answer SNMP.
func (k *switchSkips) summary(tag string) string {
	k.mu.Lock()
	checks := slices.Clone(k.checks)
	k.mu.Unlock()
	slices.SortFunc(checks, func(a, b switchCheck) int { return compareIPs(a.IP, b.IP) })
	var others, silent []switchCheck
	for _, c := range checks {
		if c.Answered {
			others = append(others, c)
		} else {
			silent = append(silent, c)
		}
	}
	var parts []string
	if len(others) > 0 {
		var names []string
		for _, c := range switchSkipPick(others) {
			names = append(names, c.describe())
		}
		parts = append(parts, fmt.Sprintf("%s without BRIDGE-MIB ports or lldpLocChassisId (no switch): %s",
			switchSkipCount(len(others), "device"), switchSkipList(names, len(others))))
	}
	if len(silent) > 0 {
		var ips []string
		for _, c := range silent[:min(len(silent), switchSkipExamples)] {
			ips = append(ips, c.IP)
		}
		parts = append(parts, fmt.Sprintf("%s did not answer SNMP: %s",
			switchSkipCount(len(silent), "host"), switchSkipList(ips, len(silent))))
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf("🚫 [%s] Not added: %s", tag, strings.Join(parts, "; "))
}

// print writes the summary line of the run, if there is one.
func (k *switchSkips) print(tag string) {
	if line := k.summary(tag); line != "" {
		fmt.Println(line)
	}
}

// switchSkipPick chooses the examples of a summary from checks (in IP
// order): the first device of each device type (sysDescr, or sysName
// without one), then the next devices in IP order; returned in IP order.
func switchSkipPick(checks []switchCheck) []switchCheck {
	picked := make([]bool, len(checks))
	n := 0
	types := map[string]bool{}
	for i, c := range checks {
		key := c.SysDescr
		if key == "" {
			key = c.SysName
		}
		if n < switchSkipExamples && !types[key] {
			types[key] = true
			picked[i] = true
			n++
		}
	}
	for i := range checks {
		if n < switchSkipExamples && !picked[i] {
			picked[i] = true
			n++
		}
	}
	var out []switchCheck
	for i, c := range checks {
		if picked[i] {
			out = append(out, c)
		}
	}
	return out
}

// describe is a skipped device in a summary: its IP with sysName and the
// start of sysDescr.
func (c switchCheck) describe() string {
	var names []string
	if c.SysName != "" {
		names = append(names, c.SysName)
	}
	if descr := []rune(c.SysDescr); len(descr) > 60 {
		names = append(names, string(descr[:60])+"…")
	} else if len(descr) > 0 {
		names = append(names, c.SysDescr)
	}
	if len(names) == 0 {
		return c.IP
	}
	return fmt.Sprintf("%s (%s)", c.IP, strings.Join(names, ", "))
}

// switchSkipCount is "1 device", "2 devices".
func switchSkipCount(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// switchSkipList joins the named items of a summary and says how many of
// the total are left out.
func switchSkipList(items []string, total int) string {
	list := strings.Join(items, ", ")
	if rest := total - len(items); rest > 0 {
		list += fmt.Sprintf(" and %d more", rest)
	}
	return list
}
