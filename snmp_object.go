package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// InterfaceData holds interface statistics from IF-MIB
type InterfaceData struct {
	IfIndex       int
	IfDescr       string
	IfAlias       string // Port description (ifAlias, OID .1.3.6.1.2.1.31.1.1.1.18)
	IfType        int
	IfMtu         int
	IfSpeed       uint64
	IfPhysAddress string
	IfAdminStatus int
	IfOperStatus  int
	IfInOctets    uint64 // Incoming bytes counter
	IfOutOctets   uint64 // Outgoing bytes counter
	// Diagnostic counters
	IfInErrors    uint64 // Input errors (CRC, frame errors)
	IfOutErrors   uint64 // Output errors
	IfInDiscards  uint64 // Input discards (buffer full)
	IfOutDiscards uint64 // Output discards (congestion)
}

// LLDPNeighbor holds LLDP remote neighbor information
type LLDPNeighbor struct {
	TimeMarker          int
	LocalPortNum        int
	RemIndex            int
	RemChassisIdSubtype int
	RemChassisId        string
	RemPortIdSubtype    int
	RemPortId           string
	RemPortDesc         string
	RemSysName          string
	RemSysDesc          string
	RemMgmtIP           string // Management IP address from lldpRemManAddrTable
	// RemSysCapEnabled is the first octet of lldpRemSysCapEnabled (see
	// lldpCapabilities); 0 when unknown or none
	RemSysCapEnabled uint8 `json:"RemSysCapEnabled,omitempty"`
	// Management Address fields (raw)
	RemManAddrIfSubtype int
	RemManAddrIfId      int
	RemManAddrOID       string
}

// MACEntry holds MAC address table entry from BRIDGE-MIB
type MACEntry struct {
	MACAddress string
	PortNumber int
	VlanID     int
	Status     string // learned, self, mgmt, other, invalid
}

// ARPEntry holds ARP table entry (IP to MAC mapping)
type ARPEntry struct {
	IPAddress  string
	MACAddress string
	Interface  int
}

// PortVLAN holds VLAN information for a port
type PortVLAN struct {
	PortIndex int
	PVID      int   // Native/Access VLAN ID
	IsTrunk   bool  // True if trunk port
	VLANs     []int // Tagged VLANs (for trunk)
}

// DeviceData holds all collected data from a device
type DeviceData struct {
	IP          string
	SysName     string
	ChassisID   string // Unique identifier (MAC address)
	Interfaces  []InterfaceData
	Neighbors   []LLDPNeighbor
	MACTable    []MACEntry // MAC address table entries
	ARPTable    []ARPEntry // ARP table (IP to MAC mappings)
	PortVLANs   []PortVLAN // Port VLAN configuration
	STPInfo     STPData    // Spanning Tree Protocol details
	Timestamp   time.Time
	Unreachable bool      `json:"unreachable,omitempty"` // Phase 8: true = SNMP timeout, device is down
	LastSeen    time.Time `json:"lastSeen,omitempty"`    // Phase 8: last successful SNMP poll time
	// MACEntry.PortNumber is a dot1dBasePort; this maps it to the ifIndex
	// (dot1dBasePortIfIndex). Nil when the switch did not report it.
	BridgePortIfIndex map[int]int `json:"bridgePortIfIndex,omitempty"`

	// Walks that failed in the poll that produced this data (not saved).
	failedWalks []string
	// The switch MIBs this poll found (not saved): storeCollectedDevice
	// stores a device it has never stored only when they make it a switch.
	polledMIBs switchMIBs
}

// Parts of one CollectData poll, as recorded in DeviceData.failedWalks.
const (
	collectWalkInterfaces  = "interfaces"
	collectWalkLLDP        = "lldp"
	collectWalkFDB         = "fdb"
	collectWalkBridgePorts = "bridge ports"
	collectWalkARP         = "arp"
	collectWalkVLAN        = "vlan"
	collectWalkSTP         = "stp"
)

// collectWalkFailed reports whether the walk of part failed in the poll
// that produced d.
func (d *DeviceData) collectWalkFailed(part string) bool {
	return slices.Contains(d.failedWalks, part)
}

// collectKeepPrevious fills the tables of data whose walk failed (a partial
// success) from prev, the stored data of the same switch, so one timed-out
// walk does not empty a table until the next poll (F57: every MAC of the
// switch would LEAVE, then JOIN again five minutes later). A walk that
// answered with no rows is not a failure. The chassis id is not tracked or
// carried over (its read decides the switch identity).
func collectKeepPrevious(data, prev *DeviceData) {
	if prev == nil || prev == data {
		return
	}
	for _, part := range data.failedWalks {
		switch part {
		case collectWalkInterfaces:
			data.Interfaces = prev.Interfaces
		case collectWalkLLDP:
			data.Neighbors = prev.Neighbors
		case collectWalkFDB:
			data.MACTable = prev.MACTable
			data.BridgePortIfIndex = prev.BridgePortIfIndex
		case collectWalkBridgePorts:
			data.BridgePortIfIndex = prev.BridgePortIfIndex
		case collectWalkARP:
			data.ARPTable = prev.ARPTable
		case collectWalkVLAN:
			data.PortVLANs = prev.PortVLANs
		case collectWalkSTP:
			data.STPInfo = prev.STPInfo
		}
	}
}

// collectBasePortIfIndexOID is dot1dBasePortIfIndex.<bridge port> = ifIndex.
const collectBasePortIfIndexOID = ".1.3.6.1.2.1.17.1.4.1.2"

// collectFDBIfIndex returns the ifIndex of FDB bridge port bridgePort, for
// port names (getLocalPortName). When the switch did not report the mapping
// the bridge port number is used as the ifIndex, the old assumption (true on
// switches that number both alike, such as the HPE and SNR ones here).
func collectFDBIfIndex(data *DeviceData, bridgePort int) int {
	if ifIndex, ok := data.BridgePortIfIndex[bridgePort]; ok && ifIndex > 0 {
		return ifIndex
	}
	return bridgePort
}

// collectBridgePortIfIndex walks dot1dBasePortIfIndex (bridge port → ifIndex).
// It returns nil when the walk fails or reports nothing.
func (s *SNMPObject) collectBridgePortIfIndex(ip string) (map[int]int, error) {
	lines, err := s.runSNMPWalk(ip, collectBasePortIfIndexOID)
	if err != nil {
		return nil, err
	}
	var ports map[int]int
	for _, line := range lines {
		oid, val, err := parseSNMPLine(line)
		if err != nil {
			continue
		}
		idx, ok := collectOIDIndex(oid, collectBasePortIfIndexOID)
		ifIndex, convErr := strconv.Atoi(val)
		if !ok || len(idx) != 1 || convErr != nil || ifIndex <= 0 {
			continue
		}
		if ports == nil {
			ports = make(map[int]int)
		}
		ports[idx[0]] = ifIndex
	}
	return ports, nil
}

// STPData holds Spanning Tree Protocol information
type STPData struct {
	Enabled       bool
	Protocol      string // "rstp", "stp", "mstp"
	RootBridgeID  string
	RootCost      int
	RootPort      int
	BridgeID      string // This device's Bridge ID
}

// SNMPObject handles detailed SNMP data collection using system snmpwalk
type SNMPObject struct {
	Community string
	Port      uint16
	// Timeout and Retries are the -t and -r of every walk of the object
	// (walkTiming); a zero Timeout means pollTiming. (They were not passed
	// on until 2026-10-22: every walk ran with -t 5 -r 1.)
	Timeout   time.Duration
	Retries   int
	OnSuccess func(data *DeviceData)
	OnFailure func(ip string, err error)
}

// NewSNMPObject creates a new SNMPObject with the poll timing (pollTiming)
func NewSNMPObject(onSuccess func(*DeviceData), onFailure func(string, error)) *SNMPObject {
	return &SNMPObject{
		Community: "public",
		Port:      161,
		Timeout:   pollTiming.Timeout,
		Retries:   pollTiming.Retries,
		OnSuccess: onSuccess,
		OnFailure: onFailure,
	}
}

// walkTiming is how long one snmpbulkwalk waits for the agent: Timeout per
// request (-t, in whole seconds, at least 1) and Retries (-r). Unordered
// walks a table that an agent may return out of OID order (-Cc, see
// collectMACTable); such a walk stops when the agent repeats an OID
// (snmpWalkOutput).
type walkTiming struct {
	Timeout   time.Duration
	Retries   int
	Unordered bool
}

// pollTiming is the timing of the polls, the ARP sweeps and checkSwitch: 5 s
// and one retry, so an agent that does not answer costs 10 s per walk.
var pollTiming = walkTiming{Timeout: 5 * time.Second, Retries: 1}

// timing is the walk timing of s: its Timeout and Retries, or pollTiming
// when Timeout is not set.
func (s *SNMPObject) timing() walkTiming {
	if s.Timeout <= 0 {
		return pollTiming
	}
	return walkTiming{Timeout: s.Timeout, Retries: max(s.Retries, 0)}
}

// CollectData starts the data collection process
func (s *SNMPObject) CollectData(ip, sysName string) {
	data := &DeviceData{
		IP:      ip,
		SysName: sysName,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	// 1. Collect Local Chassis ID
	wg.Add(1)
	go func() {
		defer wg.Done()
		chassisID, err := s.collectLocalChassisID(ip)
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("chassisID err: %v", err))
			mu.Unlock()
		} else {
			mu.Lock()
			data.ChassisID = chassisID
			data.polledMIBs.LLDPChassis = chassisID != ""
			mu.Unlock()
		}
	}()

	// The BRIDGE-MIB port count, for the switch qualification of a device
	// that was never stored (storeCollectedDevice). Optional: a failure is
	// no failed walk and does not count among the jobs below.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ports, _ := s.collectBaseNumPorts(ip)
		mu.Lock()
		data.polledMIBs.BridgePorts = ports
		mu.Unlock()
	}()

	// The sysName, when the caller has none: the rescue scan and LLDP
	// discovery poll with "", and the periodic rescan passes the stored
	// name, so a switch they added kept no name (172.20.230.40, .44, .47,
	// .76, .77, .81, .253 and 172.20.254.203 in the saved data of
	// 2026-10-20; their agents answer sysName.0: "Switch", "SNR-S2985G-24TC",
	// "HPE", "6300"...). A name the caller has is kept as it is. Optional
	// like the port count: when it gives none, storeCollectedDevice keeps
	// the stored name (keepPreviousSysName).
	if sysName == "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := s.collectSysText(ip, oidSysName)
			mu.Lock()
			data.SysName = name
			mu.Unlock()
		}()
	}

	// 2. Collect Interface Data (Full walk of IF-MIB)
	// Minimally implemented for speed since LLDP is priority
	wg.Add(1)
	go func() {
		defer wg.Done()
		ifaces, err := s.collectInterfaces(ip)
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("interfaces err: %v", err))
			data.failedWalks = append(data.failedWalks, collectWalkInterfaces)
			mu.Unlock()
		} else {
			mu.Lock()
			data.Interfaces = ifaces
			mu.Unlock()
		}
	}()

	// 3. Collect LLDP Neighbors
	wg.Add(1)
	go func() {
		defer wg.Done()
		neighbors, err := s.collectLLDPNeighbors(ip)
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("lldp err: %v", err))
			data.failedWalks = append(data.failedWalks, collectWalkLLDP)
			mu.Unlock()
		} else {
			mu.Lock()
			data.Neighbors = neighbors
			mu.Unlock()
		}
	}()

	// 4. Collect MAC Address Table (FDB)
	wg.Add(1)
	go func() {
		defer wg.Done()
		macTable, err := s.collectMACTable(ip)
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("mac table err: %v", err))
			data.failedWalks = append(data.failedWalks, collectWalkFDB)
			mu.Unlock()
		} else {
			// The FDB reports bridge ports; their ifIndex names the port (F60).
			// Optional: without it the bridge port is used as the ifIndex.
			bridgePorts, bpErr := s.collectBridgePortIfIndex(ip)
			mu.Lock()
			data.MACTable = macTable
			data.BridgePortIfIndex = bridgePorts
			if bpErr != nil {
				data.failedWalks = append(data.failedWalks, collectWalkBridgePorts)
			}
			mu.Unlock()
		}
	}()

	// 5. Collect ARP Table (IP to MAC mapping)
	wg.Add(1)
	go func() {
		defer wg.Done()
		arpTable, err := s.collectARPTable(ip)
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("arp table err: %v", err))
			data.failedWalks = append(data.failedWalks, collectWalkARP)
			mu.Unlock()
		} else {
			mu.Lock()
			data.ARPTable = arpTable
			mu.Unlock()
		}
	}()

	// 6. Collect Port VLAN Configuration: with the other walks, or after
	// them for an agent whose VLAN egress walk failed in its last poll
	// (collectVLANLast)
	vlanJob := func() {
		portVLANs, err := s.collectPortVLANs(ip)
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("vlan err: %v", err))
			data.failedWalks = append(data.failedWalks, collectWalkVLAN)
			mu.Unlock()
		} else {
			mu.Lock()
			data.PortVLANs = portVLANs
			mu.Unlock()
		}
	}
	vlanLast := collectVLANLast(ip)
	if !vlanLast {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vlanJob()
		}()
	}

	// 7. Collect STP Information
	wg.Add(1)
	go func() {
		defer wg.Done()
		stpInfo, err := s.collectSTPInfo(ip)
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("stp err: %v", err))
			data.failedWalks = append(data.failedWalks, collectWalkSTP)
			mu.Unlock()
		} else {
			mu.Lock()
			data.STPInfo = stpInfo
			mu.Unlock()
		}
	}()



	wg.Wait()
	if vlanLast {
		vlanJob()
	}

	// Phase 8: Count total parallel SNMP jobs (ChassisID, Interfaces, LLDP, MAC, ARP, VLAN, STP)
	const totalJobs = 7
	if len(errs) >= totalJobs {
		// ALL SNMP walks failed — device is unreachable
		// Do NOT call OnSuccess with empty data (would overwrite good cached data)
		if s.OnFailure != nil {
			s.OnFailure(ip, fmt.Errorf("all %d SNMP walks failed for %s", totalJobs, ip))
		}
		return
	}

	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Printf("Error collecting %s: %v\n", ip, e)
		}
	}

	// Partial or full success — deliver data. The callback keeps the tables
	// of failed walks from the previous poll (collectKeepPrevious).
	data.Timestamp = time.Now()
	if s.OnSuccess != nil {
		s.OnSuccess(data)
	}
}

// snmpWalk runs one SNMP walk for runSNMPWalk, with the object's timing.
// Tests replace it with a fake agent so no SNMP request is sent.
var snmpWalk = snmpBulkWalk

// snmpProbeWalk runs the walk that asks a host whether it runs SNMP at all
// (subnet discovery's sysDescr probe, with the run's short probe timing,
// subnetDiscoveryLimits.Probe). Tests replace it like snmpWalk.
var snmpProbeWalk = snmpBulkWalk

// runSNMPWalk runs one snmpbulkwalk of oid on ip with the timing of s
// (killed after 30s) and returns its lines.
func (s *SNMPObject) runSNMPWalk(ip, oid string) ([]string, error) {
	return snmpWalk(s.Community, ip, oid, s.timing())
}

// runSNMPWalkUnordered is runSNMPWalk for a table that some agents return
// out of OID order (walkTiming.Unordered).
func (s *SNMPObject) runSNMPWalkUnordered(ip, oid string) ([]string, error) {
	timing := s.timing()
	timing.Unordered = true
	return snmpWalk(s.Community, ip, oid, timing)
}

// snmpBulkWalkArgs are the snmpbulkwalk arguments of one walk: SNMP v2c,
// numeric OIDs, 25 repetitions per request, -Cc for an unordered walk, and
// timing as -t (whole seconds, at least 1) and -r.
func snmpBulkWalkArgs(community, ip, oid string, timing walkTiming) []string {
	seconds := max(int(timing.Timeout.Round(time.Second)/time.Second), 1)
	args := []string{"-v2c", "-c", community, "-On", "-Cr25"}
	if timing.Unordered {
		args = append(args, "-Cc")
	}
	return append(args, "-t", strconv.Itoa(seconds), "-r", strconv.Itoa(max(timing.Retries, 0)), ip, oid)
}

// snmpBulkWalk runs snmpbulkwalk with timing (snmpBulkWalkArgs; killed
// after 30s, or when an unordered walk repeats an OID) and returns its
// lines. A walk that exits with an error returns no lines: net-snmp exits
// with 1 when the agent's rows come out of OID order ("OID not increasing"),
// which is why the FDB is walked unordered.
func snmpBulkWalk(community, ip, oid string, timing walkTiming) ([]string, error) {
	cmd := exec.Command("snmpbulkwalk", snmpBulkWalkArgs(community, ip, oid, timing)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stderr = nil
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Manual timeout: kill process group after 30s
	kill := func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	timer := time.AfterFunc(30*time.Second, kill)
	lines, readErr := snmpWalkOutput(stdout, timing.Unordered, kill)
	err = cmd.Wait() // after the whole output is read: Wait closes the pipe
	timer.Stop()

	if readErr != nil {
		return nil, fmt.Errorf("snmpwalk of %s OID %s stopped: %w", ip, oid, readErr)
	}
	if err != nil {
		return nil, fmt.Errorf("snmpwalk timeout/error for %s OID %s: %v", ip, oid, err)
	}
	return lines, nil
}

// errWalkRepeats is the error of an unordered walk whose agent repeated an
// OID (snmpWalkOutput).
var errWalkRepeats = errors.New("the agent repeats an OID")

// snmpWalkOutput reads the lines of one snmpbulkwalk from r to its end. In
// an unordered walk (-Cc) net-snmp no longer stops an agent that leads the
// walk back to rows it has sent (its "OID not increasing" check is what
// -Cc turns off), so a varbind OID that comes a second time calls stop
// (which kills the walk) and gives errWalkRepeats. The output is always
// read to its end, so the walk never blocks on a full pipe; a line too
// long to read ends the lines, as it did before.
func snmpWalkOutput(r io.Reader, unordered bool, stop func()) ([]string, error) {
	defer func() { _, _ = io.Copy(io.Discard, r) }()
	scanner := bufio.NewScanner(r)
	var lines []string
	seen := make(map[string]bool)
	for scanner.Scan() {
		line := scanner.Text()
		if oid, _, ok := strings.Cut(line, " = "); unordered && ok && strings.HasPrefix(oid, ".") {
			if seen[oid] {
				stop()
				return nil, fmt.Errorf("%w: %s", errWalkRepeats, oid)
			}
			seen[oid] = true
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// collectLocalChassisID collects the local Chassis ID (lldpLocChassisId).
// When the agent answers without one the error wraps errNoLocalChassis; a
// walk error means the agent did not answer.
//
// The walk of the scalar ends in a GET of lldpLocChassisId.0. The
// PiXiETECH switches 172.20.230.40 and .44 answer it with the chassis id
// (STRING "5894.8000.f7a3"), but the saved data of 2026-10-20 holds
// "No Such Instance currently exists at this OID" for both: now and then
// the instance is missing. So an answer of "No Such Instance" (the object
// is there, the instance is not), no output or an unreadable line is read
// once more as the column (a GETBULK whose first row is the instance,
// collectLocalChassisColumn). "No Such Object" (no LLDP-MIB: the
// FortiGate, the Huawei switches) is final. When both reads fail, the
// stored chassis id of the switch stays (keepPreviousChassisID, H9).
func (s *SNMPObject) collectLocalChassisID(ip string) (string, error) {
	lines, err := s.runSNMPWalk(ip, oidLLDPLocChassisID)
	if err != nil {
		return "", err
	}
	id, retry, noChassis := collectChassisAnswer(lines)
	if noChassis == nil || !retry {
		return id, noChassis
	}
	if id, ok := s.collectLocalChassisColumn(ip); ok {
		return id, nil
	}
	return "", noChassis
}

// oidLLDPLocChassisIDColumn is lldpLocChassisId without the instance: its
// walk is answered by a GETBULK from the column, not by a GET of the
// instance.
const oidLLDPLocChassisIDColumn = ".1.0.8802.1.1.2.1.3.2"

// collectChassisAnswer reads the answer of the lldpLocChassisId walk: the
// normalized chassis id (graphLocalChassisID), or an error that wraps
// errNoLocalChassis, with retry set when the answer is worth a second read
// (no output, an unreadable first line, "No Such Instance").
func collectChassisAnswer(lines []string) (id string, retry bool, err error) {
	if len(lines) == 0 {
		return "", true, fmt.Errorf("%w: no output", errNoLocalChassis)
	}
	// Parse first line
	_, val, err := parseSNMPLine(lines[0])
	if err != nil {
		return "", true, fmt.Errorf("%w: %v", errNoLocalChassis, err)
	}
	// "No Such Object…" is no chassis id: the graph then uses the device IP
	// instead of merging every switch that answers with the same text
	if graphIsSNMPException(val) {
		retry = strings.HasPrefix(strings.ToLower(val), "no such instance")
		return "", retry, fmt.Errorf("%w: %s", errNoLocalChassis, val)
	}
	return graphLocalChassisID(val), false, nil
}

// collectLocalChassisColumn is the second lldpLocChassisId read: a walk of
// the column whose lldpLocChassisId.0 row holds a chassis id. ok is false
// when the walk fails or shows none.
func (s *SNMPObject) collectLocalChassisColumn(ip string) (string, bool) {
	lines, err := s.runSNMPWalk(ip, oidLLDPLocChassisIDColumn)
	if err != nil {
		return "", false
	}
	for i, line := range lines {
		oid, _, _, found := collectSNMPValue(line)
		if found && strings.TrimPrefix(oid, ".") == strings.TrimPrefix(oidLLDPLocChassisID, ".") {
			id, _, noChassis := collectChassisAnswer(lines[i : i+1])
			return id, noChassis == nil && id != ""
		}
	}
	return "", false
}

// collectInterfaces walks IF-MIB with parallel OID groups for speed
func (s *SNMPObject) collectInterfaces(ip string) ([]InterfaceData, error) {
	// Walk ifDescr first (required to build interface map)
	descrLines, err := s.runSNMPWalk(ip, ".1.3.6.1.2.1.2.2.1.2")
	if err != nil {
		return nil, err
	}

	// Build interface map with descriptions
	ifaceMap := make(map[int]*InterfaceData)
	var ifaceMu sync.Mutex
	for _, line := range descrLines {
		oid, val, err := parseSNMPLine(line)
		if err != nil {
			continue
		}
		parts := strings.Split(oid, ".")
		idxStr := parts[len(parts)-1]
		idx, _ := strconv.Atoi(idxStr)
		ifaceMap[idx] = &InterfaceData{
			IfIndex: idx,
			IfDescr: val,
		}
	}

	// Helper to parse lines and fill ifaceMap fields
	type walkJob struct {
		oid    string
		apply  func(iface *InterfaceData, val string)
	}

	runWalkJobs := func(jobs []walkJob) {
		var wg sync.WaitGroup
		for _, job := range jobs {
			wg.Add(1)
			go func(j walkJob) {
				defer wg.Done()
				lines, err := s.runSNMPWalk(ip, j.oid)
				if err != nil {
					return
				}
				for _, line := range lines {
					oid, val, err := parseSNMPLine(line)
					if err != nil {
						continue
					}
					parts := strings.Split(oid, ".")
					idxStr := parts[len(parts)-1]
					idx, _ := strconv.Atoi(idxStr)
					ifaceMu.Lock()
					if iface, exists := ifaceMap[idx]; exists {
						j.apply(iface, val)
					}
					ifaceMu.Unlock()
				}
			}(job)
		}
		wg.Wait()
	}

	// Group 1: Speed + Status (independent, can run together). ifSpeed and
	// ifHighSpeed walk at the same time and either may finish first: ifSpeed
	// does not replace a speed ifHighSpeed set with a lower one or with its
	// 4294967295 "faster than 32 bits" value. It used to, whenever it
	// finished last, and 10G ports showed "4G" (94 of the 197 interfaces at
	// either speed in the saved data of 2026-10-20 kept 4294967295, on 22
	// switches; 81 in the live data of 2026-10-22, partly on others).
	runWalkJobs([]walkJob{
		{".1.3.6.1.2.1.2.2.1.5", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "Gauge32: ")
			speed, _ := strconv.ParseUint(val, 10, 64)
			if iface.IfSpeed == 0 || (speed > iface.IfSpeed && speed != 4294967295) {
				iface.IfSpeed = speed
			}
		}},
		{".1.3.6.1.2.1.31.1.1.1.15", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "Gauge32: ")
			highSpeed, _ := strconv.ParseUint(val, 10, 64)
			if highSpeed > 0 {
				speedBps := highSpeed * 1_000_000
				if speedBps > iface.IfSpeed || iface.IfSpeed == 4294967295 {
					iface.IfSpeed = speedBps
				}
			}
		}},
		{".1.3.6.1.2.1.2.2.1.7", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "INTEGER: ")
			adminStatus, _ := strconv.Atoi(val)
			iface.IfAdminStatus = adminStatus
		}},
		{".1.3.6.1.2.1.2.2.1.8", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "INTEGER: ")
			operStatus, _ := strconv.Atoi(val)
			iface.IfOperStatus = operStatus
		}},
		{".1.3.6.1.2.1.31.1.1.1.18", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "STRING: ")
			val = strings.Trim(val, "\" ")
			iface.IfAlias = val
		}},
	})

	// Group 2: Traffic counters (32-bit + 64-bit) + Errors + Discards
	runWalkJobs([]walkJob{
		{".1.3.6.1.2.1.2.2.1.10", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "Counter32: ")
			inOctets, _ := strconv.ParseUint(val, 10, 64)
			iface.IfInOctets = inOctets
		}},
		{".1.3.6.1.2.1.2.2.1.16", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "Counter32: ")
			outOctets, _ := strconv.ParseUint(val, 10, 64)
			iface.IfOutOctets = outOctets
		}},
		{".1.3.6.1.2.1.2.2.1.14", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "Counter32: ")
			val = strings.TrimPrefix(val, "Counter64: ")
			inErrors, _ := strconv.ParseUint(val, 10, 64)
			iface.IfInErrors = inErrors
		}},
		{".1.3.6.1.2.1.2.2.1.20", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "Counter32: ")
			val = strings.TrimPrefix(val, "Counter64: ")
			outErrors, _ := strconv.ParseUint(val, 10, 64)
			iface.IfOutErrors = outErrors
		}},
		{".1.3.6.1.2.1.2.2.1.13", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "Counter32: ")
			val = strings.TrimPrefix(val, "Counter64: ")
			inDiscards, _ := strconv.ParseUint(val, 10, 64)
			iface.IfInDiscards = inDiscards
		}},
		{".1.3.6.1.2.1.2.2.1.19", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "Counter32: ")
			val = strings.TrimPrefix(val, "Counter64: ")
			outDiscards, _ := strconv.ParseUint(val, 10, 64)
			iface.IfOutDiscards = outDiscards
		}},
	})

	// Group 3: HC (64-bit) counters — overwrite 32-bit values
	runWalkJobs([]walkJob{
		{".1.3.6.1.2.1.31.1.1.1.6", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "Counter64: ")
			hcIn, err := strconv.ParseUint(val, 10, 64)
			if err == nil && hcIn > 0 {
				iface.IfInOctets = hcIn
			}
		}},
		{".1.3.6.1.2.1.31.1.1.1.10", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "Counter64: ")
			hcOut, err := strconv.ParseUint(val, 10, 64)
			if err == nil && hcOut > 0 {
				iface.IfOutOctets = hcOut
			}
		}},
	})

	// Convert map to slice
	ifaces := make([]InterfaceData, 0, len(ifaceMap))
	for _, iface := range ifaceMap {
		ifaces = append(ifaces, *iface)
	}

	return ifaces, nil
}

// collectLLDPNeighbors walks LLDP Remote Table (lldpRemTable, then the
// management addresses of lldpRemManAddrTable), in the index layout of the
// LLDP-MIB or in the 2-part layout of the PiXiETECH switches
// (collectLLDPRemIndex).
func (s *SNMPObject) collectLLDPNeighbors(ip string) ([]LLDPNeighbor, error) {
	// Walk lldpRemTable
	lines, err := s.runSNMPWalk(ip, collectLLDPRemOID)
	if err != nil {
		return nil, err
	}

	neighborMap := make(map[string]*LLDPNeighbor)

	for _, line := range lines {
		oid, val, err := parseSNMPLine(line)
		if err != nil {
			continue
		}

		// OID: .1.0.8802.1.1.2.1.4.1.1.COLUMN.TimeMark.LocalPort.RemIndex,
		// or the PiXiETECH form without the time mark (collectLLDPRemIndex)
		col, key, lp, ri, twoPart, ok := collectLLDPRemIndex(oid)
		if !ok {
			continue
		}

		if _, exists := neighborMap[key]; !exists {
			neighborMap[key] = &LLDPNeighbor{
				LocalPortNum: lp,
				RemIndex:     ri,
			}
		}
		neighbor := neighborMap[key]

		switch col {
		case 2, 3: // lldpRemLocalPortNum, lldpRemIndex: index columns, read on the 2-part form only
			if n, err := strconv.Atoi(val); twoPart && err == nil && n > 0 {
				if col == 2 {
					neighbor.LocalPortNum = n
				} else {
					neighbor.RemIndex = n
				}
			}
		case 4: // ChassisIdSubtype
			neighbor.RemChassisIdSubtype, _ = strconv.Atoi(val)
		case 5: // ChassisId
			// Don't normalize here - we need subtype info first
			// Store raw value, normalize in example_usage.go based on subtype
			neighbor.RemChassisId = val
		case 6: // PortIdSubtype
			neighbor.RemPortIdSubtype, _ = strconv.Atoi(val)
		case 7: // PortId
			neighbor.RemPortId = val
		case 8: // PortDesc
			neighbor.RemPortDesc = val
		case 9: // SysName
			neighbor.RemSysName = strings.Trim(val, "\"")
		case 10: // SysDesc
			neighbor.RemSysDesc = strings.Trim(val, "\"")
		case 12: // SysCapEnabled (BITS), read with its value type
			if _, typ, raw, ok := collectSNMPValue(line); ok {
				neighbor.RemSysCapEnabled = lldpCapabilities(typ, raw)
			}
		}
	}

	for _, n := range neighborMap {
		logDebug("  [SNMP-RAW] %s: Neighbor on LocalPort %d -> RemChassis: %s (Subtype: %d), RemPort: %s",
			ip, n.LocalPortNum, n.RemChassisId, n.RemChassisIdSubtype, n.RemPortId)
	}

	// Collect Management Addresses and populate RemMgmtIP
	if err := s.enrichWithManagementIPs(ip, neighborMap); err != nil {
		// Non-fatal, just log
		fmt.Printf("Warning: Failed to collect management IPs for %s: %v\n", ip, err)
	}

	// Convert map to slice
	result := make([]LLDPNeighbor, 0, len(neighborMap))
	for _, n := range neighborMap {
		result = append(result, *n)
	}

	return result, nil
}

// collectLLDPRemOID is lldpRemEntry (LLDP-MIB lldpRemTable): column, then
// the index lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex.
const collectLLDPRemOID = ".1.0.8802.1.1.2.1.4.1.1"

// collectLLDPRemIndex decodes one lldpRemTable OID into its column, the
// neighbor key ("localPort.remIndex", the key collectLLDPManAddr gives),
// the local port and the remote index. The LLDP-MIB index has three parts
// (time mark, local port, remote index) and is read as before. The
// PiXiETECH PXT-S2780G switches (172.20.230.40 and .44, firmware 2.2.0D)
// leave the time mark out and put the remote index first:
// lldpRemSysName.1.25 = "Switch" is remote index 1 on local port 25. Their
// agent also reports the index columns, and they say so
// (lldpRemLocalPortNum.1.25 = 25, lldpRemIndex.1.25 = 1), as do the FDB
// (every upstream MAC on port 25), the STP root port (25) and the far end
// (172.20.230.44 sees 172.20.230.40 on its port 27, and .40 sees .44's
// Gig0/27 on port 25). twoPart marks that layout: collectLLDPNeighbors
// then takes lldpRemLocalPortNum and lldpRemIndex from those columns when
// the agent reports them. Any other index length gives ok=false.
func collectLLDPRemIndex(oid string) (col int, key string, localPort, remIndex int, twoPart, ok bool) {
	idx, ok := collectOIDIndex(oid, collectLLDPRemOID)
	if !ok {
		return 0, "", 0, 0, false, false
	}
	switch len(idx) {
	case 4: // column, lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex
		col, localPort, remIndex = idx[0], idx[2], idx[3]
	case 3: // column, lldpRemIndex, lldpRemLocalPortNum (PiXiETECH)
		col, localPort, remIndex, twoPart = idx[0], idx[2], idx[1], true
	default:
		return 0, "", 0, 0, false, false
	}
	return col, fmt.Sprintf("%d.%d", localPort, remIndex), localPort, remIndex, twoPart, true
}

// LLDP system capabilities (LldpSystemCapabilitiesMap, a BITS value whose
// bit 0 is the most significant bit of the first octet): other 0,
// repeater 1, bridge 2, wlanAccessPoint 3, router 4, telephone 5,
// docsisCableDevice 6, stationOnly 7.
const (
	lldpCapBridge = 0x80 >> 2
	lldpCapWLANAP = 0x80 >> 3
	lldpCapRouter = 0x80 >> 4
	lldpCapPhone  = 0x80 >> 5
)

// lldpCapabilities reads an lldpRemSysCapEnabled value as net-snmp prints
// it: "Hex-STRING: 28 00", "BITS: 28 00 bridge(2) router(4)" when the
// LLDP-MIB is loaded, or a quoted STRING when the octets are printable
// ("(" is 0x28). It returns the first octet, or 0 when the value cannot be
// read.
func lldpCapabilities(typ, val string) uint8 {
	switch typ {
	case "Hex-STRING", "BITS":
		fields := strings.Fields(val)
		if len(fields) == 0 {
			return 0
		}
		octet, err := hex.DecodeString(fields[0])
		if err != nil || len(octet) != 1 {
			return 0
		}
		return octet[0]
	case "STRING":
		if inner, quoted := macUnquote(val); quoted && inner != "" {
			return inner[0]
		}
	}
	return 0
}

// lldpDiscoverable reports whether an LLDP neighbor with these enabled
// capabilities may be polled as a switch and added to swich_ips: a router,
// or a bridge that is no wireless access point and no telephone (access
// points and IP phones enable bridge as well). Unknown capabilities (0) are
// never added automatically.
func lldpDiscoverable(caps uint8) bool {
	if caps&lldpCapRouter != 0 {
		return true
	}
	return caps&lldpCapBridge != 0 && caps&(lldpCapWLANAP|lldpCapPhone) == 0
}

// enrichWithManagementIPs collects Management IP addresses from lldpRemManAddrTable
func (s *SNMPObject) enrichWithManagementIPs(ip string, neighborMap map[string]*LLDPNeighbor) error {
	// Walk lldpRemManAddrTable (.1.0.8802.1.1.2.1.4.2.1)
	lines, err := s.runSNMPWalk(ip, collectLLDPManAddrOID)
	if err != nil {
		return err
	}

	for _, line := range lines {
		oid, typ, val, found := collectSNMPValue(line)
		if !found {
			continue
		}
		// The address is in the index (every accessible column repeats it),
		// or in a column on the PiXiETECH switches (collectLLDPManAddrValue).
		// The first IPv4 address in walk order wins.
		key, mgmtIP, ok := collectLLDPManAddr(oid)
		if !ok {
			key, mgmtIP, ok = collectLLDPManAddrValue(oid, typ, val)
		}
		if !ok {
			continue
		}
		if neighbor, exists := neighborMap[key]; exists && neighbor.RemMgmtIP == "" {
			neighbor.RemMgmtIP = mgmtIP
		}
	}

	return nil
}

// collectLLDPManAddrOID is lldpRemManAddrTable (LLDP-MIB). Its index is
// lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex.lldpRemManAddrSubtype.
// lldpRemManAddr, and the address is an OCTET STRING index: its length, then
// its octets (IPv4: ...<column>.<timeMark>.<localPort>.<remIndex>.1.4.a.b.c.d).
const collectLLDPManAddrOID = ".1.0.8802.1.1.2.1.4.2.1"

// collectLLDPManAddr decodes one lldpRemManAddrTable OID into the neighbor
// key ("localPort.remIndex", as in collectLLDPNeighbors) and its IPv4
// management address. Agents that leave out the length octet are accepted
// (four octets not starting with 4, which would be a truncated length-4
// address); other address families give ok=false.
func collectLLDPManAddr(oid string) (key, ip string, ok bool) {
	idx, ok := collectOIDIndex(oid, collectLLDPManAddrOID)
	// column, time mark, local port, remote index, address family, address
	if !ok || len(idx) < 6 || idx[4] != 1 { // IANA address family 1 = IPv4
		return "", "", false
	}
	addr := idx[5:]
	switch {
	case len(addr) == 5 && addr[0] == 4:
		addr = addr[1:]
	case len(addr) == 4 && addr[0] != 4:
	default:
		return "", "", false
	}
	if slices.ContainsFunc(addr, func(b int) bool { return b > 255 }) ||
		slices.Equal(addr, []int{0, 0, 0, 0}) {
		return "", "", false
	}
	return fmt.Sprintf("%d.%d", idx[2], idx[3]),
		fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]), true
}

// collectLLDPManAddrValue decodes one lldpRemManAddrTable row of the
// PiXiETECH switches, whose index is their 2-part lldpRemTable index
// (lldpRemIndex.lldpRemLocalPortNum, collectLLDPRemIndex) and whose address
// is a column, not an index: column 1 is the address subtype, column 2 the
// address as text (lldpRemManAddr.1.25 = STRING: "172.20.230.44", or
// "FE80::AE8B:A9FF:FE70:A966" for the access points). It gives the
// neighbor key and the IPv4 address of a column 2 row (text, IpAddress or
// four Hex-STRING octets); any other row gives ok=false.
func collectLLDPManAddrValue(oid, typ, val string) (key, ip string, ok bool) {
	idx, ok := collectOIDIndex(oid, collectLLDPManAddrOID)
	if !ok || len(idx) != 3 || idx[0] != 2 {
		return "", "", false
	}
	var addr netip.Addr
	switch typ {
	case "STRING", "IpAddress":
		addr, _ = netip.ParseAddr(strings.TrimSpace(strings.Trim(val, "\"")))
	case "Hex-STRING":
		var octets [4]byte
		fields := strings.Fields(val)
		if len(fields) != len(octets) {
			return "", "", false
		}
		for i, f := range fields {
			b, err := hex.DecodeString(f)
			if err != nil || len(b) != 1 {
				return "", "", false
			}
			octets[i] = b[0]
		}
		addr = netip.AddrFrom4(octets)
	}
	if !addr.Is4() || addr.IsUnspecified() {
		return "", "", false
	}
	return fmt.Sprintf("%d.%d", idx[2], idx[1]), addr.String(), true
}

// OIDs of the FDB and ARP walks.
const (
	collectFDBPortOID = ".1.3.6.1.2.1.17.4.3.1.2" // dot1dTpFdbPort.<6 MAC octets> = bridge port
	collectARPPhysOID = ".1.3.6.1.2.1.4.22.1.2"   // ipNetToMediaPhysAddress.<ifIndex>.<4 IP octets> = MAC
)

// collectSNMPValue splits one snmpbulkwalk -On line into the OID, the value
// type ("Hex-STRING", "STRING", "INTEGER"...; "" when there is none, as for
// exception text) and the value.
func collectSNMPValue(line string) (oid, typ, val string, ok bool) {
	oid, raw, ok := strings.Cut(line, " = ")
	if !ok {
		return "", "", "", false
	}
	typ, val, found := strings.Cut(raw, ": ")
	if !found {
		typ, val = "", raw
	}
	return oid, typ, strings.TrimSpace(val), true
}

// collectPhysAddress decodes an ipNetToMediaPhysAddress value into canonical
// MAC text. net-snmp prints the 6 octets as "Hex-STRING: 00 0C 29 6F E0 BC",
// or as a quoted STRING when every byte is printable ("P(J3:L" is
// 50:28:4a:33:3a:4c, with \" and \\ escaped: parseMACOctets), or with the
// PhysAddress DISPLAY-HINT when MIBs are loaded ("STRING: 0:c:29:aa:bb:cd",
// the unpadded form parseMAC reads). Text MACs with dashes
// ("f8-f0-82-7a-d9-69") are accepted as before.
func collectPhysAddress(typ, val string) (string, bool) {
	switch typ {
	case "Hex-STRING":
		if len(strings.Fields(val)) != 6 {
			return "", false
		}
	case "STRING", "":
		if m, ok := parseMACOctets(val); ok && strings.HasPrefix(val, "\"") {
			return m.String(), true
		}
	default:
		return "", false
	}
	mac := canonicalMAC(val)
	return mac, mac != ""
}

// collectOIDIndex returns the index components after base in a numeric OID
// (snmpbulkwalk -On), or ok=false when the OID is not below base or one of
// the components is not a number.
func collectOIDIndex(oid, base string) ([]int, bool) {
	rest, found := strings.CutPrefix(strings.TrimPrefix(oid, "."), strings.TrimPrefix(base, ".")+".")
	if !found || rest == "" {
		return nil, false
	}
	parts := strings.Split(rest, ".")
	idx := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p[0] == '+' {
			return nil, false
		}
		idx[i] = n
	}
	return idx, true
}

// parseSNMPLine parses specific snmpwalk output line
// .1.0.8802.1.1.2.1.4.1.1.5.0.48.1 = Hex-STRING: 4C AE A3 8E 42 11
// OR
// .1.0.8802... = STRING: "B-318/1"
func parseSNMPLine(line string) (oid string, value string, err error) {
	parts := strings.SplitN(line, " = ", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("bad format")
	}
	oid = parts[0]
	rawVal := parts[1]

	// Remove type prefix (STRING:, Hex-STRING:, INTEGER:, etc)
	valParts := strings.SplitN(rawVal, ": ", 2)
	if len(valParts) == 2 {
		value = valParts[1]
	} else {
		value = rawVal // e.g. integers might not have colon? "INTEGER: 10" usually.
		// Sometimes just "10" if -Oqv? No we didn't use -Oqv.
	}
	return oid, strings.TrimSpace(value), nil
}

// collectMACTable collects MAC address table (FDB) from BRIDGE-MIB. The
// walk is unordered (-Cc): the PiXiETECH switches 172.20.230.40 and .44
// return their FDB in hash order (148.64.201.42.244.74, then
// 248.240.130.124.249.203, then 148.64.201.42.244.98...), so net-snmp
// stopped at its second request with "OID not increasing" and exit status
// 1, the walk failed in every poll and the stored FDB of both stayed empty;
// read without the check the agent gives each row once (94 and 106 rows on
// 2026-10-22) and ends the table. On agents that keep OID order -Cc
// changes nothing.
func (s *SNMPObject) collectMACTable(ip string) ([]MACEntry, error) {
	// Walk dot1dTpFdbPort (.1.3.6.1.2.1.17.4.3.1.2) to get MAC->Port mapping
	// OID format: .1.3.6.1.2.1.17.4.3.1.2.M1.M2.M3.M4.M5.M6 = INTEGER: PortNum
	// where M1-M6 are the 6 bytes of MAC address

	lines, err := s.runSNMPWalkUnordered(ip, collectFDBPortOID)
	if err != nil {
		return nil, err
	}

	result := []MACEntry{}

	for _, line := range lines {
		oid, val, err := parseSNMPLine(line)
		if err != nil {
			continue
		}

		// Extract MAC address from OID
		// OID: .1.3.6.1.2.1.17.4.3.1.2.76.174.163.142.66.17
		// The index is exactly the six MAC octets.
		octets, ok := collectOIDIndex(oid, collectFDBPortOID)
		if !ok || len(octets) != 6 || slices.ContainsFunc(octets, func(b int) bool { return b > 255 }) {
			continue
		}
		macAddr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			octets[0], octets[1], octets[2], octets[3], octets[4], octets[5])

		// Parse port number from value
		val = strings.TrimPrefix(val, "INTEGER: ")
		portNum, _ := strconv.Atoi(val)

		// Skip port 0 (usually invalid)
		if portNum == 0 {
			continue
		}

		entry := MACEntry{
			MACAddress: macAddr,
			PortNumber: portNum,
			VlanID:     0,         // Will be populated if Q-BRIDGE is available
			Status:     "learned", // Default
		}

		result = append(result, entry)
	}


	return result, nil
}

// collectARPTable collects ARP table (IP to MAC mapping) from IP-MIB
func (s *SNMPObject) collectARPTable(ip string) ([]ARPEntry, error) {
	// Walk ipNetToMediaPhysAddress (.1.3.6.1.2.1.4.22.1.2)
	// OID format: .1.3.6.1.2.1.4.22.1.2.IfIndex.IP1.IP2.IP3.IP4 = Hex-STRING: MAC

	lines, err := s.runSNMPWalk(ip, collectARPPhysOID)
	if err != nil {
		return nil, err
	}

	result := []ARPEntry{}

	for _, line := range lines {
		oid, typ, val, ok := collectSNMPValue(line)
		if !ok {
			continue
		}

		// Extract IP address from OID
		// OID: .1.3.6.1.2.1.4.22.1.2.1.192.168.1.100
		// The index is exactly the interface index and the 4 IP octets.
		idx, ok := collectOIDIndex(oid, collectARPPhysOID)
		if !ok || len(idx) != 5 || slices.ContainsFunc(idx[1:], func(b int) bool { return b > 255 }) {
			continue
		}
		ifIndex := idx[0]
		ipAddr := fmt.Sprintf("%d.%d.%d.%d", idx[1], idx[2], idx[3], idx[4])

		// Parse the MAC: Hex-STRING, or STRING when all six bytes are
		// printable or MIBs are loaded (F58). Incomplete entries fail here.
		macAddr, ok := collectPhysAddress(typ, val)
		if !ok {
			continue
		}

		// Skip invalid IPs
		if idx[1] == 0 {
			continue
		}

		// Skip null, broadcast, multicast and zero-OUI MACs (Q11)
		if usableMAC(macAddr) == "" {
			continue
		}

		result = append(result, ARPEntry{
			IPAddress:  ipAddr,
			MACAddress: macAddr,
			Interface:  ifIndex,
		})
	}


	return result, nil
}

// collectSTPInfo collects Spanning Tree Protocol details
func (s *SNMPObject) collectSTPInfo(ip string) (STPData, error) {
	data := STPData{}
	
	// Check dot1dStpProtocolSpecification (.1.3.6.1.2.1.17.2.1)
	// 1=unknown, 2=decLb100, 3=ieee8021d, 4=ieee8021q
	lines, err := s.runSNMPWalk(ip, ".1.3.6.1.2.1.17.2.1")
	if err == nil && len(lines) > 0 {
		_, val, _ := parseSNMPLine(lines[0])
		val = strings.TrimPrefix(val, "INTEGER: ")
		if val != "" {
			data.Enabled = true // Assume enabled if MIB exists
			data.Protocol = "stp" // default
		}
	} else {
		return data, fmt.Errorf("No STP MIB")
	}

	// dot1dStpDesignatedRoot (.1.3.6.1.2.1.17.2.5) -> Root Bridge ID
	lines, err = s.runSNMPWalk(ip, ".1.3.6.1.2.1.17.2.5")
	if err == nil && len(lines) > 0 {
		_, val, _ := parseSNMPLine(lines[0])
		// Value: Hex-STRING: 80 00 00 19 ...
		val = strings.TrimPrefix(val, "Hex-STRING: ")
		
		// Priority (2 bytes) + MAC (6 bytes)
		// e.g. "80 00 00 1A 2B 3C 4D 5E"
		parts := strings.Fields(val)
		if len(parts) >= 8 {
			// Extract MAC part (last 6 bytes)
			macParts := parts[2:8]
			data.RootBridgeID = strings.ToLower(strings.Join(macParts, ":"))
		}
	}

	// dot1dStpRootCost (.1.3.6.1.2.1.17.2.6)
	lines, err = s.runSNMPWalk(ip, ".1.3.6.1.2.1.17.2.6")
	if err == nil && len(lines) > 0 {
		_, val, _ := parseSNMPLine(lines[0])
		val = strings.TrimPrefix(val, "INTEGER: ")
		cost, _ := strconv.Atoi(val)
		data.RootCost = cost
	}

	// dot1dStpRootPort (.1.3.6.1.2.1.17.2.7)
	lines, err = s.runSNMPWalk(ip, ".1.3.6.1.2.1.17.2.7")
	if err == nil && len(lines) > 0 {
		_, val, _ := parseSNMPLine(lines[0])
		val = strings.TrimPrefix(val, "INTEGER: ")
		port, _ := strconv.Atoi(val)
		data.RootPort = port
	}

	return data, nil
}

// collectVLANEgressOID is dot1qVlanCurrentEgressPorts (Q-BRIDGE-MIB): the
// ports of each VLAN as a bitmap, the trunk detection of collectPortVLANs.
const collectVLANEgressOID = ".1.3.6.1.2.1.17.7.1.4.2.1.4"

// The agents whose VLAN egress walk failed in their last poll: CollectData
// walks their VLAN table (dot1qPvid, then the egress ports) after the other
// walks of the poll, not with them. The Aruba 6300 172.20.230.253 (JL658A,
// FL.10.13.1040) has no row in dot1qVlanCurrentTable, and its agent takes
// 10.8 s to answer a GETNEXT into it (its answer is cached for a short
// while: slow again 73 s later, and the polls are 5 minutes apart), so the
// walk times out after its two 5 s attempts. While the agent works on it,
// it answers no other request of the switch: a sysUpTime GET and a
// dot1dTpFdbPort GETBULK sent 1 s after it were answered 9.8 and 10.2 s
// later (read-only snmpgetnext, snmpget and snmpbulkget, one at a time,
// 2026-10-22 20:41-20:43). The walk started about 1 s into a poll, after
// dot1qPvid, while the FDB walk was still in flight: 164 round trips (the
// agent puts at most 10 varbinds into a response, -Cr25 or not) between
// the slow requests of the other walks (STP about 0.95 s, dot1qPvid 0.33
// s, dot1dBaseNumPorts 0.3 s each). So the FDB walk failed in every poll
// since the switch answered SNMP on 2026-10-20 (cron_monitor.log: one "mac
// table err" per rescan, 180 on 2026-10-22) and the ifDescr walk in half
// of them or more, although alone the FDB gives its 1,619-1,638 rows in
// 0.26-0.83 s, and the agent answered every request it received, late
// (snmpInPkts minus snmpOutPkts is its 44 bad community names,
// snmpSilentDrops 0). A switch whose egress walk answers keeps its timing:
// the HPE, SNR and PiXiETECH agents give their 4,094 rows in 2.5-5.3 s. A
// walk that answers again clears the mark.
var (
	collectVLANLastMu  sync.Mutex
	collectVLANLastIPs = make(map[string]bool)
)

// collectVLANLast reports whether CollectData walks the VLAN table of ip
// after its other walks: the last egress walk of ip failed.
func collectVLANLast(ip string) bool {
	collectVLANLastMu.Lock()
	defer collectVLANLastMu.Unlock()
	return collectVLANLastIPs[ip]
}

// collectNoteEgressWalk records the outcome of an egress walk of ip
// (collectVLANLast).
func collectNoteEgressWalk(ip string, err error) {
	collectVLANLastMu.Lock()
	defer collectVLANLastMu.Unlock()
	if err != nil {
		collectVLANLastIPs[ip] = true
	} else {
		delete(collectVLANLastIPs, ip)
	}
}

// collectPortVLANs collects VLAN configuration for ports
// Uses Q-BRIDGE-MIB (dot1qPvid) for PVID and port mode detection
func (s *SNMPObject) collectPortVLANs(ip string) ([]PortVLAN, error) {
	// OID for dot1qPvid - Port VLAN ID (PVID)
	// .1.3.6.1.2.1.17.7.1.4.5.1.1.<port_index> = VLAN_ID
	pvidOID := ".1.3.6.1.2.1.17.7.1.4.5.1.1"

	lines, err := s.runSNMPWalk(ip, pvidOID)
	if err != nil {
		return nil, err
	}

	result := []PortVLAN{}
	portPVIDs := make(map[int]int)

	// Parse PVID output
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Format: .1.3.6.1.2.1.17.7.1.4.5.1.1.49 = INTEGER: 1616
		parts := strings.Split(line, "=")
		if len(parts) < 2 {
			continue
		}

		oidPart := strings.TrimSpace(parts[0])
		valPart := strings.TrimSpace(parts[1])

		// Extract port index from OID
		oidParts := strings.Split(oidPart, ".")
		if len(oidParts) < 1 {
			continue
		}
		portIndex, _ := strconv.Atoi(oidParts[len(oidParts)-1])
		if portIndex == 0 {
			continue
		}

		// Extract VLAN ID
		valPart = strings.TrimPrefix(valPart, "INTEGER: ")
		valPart = strings.TrimPrefix(valPart, "Gauge32: ")
		vlanID, _ := strconv.Atoi(valPart)

		portPVIDs[portIndex] = vlanID
	}

	// Now check for trunk ports by looking at dot1qVlanCurrentEgressPorts
	// A trunk port will have multiple VLANs. Its failure is no failed walk,
	// but the next poll asks it last (collectVLANLast)
	vlanLines, egressErr := s.runSNMPWalk(ip, collectVLANEgressOID)
	collectNoteEgressWalk(ip, egressErr)

	portVLANCount := make(map[int]int)
	if len(vlanLines) > 0 {
		for _, line := range vlanLines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Format: .1.3.6.1.2.1.17.7.1.4.2.1.4.VLANID = Hex-STRING: XX XX XX ...
			// Each byte in Hex-STRING is a bitmask for 8 ports
			parts := strings.Split(line, "=")
			if len(parts) < 2 {
				continue
			}

			valPart := strings.TrimSpace(parts[1])
			valPart = strings.TrimPrefix(valPart, "Hex-STRING: ")
			valPart = strings.TrimPrefix(valPart, "STRING: ")

			// Parse hex bytes to find which ports are in this VLAN
			hexBytes := strings.Fields(valPart)
			for byteIdx, hexByte := range hexBytes {
				b, err := strconv.ParseUint(hexByte, 16, 8)
				if err != nil {
					continue
				}
				// Each bit represents a port (MSB first)
				for bit := 7; bit >= 0; bit-- {
					if b&(1<<uint(bit)) != 0 {
						portNum := byteIdx*8 + (7 - bit) + 1
						portVLANCount[portNum]++
					}
				}
			}
		}
	}

	// Build final result
	for portIndex, pvid := range portPVIDs {
		isTrunk := portVLANCount[portIndex] > 5 // Heuristic: more than 5 VLANs = trunk

		entry := PortVLAN{
			PortIndex: portIndex,
			PVID:      pvid,
			IsTrunk:   isTrunk,
		}
		result = append(result, entry)
	}


	return result, nil
}

