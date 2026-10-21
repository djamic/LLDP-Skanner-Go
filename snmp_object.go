package main

import (
	"bufio"
	"bytes"
	"fmt"
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
	Timeout   time.Duration // Not directly used by snmpwalk command unless via -t
	Retries   int
	OnSuccess func(data *DeviceData)
	OnFailure func(ip string, err error)
}

// NewSNMPObject creates a new SNMPObject
func NewSNMPObject(onSuccess func(*DeviceData), onFailure func(string, error)) *SNMPObject {
	return &SNMPObject{
		Community: "public",
		Port:      161,
		Timeout:   5 * time.Second,
		Retries:   2,
		OnSuccess: onSuccess,
		OnFailure: onFailure,
	}
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
			mu.Unlock()
		}
	}()

	// 2. Collect Interface Data (Full walk of IF-MIB)
	// Minimally implemented for speed since LLDP is priority
	wg.Add(1)
	go func() {
		defer wg.Done()
		ifaces, err := s.collectInterfaces(ip)
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("interfaces err: %v", err))
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
			mu.Unlock()
		} else {
			mu.Lock()
			data.MACTable = macTable
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
			mu.Unlock()
		} else {
			mu.Lock()
			data.ARPTable = arpTable
			mu.Unlock()
		}
	}()

	// 6. Collect Port VLAN Configuration
	wg.Add(1)
	go func() {
		defer wg.Done()
		portVLANs, err := s.collectPortVLANs(ip)
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("vlan err: %v", err))
			mu.Unlock()
		} else {
			mu.Lock()
			data.PortVLANs = portVLANs
			mu.Unlock()
		}
	}()

	// 7. Collect STP Information
	wg.Add(1)
	go func() {
		defer wg.Done()
		stpInfo, err := s.collectSTPInfo(ip)
		if err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("stp err: %v", err))
			mu.Unlock()
		} else {
			mu.Lock()
			data.STPInfo = stpInfo
			mu.Unlock()
		}
	}()



	wg.Wait()

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

	// Partial or full success — deliver data
	data.Timestamp = time.Now()
	if s.OnSuccess != nil {
		s.OnSuccess(data)
	}
}

// snmpWalk runs one SNMP walk for runSNMPWalk. Tests replace it with a fake
// agent so no SNMP request is sent.
var snmpWalk = snmpBulkWalk

// runSNMPWalk executes snmpbulkwalk command with 30s timeout and returns lines
func (s *SNMPObject) runSNMPWalk(ip, oid string) ([]string, error) {
	return snmpWalk(s.Community, ip, oid)
}

// snmpBulkWalk runs snmpbulkwalk (killed after 30s) and returns its lines.
func snmpBulkWalk(community, ip, oid string) ([]string, error) {
	cmd := exec.Command("snmpbulkwalk", "-v2c", "-c", community, "-On", "-Cr25", "-t", "5", "-r", "1", ip, oid)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Manual timeout: kill process group after 30s
	done := make(chan error, 1)
	timer := time.AfterFunc(30*time.Second, func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	})
	go func() { done <- cmd.Wait() }()
	err := <-done
	timer.Stop()

	if err != nil {
		return nil, fmt.Errorf("snmpwalk timeout/error for %s OID %s: %v", ip, oid, err)
	}

	scanner := bufio.NewScanner(&out)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, nil
}

// collectLocalChassisID collects the local Chassis ID
func (s *SNMPObject) collectLocalChassisID(ip string) (string, error) {
	oid := ".1.0.8802.1.1.2.1.3.2.0" // lldpLocChassisId
	lines, err := s.runSNMPWalk(ip, oid)
	if err != nil {
		return "", err
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("no output")
	}
	// Parse first line
	_, val, err := parseSNMPLine(lines[0])
	if err != nil {
		return "", err
	}
	return normalizeChassisID(val), nil
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

	// Group 1: Speed + Status (independent, can run together)
	runWalkJobs([]walkJob{
		{".1.3.6.1.2.1.2.2.1.5", func(iface *InterfaceData, val string) {
			val = strings.TrimPrefix(val, "Gauge32: ")
			speed, _ := strconv.ParseUint(val, 10, 64)
			iface.IfSpeed = speed
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

// collectLLDPNeighbors walks LLDP Remote Table
func (s *SNMPObject) collectLLDPNeighbors(ip string) ([]LLDPNeighbor, error) {
	// Walk lldpRemTable
	lines, err := s.runSNMPWalk(ip, ".1.0.8802.1.1.2.1.4.1.1")
	if err != nil {
		return nil, err
	}

	neighborMap := make(map[string]*LLDPNeighbor)

	for _, line := range lines {
		oid, val, err := parseSNMPLine(line)
		if err != nil {
			continue
		}

		// OID: .1.0.8802.1.1.2.1.4.1.1.COLUMN.TimeMark.LocalPort.RemIndex
		// Base len is 11 parts (.1.0...1)
		// Full OID parts
		parts := strings.Split(oid, ".")
		// Example: .1.0.8802.1.1.2.1.4.1.1.5.0.48.1
		// Indices need careful parsing.
		// Base prefix: .1.0.8802.1.1.2.1.4.1.1 (12 dots? No, starts with dot)
		// parts[0] is empty string if starts with dot.

		// Let's rely on finding "8802.1.1.2.1.4.1.1" and taking subsequent parts

		// Simple heuristic: Take last 4 parts
		if len(parts) < 15 {
			continue
		}

		n := len(parts)
		colStr := parts[n-4]
		// timeMark := parts[n-3]
		localPortStr := parts[n-2]
		remIdxStr := parts[n-1]

		key := fmt.Sprintf("%s.%s", localPortStr, remIdxStr) // Unique key per neighbor per port

		if _, exists := neighborMap[key]; !exists {
			lp, _ := strconv.Atoi(localPortStr)
			ri, _ := strconv.Atoi(remIdxStr)
			neighborMap[key] = &LLDPNeighbor{
				LocalPortNum: lp,
				RemIndex:     ri,
			}
		}
		neighbor := neighborMap[key]

		col, _ := strconv.Atoi(colStr)
		switch col {
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

// enrichWithManagementIPs collects Management IP addresses from lldpRemManAddrTable
func (s *SNMPObject) enrichWithManagementIPs(ip string, neighborMap map[string]*LLDPNeighbor) error {
	// Walk lldpRemManAddrTable (.1.0.8802.1.1.2.1.4.2.1)
	lines, err := s.runSNMPWalk(ip, collectLLDPManAddrOID)
	if err != nil {
		return err
	}

	for _, line := range lines {
		oid, _, err := parseSNMPLine(line)
		if err != nil {
			continue
		}
		// The address is in the index (every accessible column repeats it).
		// The first IPv4 address in walk order wins.
		key, mgmtIP, ok := collectLLDPManAddr(oid)
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

// OIDs of the FDB and ARP walks.
const (
	collectFDBPortOID = ".1.3.6.1.2.1.17.4.3.1.2" // dot1dTpFdbPort.<6 MAC octets> = bridge port
	collectARPPhysOID = ".1.3.6.1.2.1.4.22.1.2"   // ipNetToMediaPhysAddress.<ifIndex>.<4 IP octets> = MAC
)

// collectUsableMAC applies the Q11 MAC filter: false for anything that is
// not a 6-octet MAC, and for null, broadcast, multicast (I/G bit set) and
// zero-OUI (00:00:00) addresses.
func collectUsableMAC(mac string) bool {
	b, ok := collectTextMAC(mac)
	return ok && b[0]&1 == 0 && (b[0]|b[1]|b[2]) != 0
}

// collectCanonicalMAC returns a text MAC as "aa:bb:cc:dd:ee:ff", or "" when
// it is not one.
func collectCanonicalMAC(mac string) string {
	b, ok := collectTextMAC(mac)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

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
// 50:28:4a:33:3a:4c, with \" and \\ escaped), or with the PhysAddress
// DISPLAY-HINT when MIBs are loaded ("STRING: 0:c:29:aa:bb:cd"). Text MACs
// with dashes ("f8-f0-82-7a-d9-69") are accepted as before.
func collectPhysAddress(typ, val string) (string, bool) {
	var b [6]byte
	switch typ {
	case "Hex-STRING":
		fields := strings.Fields(val)
		if len(fields) != 6 {
			return "", false
		}
		for i, f := range fields {
			n, err := strconv.ParseUint(f, 16, 8)
			if err != nil || len(f) != 2 {
				return "", false
			}
			b[i] = byte(n)
		}
	case "STRING", "":
		text := val
		if raw, quoted := collectUnquote(val); quoted {
			if len(raw) == 6 {
				copy(b[:], raw)
				break
			}
			text = raw
		}
		mac := collectCanonicalMAC(text)
		return mac, mac != ""
	default:
		return "", false
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]), true
}

// collectUnquote removes the quotes net-snmp puts around a printable STRING
// and undoes its \" and \\ escapes. quoted is false when s is not quoted.
func collectUnquote(s string) (raw string, quoted bool) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", false
	}
	s = s[1 : len(s)-1]
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
			i++
		}
		sb.WriteByte(s[i])
	}
	return sb.String(), true
}

// collectTextMAC parses a MAC written as text: six groups of one or two hex
// digits separated by ':' or '-' (the unpadded net-snmp form included), or
// six two-digit groups separated by spaces.
func collectTextMAC(s string) ([6]byte, bool) {
	var b [6]byte
	s = strings.TrimSpace(s)
	sep := ":"
	switch {
	case strings.Count(s, "-") == 5:
		sep = "-"
	case strings.Count(s, " ") == 5:
		sep = " "
	}
	groups := strings.Split(s, sep)
	if len(groups) != 6 {
		return b, false
	}
	for i, g := range groups {
		if len(g) == 0 || len(g) > 2 || sep == " " && len(g) != 2 {
			return b, false
		}
		n, err := strconv.ParseUint(g, 16, 8)
		if err != nil {
			return b, false
		}
		b[i] = byte(n)
	}
	return b, true
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

// normalizeChassisID cleans up Hex-STRING output
func normalizeChassisID(val string) string {
	return normalizeMAC(val)
}

// collectMACTable collects MAC address table (FDB) from BRIDGE-MIB
func (s *SNMPObject) collectMACTable(ip string) ([]MACEntry, error) {
	// Walk dot1dTpFdbPort (.1.3.6.1.2.1.17.4.3.1.2) to get MAC->Port mapping
	// OID format: .1.3.6.1.2.1.17.4.3.1.2.M1.M2.M3.M4.M5.M6 = INTEGER: PortNum
	// where M1-M6 are the 6 bytes of MAC address

	lines, err := s.runSNMPWalk(ip, collectFDBPortOID)
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
		if !collectUsableMAC(macAddr) {
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
	// A trunk port will have multiple VLANs
	vlanEgressOID := ".1.3.6.1.2.1.17.7.1.4.2.1.4"
	vlanLines, _ := s.runSNMPWalk(ip, vlanEgressOID)

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

