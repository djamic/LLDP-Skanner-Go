package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
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

	// Convert map to slice
	result := make([]LLDPNeighbor, 0, len(neighborMap))
	for _, n := range neighborMap {
		logDebug("  [SNMP-RAW] %s: Neighbor on LocalPort %d -> RemChassis: %s (Subtype: %d), RemPort: %s",
			ip, n.LocalPortNum, n.RemChassisId, n.RemChassisIdSubtype, n.RemPortId)
		result = append(result, *n)
	}

	// Collect Management Addresses and populate RemMgmtIP
	if err := s.enrichWithManagementIPs(ip, neighborMap); err != nil {
		// Non-fatal, just log
		fmt.Printf("Warning: Failed to collect management IPs for %s: %v\n", ip, err)
	}

	// Re-convert to slice after enrichment
	result = make([]LLDPNeighbor, 0, len(neighborMap))
	for _, n := range neighborMap {
		result = append(result, *n)
	}

	return result, nil
}

// enrichWithManagementIPs collects Management IP addresses from lldpRemManAddrTable
func (s *SNMPObject) enrichWithManagementIPs(ip string, neighborMap map[string]*LLDPNeighbor) error {
	// Walk lldpRemManAddrTable (.1.0.8802.1.1.2.1.4.2.1)
	lines, err := s.runSNMPWalk(ip, ".1.0.8802.1.1.2.1.4.2.1")
	if err != nil {
		return err
	}

	for _, line := range lines {
		oid, _, err := parseSNMPLine(line)
		if err != nil {
			continue
		}

		// OID format: .1.0.8802.1.1.2.1.4.2.1.COLUMN.TimeMark.LocalPort.RemIndex.AddrSubtype.Address
		// We're interested in column 3 (lldpRemManAddrIfSubtype) which contains the address type
		// The actual IP is embedded in the OID itself as the last components

		parts := strings.Split(oid, ".")
		if len(parts) < 18 {
			continue
		}

		// Extract indices
		// Last 4 octets are the IP address (for IPv4)
		// Format: ...TimeMark.LocalPort.RemIndex.1.A.B.C.D
		// where 1 is IPv4 address subtype

		// Find column number
		colStr := parts[12] // Column is at fixed position after base OID
		col, _ := strconv.Atoi(colStr)

		if col != 3 { // We only care about column 3 (lldpRemManAddrIfSubtype)
			continue
		}

		// Extract TimeMark, LocalPort, RemIndex
		localPortStr := parts[14]
		remIdxStr := parts[15]
		addrSubtype := parts[16]

		key := fmt.Sprintf("%s.%s", localPortStr, remIdxStr)

		if neighbor, exists := neighborMap[key]; exists {
			// Check if it's IPv4 (subtype 1)
			if addrSubtype == "1" && len(parts) >= 20 {
				// Extract IP from last 4 octets
				ipAddr := fmt.Sprintf("%s.%s.%s.%s", parts[17], parts[18], parts[19], parts[20])
				neighbor.RemMgmtIP = ipAddr
			}
		}
	}

	return nil
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

	lines, err := s.runSNMPWalk(ip, ".1.3.6.1.2.1.17.4.3.1.2")
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
		parts := strings.Split(oid, ".")
		if len(parts) < 17 {
			continue
		}

		// Last 6 parts are MAC address bytes
		macParts := parts[len(parts)-6:]
		macBytes := make([]string, 6)
		for i, p := range macParts {
			b, _ := strconv.Atoi(p)
			macBytes[i] = fmt.Sprintf("%02x", b)
		}
		macAddr := strings.Join(macBytes, ":")

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

	lines, err := s.runSNMPWalk(ip, ".1.3.6.1.2.1.4.22.1.2")
	if err != nil {
		return nil, err
	}

	result := []ARPEntry{}

	for _, line := range lines {
		oid, val, err := parseSNMPLine(line)
		if err != nil {
			continue
		}

		// Extract IP address from OID
		// OID: .1.3.6.1.2.1.4.22.1.2.1.192.168.1.100
		parts := strings.Split(oid, ".")
		if len(parts) < 15 {
			continue
		}

		// Last 4 parts are IP address octets, part before that is interface index
		ipParts := parts[len(parts)-4:]
		ipAddr := strings.Join(ipParts, ".")

		// Interface index is before IP
		ifIndex, _ := strconv.Atoi(parts[len(parts)-5])

		// Parse MAC address from value (Hex-STRING format)
		// Value: "4C AE A3 8E 42 11" or similar
		val = strings.TrimPrefix(val, "Hex-STRING: ")
		val = strings.TrimPrefix(val, "STRING: ")
		val = strings.Trim(val, "\"")

		// Convert hex string to MAC format
		macAddr := normalizeChassisID(val)

		// Skip incomplete entries
		if len(macAddr) < 17 {
			continue
		}
		
		// Skip invalid IPs
		if ipAddr == "0.0.0.0" || strings.HasPrefix(ipAddr, "0.") {
			continue
		}

		// Skip broadcast/null MACs
		if macAddr == "00:00:00:00:00:00" || macAddr == "ff:ff:ff:ff:ff:ff" {
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

