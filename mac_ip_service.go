package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ─── ESXi HTTP Fingerprinting ──────────────────────────────────────────────────
var ConfirmedESXiMACs sync.Map
var validationQueue = make(chan esxiJob, 2000)

type esxiJob struct {
	mac string
	ip  string
}

func init() {
	// Start 100 background workers for fast LAN ESXi HTTP fingerprinting
	for i := 0; i < 100; i++ {
		go esxiCheckWorker()
	}
}

func esxiCheckWorker() {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 1 * time.Second,
		},
	}
	for job := range validationQueue {
		// Fast port 443 check (500ms is plenty for local network)
		conn, err := net.DialTimeout("tcp", job.ip+":443", 500*time.Millisecond)
		if err != nil {
			continue
		}
		conn.Close()

		// HTTP GET /ui/ check
		req, _ := http.NewRequest("GET", "https://"+job.ip+"/ui/", nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(bodyBytes)
		if strings.Contains(bodyStr, "esxUiApp") || strings.Contains(bodyStr, "VMware ESXi") {
			fmt.Printf("✅ [Active-Check] Confirmed ESXi via HTTP: %s (MAC: %s)\n", job.ip, job.mac)
			ConfirmedESXiMACs.Store(job.mac, true)
		}
	}
}

func queueESXiValidation(mac, ip string) {
	if _, loaded := ConfirmedESXiMACs.Load(mac); !loaded {
		select {
		case validationQueue <- esxiJob{mac: mac, ip: ip}:
			// sent successfully
		default:
			// queue is full, spawn a background goroutine to avoid blocking
			go func(m, i string) {
				validationQueue <- esxiJob{mac: m, ip: i}
			}(mac, ip)
		}
	}
}


// ─── MAC-IP Cache ──────────────────────────────────────────────────────────────

// macIPCacheFile is the persistent JSON cache path
const macIPCacheFile = "mac_ip_cache.json"

// macIPServiceMu protects macIPServiceRunning flag
var macIPServiceRunning bool
var macIPServiceMu sync.Mutex

// loadMacIPCache loads mac→ip mappings from JSON file into globalMACtoIP
func loadMacIPCache() {
	data, err := os.ReadFile(macIPCacheFile)
	if err != nil {
		// File doesn't exist yet — not an error
		return
	}
	var cache map[string]string
	if err := json.Unmarshal(data, &cache); err != nil {
		fmt.Printf("⚠️ [MacIPService] Failed to parse %s: %v\n", macIPCacheFile, err)
		return
	}
	globalMACtoIPMutex.Lock()
	loaded := 0
	for mac, ip := range cache {
		if globalMACtoIP[mac] == "" {
			globalMACtoIP[mac] = ip
			queueESXiValidation(mac, ip) // Send to validation queue
			loaded++
		}
	}
	globalMACtoIPMutex.Unlock()
	fmt.Printf("📂 [MacIPService] Loaded %d MAC-IP entries from cache\n", loaded)
}

// saveMacIPCache saves globalMACtoIP to JSON file atomically
func saveMacIPCache() {
	globalMACtoIPMutex.RLock()
	snapshot := make(map[string]string, len(globalMACtoIP))
	for k, v := range globalMACtoIP {
		snapshot[k] = v
	}
	globalMACtoIPMutex.RUnlock()

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	// Write to temp file then rename — atomic write
	tmp := macIPCacheFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	os.Rename(tmp, macIPCacheFile)
}

// ─── ARP Collection from all switches ─────────────────────────────────────────

// collectARPFromSwitch collects ARP table from a single switch IP and
// merges results into globalMACtoIP. Returns number of new entries added.
func collectARPFromSwitch(snmpObj *SNMPObject, ip string) int {
	entries, err := snmpObj.collectARPTable(ip)
	if err != nil {
		return 0
	}

	newEntries := 0
	globalMACtoIPMutex.Lock()
	for _, e := range entries {
		mac := normalizeMAC(e.MACAddress)
		if mac == "" {
			continue
		}
		if globalMACtoIP[mac] == "" {
			globalMACtoIP[mac] = e.IPAddress
			newEntries++
			queueESXiValidation(mac, e.IPAddress) // Check new IP for ESXi
		}
	}
	globalMACtoIPMutex.Unlock()
	return newEntries
}

// collectARPFromAllSwitches collects ARP from gateway (all SVI IPs) + all discovered switches
func collectARPFromAllSwitches() {
	snmpObj := &SNMPObject{
		Community: "public",
		Port:      161,
		Timeout:   10 * time.Second,
		Retries:   1,
	}

	totalNew := 0

	// 1. Gateway — collect from its own IP first
	n := collectARPFromSwitch(snmpObj, gatewayIP)
	if n > 0 {
		fmt.Printf("🌐 [MacIPService] Gateway %s: +%d new MAC-IP entries\n", gatewayIP, n)
		totalNew += n
	}

	// 2. Gateway SVI IPs — gateway may route multiple VLANs (172.20.x.x, 10.20.x.x...)
	//    Query ipAddrTable to find all its interface IPs and collect ARP from each
	sviIPs := collectGatewaySVIIPs(snmpObj, gatewayIP)
	for _, svi := range sviIPs {
		if svi == gatewayIP {
			continue // already done above
		}
		n := collectARPFromSwitch(snmpObj, svi)
		if n > 0 {
			fmt.Printf("🌐 [MacIPService] Gateway SVI %s: +%d new MAC-IP entries\n", svi, n)
			totalNew += n
		}
	}

	// 3. All discovered switches
	collectedDataMutex.RLock()
	switchIPs := make([]string, 0, len(collectedData))
	for ip := range collectedData {
		if ip != gatewayIP {
			switchIPs = append(switchIPs, ip)
		}
	}
	collectedDataMutex.RUnlock()

	for _, ip := range switchIPs {
		n := collectARPFromSwitch(snmpObj, ip)
		if n > 0 {
			fmt.Printf("🔗 [MacIPService] Switch %s: +%d new MAC-IP entries\n", ip, n)
			totalNew += n
		}
	}

	if totalNew > 0 {
		fmt.Printf("✅ [MacIPService] Total new: %d entries. Saving cache...\n", totalNew)
		saveMacIPCache()
		// Note: IP enrichment happens automatically during rebuildGraph()
	}
}

// collectGatewaySVIIPs returns all IP addresses configured on the gateway device.
// Uses ipAddrTable (.1.3.6.1.2.1.4.20.1.2) — returns interface addresses (SVI/VLAN IPs).
// This allows ARP collection from each routed VLAN interface.
func collectGatewaySVIIPs(snmpObj *SNMPObject, gwIP string) []string {
	lines, err := snmpObj.runSNMPWalk(gwIP, ".1.3.6.1.2.1.4.20.1.2")
	if err != nil {
		return []string{gwIP}
	}
	ips := []string{gwIP}
	seen := map[string]bool{gwIP: true}
	for _, line := range lines {
		// OID: .1.3.6.1.2.1.4.20.1.2.<ip1>.<ip2>.<ip3>.<ip4> = ifIndex
		// IP is in the OID itself
		oid, _, err := parseSNMPLine(line)
		if err != nil {
			continue
		}
		parts := strings.Split(oid, ".")
		if len(parts) < 4 {
			continue
		}
		// Last 4 parts of OID are the IP octets
		ipStr := strings.Join(parts[len(parts)-4:], ".")
		if net := parseIPv4(ipStr); net != "" && !seen[net] {
			// Skip link-local, loopback, multicast
			if !strings.HasPrefix(net, "127.") &&
				!strings.HasPrefix(net, "169.254.") &&
				!strings.HasPrefix(net, "224.") &&
				net != "0.0.0.0" {
				ips = append(ips, net)
				seen[net] = true
				fmt.Printf("📡 [MacIPService] Found gateway SVI IP: %s\n", net)
			}
		}
	}
	return ips
}

// parseIPv4 validates and returns an IPv4 string, or empty string if invalid.
func parseIPv4(s string) string {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return ""
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return ""
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return ""
			}
		}
	}
	return s
}

// ─── Gateway Subnet Discovery ──────────────────────────────────────────────────

// SubnetInfo holds IP + prefix length from gateway ipAddr table
type SubnetInfo struct {
	IP     string
	Prefix int
	Net    string // network address e.g. "172.20.0.0"
}

// discoverGatewaySubnets reads gateway ipAddrTable + netmask, returns all subnets
func discoverGatewaySubnets(snmpObj *SNMPObject, gwIP string) []SubnetInfo {
	// Get IP list from ipAddrTable (.1.3.6.1.2.1.4.20.1.1)
	maskLines, err := snmpObj.runSNMPWalk(gwIP, ".1.3.6.1.2.1.4.20.1.3")
	if err != nil {
		return nil
	}
	var subnets []SubnetInfo
	for _, line := range maskLines {
		oid, val, err := parseSNMPLine(line)
		if err != nil {
			continue
		}
		parts := strings.Split(oid, ".")
		if len(parts) < 4 {
			continue
		}
		ipStr := strings.Join(parts[len(parts)-4:], ".")
		if parseIPv4(ipStr) == "" {
			continue
		}
		// Skip loopback
		if strings.HasPrefix(ipStr, "127.") {
			continue
		}
		maskStr := strings.TrimSpace(val)
		// Count prefix bits
		bits := 0
		for _, oct := range strings.Split(maskStr, ".") {
			var n int
			fmt.Sscanf(oct, "%d", &n)
			bits += countBits(n)
		}
		// Compute network address
		ipParts := strings.Split(ipStr, ".")
		maskParts := strings.Split(maskStr, ".")
		if len(ipParts) != 4 || len(maskParts) != 4 {
			continue
		}
		netParts := make([]string, 4)
		for i := 0; i < 4; i++ {
			var a, b int
			fmt.Sscanf(ipParts[i], "%d", &a)
			fmt.Sscanf(maskParts[i], "%d", &b)
			netParts[i] = fmt.Sprintf("%d", a&b)
		}
		netStr := strings.Join(netParts, ".")
		subnets = append(subnets, SubnetInfo{IP: ipStr, Prefix: bits, Net: netStr})
		fmt.Printf("📡 [SubnetDisc] Found subnet: %s/%d (gateway SVI: %s)\n", netStr, bits, ipStr)
	}
	return subnets
}

// countBits counts set bits in an integer (for mask)
func countBits(n int) int {
	count := 0
	for n > 0 {
		count += n & 1
		n >>= 1
	}
	return count
}

// probeSubnetForSwitches probes a subnet for SNMP-capable devices.
// For small subnets (/22 or less = ≤1022 hosts), scans all IPs.
// For large subnets, only probes IPs known from ARP cache.
func probeSubnetForSwitches(snmpObj *SNMPObject, subnet SubnetInfo) []string {
	var newSwitchIPs []string

	// Get existing known IPs from collectedData
	collectedDataMutex.RLock()
	knownIPs := make(map[string]bool, len(collectedData))
	for ip := range collectedData {
		knownIPs[ip] = true
	}
	collectedDataMutex.RUnlock()

	// For large subnets, only probe IPs from ARP cache
	var candidateIPs []string
	if subnet.Prefix < 22 {
		// Large subnet: use ARP cache IPs in this subnet
		globalMACtoIPMutex.RLock()
		for _, ip := range globalMACtoIP {
			if isIPInSubnet(ip, subnet.Net, subnet.Prefix) {
				candidateIPs = append(candidateIPs, ip)
			}
		}
		globalMACtoIPMutex.RUnlock()
		fmt.Printf("📡 [SubnetDisc] Large subnet %s/%d — probing %d ARP-known IPs\n",
			subnet.Net, subnet.Prefix, len(candidateIPs))
	} else {
		// Small subnet: generate all host IPs
		candidateIPs = generateSubnetIPs(subnet.Net, subnet.Prefix)
		fmt.Printf("📡 [SubnetDisc] Small subnet %s/%d — probing %d IPs\n",
			subnet.Net, subnet.Prefix, len(candidateIPs))
	}

	for _, ip := range candidateIPs {
		if knownIPs[ip] || ip == gatewayIP {
			continue
		}
		// Quick SNMP probe: request sysDescr via walk (1 OID)
		lines, err := snmpObj.runSNMPWalk(ip, ".1.3.6.1.2.1.1.1.0")
		if err == nil && len(lines) > 0 {
			fmt.Printf("✅ [SubnetDisc] New SNMP device found: %s — adding to scan list\n", ip)
			newSwitchIPs = append(newSwitchIPs, ip)
		}
	}
	return newSwitchIPs
}

// isIPInSubnet checks if an IP is in a given network/prefix
func isIPInSubnet(ip, net string, prefix int) bool {
	ipP := strings.Split(ip, ".")
	netP := strings.Split(net, ".")
	if len(ipP) != 4 || len(netP) != 4 {
		return false
	}
	fullBits := prefix
	for i := 0; i < 4; i++ {
		bits := 8
		if fullBits <= 0 {
			break
		}
		if fullBits < 8 {
			bits = fullBits
		}
		var a, b int
		fmt.Sscanf(ipP[i], "%d", &a)
		fmt.Sscanf(netP[i], "%d", &b)
		mask := (0xFF << (8 - bits)) & 0xFF
		if (a & mask) != (b & mask) {
			return false
		}
		fullBits -= bits
	}
	return true
}

// generateSubnetIPs generates all host IPs in a /prefix subnet
func generateSubnetIPs(net string, prefix int) []string {
	if prefix < 22 {
		return nil // too large
	}
	parts := strings.Split(net, ".")
	if len(parts) != 4 {
		return nil
	}
	// Convert to uint32
	var base uint32
	for _, p := range parts {
		var n int
		fmt.Sscanf(p, "%d", &n)
		base = (base << 8) | uint32(n)
	}
	hostBits := 32 - prefix
	count := uint32(1) << hostBits
	ips := make([]string, 0, count-2)
	for i := uint32(1); i < count-1; i++ {
		addr := base | i
		ip := fmt.Sprintf("%d.%d.%d.%d", (addr>>24)&0xFF, (addr>>16)&0xFF, (addr>>8)&0xFF, addr&0xFF)
		ips = append(ips, ip)
	}
	return ips
}

// RunSubnetDiscovery discovers new SNMP switches from gateway subnets
// and adds them to swich_ips for future scanning
func RunSubnetDiscovery() {
	snmpObj := &SNMPObject{
		Community: "public",
		Port:      161,
		Timeout:   3 * time.Second,
		Retries:   0,
	}

	subnets := discoverGatewaySubnets(snmpObj, gatewayIP)
	if len(subnets) == 0 {
		return
	}

	var allNew []string
	for _, s := range subnets {
		if s.Prefix < 16 {
			continue // skip /8, /12 etc — too large, no use
		}
		new := probeSubnetForSwitches(snmpObj, s)
		allNew = append(allNew, new...)
	}

	if len(allNew) == 0 {
		fmt.Println("📡 [SubnetDisc] No new SNMP devices found in gateway subnets")
		return
	}

	// Append to swich_ips
	f, err := os.OpenFile("swich_ips", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("⚠️ [SubnetDisc] Cannot open swich_ips: %v\n", err)
		return
	}
	defer f.Close()
	added := 0
	for _, ip := range allNew {
		fmt.Fprintf(f, "%s\n", ip)
		added++
	}
	fmt.Printf("✅ [SubnetDisc] Added %d new devices to swich_ips\n", added)
}

// ─── Graph Enrichment ──────────────────────────────────────────────────────────

// enrichGraphWithIPs adds IP labels to graph nodes whose MAC is in globalMACtoIP.
// Called after detectHypervisors() so VM and hypervisor nodes get IPs too.
func enrichGraphWithIPs(graph *DJGraph) {
	if graph == nil {
		return
	}

	globalMACtoIPMutex.RLock()
	ipMap := make(map[string]string, len(globalMACtoIP))
	for k, v := range globalMACtoIP {
		ipMap[k] = v
	}
	globalMACtoIPMutex.RUnlock()

	enriched := 0
	for mac := range graph.Nodes {
		ip := ipMap[mac] // may be empty
		info := graph.SwitchInfo[mac]
		changed := false

		// Check if actively confirmed ESXi (works even without IP)
		if _, isESXi := ConfirmedESXiMACs.Load(mac); isESXi {
			if !strings.Contains(info, "[HYPERVISOR]") && !strings.Contains(info, "vmnic") && !strings.Contains(info, "[SWITCH]") {
				info = "[HYPERVISOR] VMware ESXi\n" + info
				changed = true
			}
		}

		// Add IP label if available and not duplicate
		if ip != "" && !strings.Contains(info, ip) {
			info = info + "\n" + ip
			changed = true
		}

		if changed {
			graph.SwitchInfo[mac] = info
			enriched++
		}
	}

	// Also enrich hypervisor nodes — list VM IPs in their label
	for nodeID := range graph.Nodes {
		if !strings.HasPrefix(nodeID, "hyp-") {
			continue
		}
		// Find VM MACs connected to this hypervisor
		vmIPs := []string{}
		for vmMAC, edgeLabel := range graph.Edges[nodeID] {
			if edgeLabel == "vNIC" {
				if ip, ok := ipMap[vmMAC]; ok && ip != "" {
					vmIPs = append(vmIPs, ip)
				}
			}
		}
		if len(vmIPs) > 0 {
			info := graph.SwitchInfo[nodeID]
			ipLine := "VMs: " + strings.Join(vmIPs, ", ")
			if !strings.Contains(info, "VMs:") {
				graph.SwitchInfo[nodeID] = info + "\n" + ipLine
			}
		}
	}

	if enriched > 0 {
		fmt.Printf("🖊️  [MacIPService] Enriched %d graph nodes with IPs\n", enriched)
	}
}

// ─── Service Goroutine ─────────────────────────────────────────────────────────

// startMacIPService starts a background goroutine that periodically collects
// ARP tables from gateway and all discovered switches. Safe to call once.
func startMacIPService() {
	macIPServiceMu.Lock()
	if macIPServiceRunning {
		macIPServiceMu.Unlock()
		return
	}
	macIPServiceRunning = true
	macIPServiceMu.Unlock()

	// Load persistent cache first
	loadMacIPCache()

	go func() {
		fmt.Println("🚀 [MacIPService] Started — collecting ARP from all switches every 5 min")

		// First run immediately
		collectARPFromAllSwitches()

		// Discover new SNMP devices from gateway subnets (one-time after first ARP)
		go func() {
			time.Sleep(10 * time.Second) // wait for ARP cache to populate
			fmt.Println("🔍 [SubnetDisc] Starting gateway subnet discovery...")
			RunSubnetDiscovery()
		}()

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			fmt.Println("⏱️  [MacIPService] Periodic ARP collection started...")
			collectARPFromAllSwitches()
		}
	}()
}

// TriggerMacIPCollection can be called externally to force an immediate ARP sweep
// (e.g. after a new switch is discovered)
func TriggerMacIPCollection() {
	go collectARPFromAllSwitches()
}
