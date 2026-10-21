package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// ScanEvent represents different event types during scanning
type ScanEvent int

const (
	EventHostFound ScanEvent = iota
	EventSNMPSuccess
	EventSNMPFailure
	EventScanComplete
)

// ScanResult contains information about a scan result
type ScanResult struct {
	Event     ScanEvent
	IP        string
	Message   string
	Error     error
	SysDescr  string
	SysName   string
	SysUpTime uint32
	Timestamp time.Time
}

// SNMPScanner is the main scanner class
type SNMPScanner struct {
	Community      string
	Port           uint16
	Timeout        time.Duration
	Retries        int
	MaxWorkers     int
	MaxRepetitions uint32 // Max OIDs per GetBulk
	PingTimeout    time.Duration
	UsePing        bool // If true, use ICMP ping before SNMP check
	ResultCallback func(result ScanResult)
	wg             sync.WaitGroup
}

// NewSNMPScanner creates a new SNMP scanner with default settings
func NewSNMPScanner(callback func(result ScanResult)) *SNMPScanner {
	return &SNMPScanner{
		ResultCallback: callback,
		Community:      "public",
		Port:           161,
		Timeout:        2 * time.Second,
		Retries:        1,
		MaxWorkers:     50,
		MaxRepetitions: 10, // Safe default for bulk
		PingTimeout:    1 * time.Second,
		UsePing:        true, // Default: ICMP ping first to filter dead hosts
	}
}

// ReadIPsFromFile reads IP addresses and networks from a file
func (s *SNMPScanner) ReadIPsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips = append(ips, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return ips, nil
}

// ExpandNetworks converts CIDR networks to individual IP addresses
func (s *SNMPScanner) ExpandNetworks(entries []string) ([]string, error) {
	var allIPs []string

	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			// CIDR notation
			ips, err := s.expandCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("failed to expand CIDR %s: %w", entry, err)
			}
			allIPs = append(allIPs, ips...)
		} else {
			// Single IP address
			allIPs = append(allIPs, entry)
		}
	}

	return allIPs, nil
}

// expandCIDR expands a CIDR notation into individual IP addresses
func (s *SNMPScanner) expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// isHostAlive checks if a host is reachable
func (s *SNMPScanner) isHostAlive(ip string) bool {
	if s.UsePing {
		// Use ICMP Ping
		return s.pingHost(ip)
	}
	// Use simple UDP port check (fast but less accurate)
	address := fmt.Sprintf("%s:%d", ip, s.Port)
	conn, err := net.DialTimeout("udp", address, s.PingTimeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// pingHost performs an ICMP ping using system ping command (reliable)
func (s *SNMPScanner) pingHost(ip string) bool {
	timeoutMs := int(s.PingTimeout.Milliseconds())
	if timeoutMs < 500 {
		timeoutMs = 500
	}
	deadlineSec := fmt.Sprintf("%d", (timeoutMs/1000)+1)
	cmd := exec.Command("ping", "-c", "1", "-W", deadlineSec, ip)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return false
	}
	done := make(chan error, 1)
	timer := time.AfterFunc(time.Duration(timeoutMs+1000)*time.Millisecond, func() {
		_ = cmd.Process.Kill()
	})
	go func() { done <- cmd.Wait() }()
	err := <-done
	timer.Stop()
	return err == nil
}

// Connect creates a new GoSNMP session
func (s *SNMPScanner) Connect(ip string) (*gosnmp.GoSNMP, error) {
	params := &gosnmp.GoSNMP{
		Target:         ip,
		Port:           161, // Default SNMP port
		Community:      s.Community,
		Version:        gosnmp.Version2c,
		Timeout:        s.Timeout,
		Retries:        1, // Minimal retries for fast scanning
		MaxRepetitions: s.MaxRepetitions,
	}
	err := params.Connect()
	if err != nil {
		return nil, err
	}
	return params, nil
}

// testSNMP tests SNMP connectivity to a host
func (s *SNMPScanner) testSNMP(ip string) error {
	target, err := s.Connect(ip)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer target.Conn.Close()

	// Try to get system information
	oids := []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.5.0", // sysName
		"1.3.6.1.2.1.1.3.0", // sysUpTime
	}

	result, err := target.Get(oids)
	if err != nil {
		return fmt.Errorf("SNMP GET failed: %w", err)
	}

	// Extract system information
	scanResult := ScanResult{
		Event:     EventSNMPSuccess,
		IP:        ip,
		Timestamp: time.Now(),
	}

	if len(result.Variables) > 0 {
		if result.Variables[0].Value != nil {
			scanResult.SysDescr = fmt.Sprintf("%s", result.Variables[0].Value)
		}
	}
	if len(result.Variables) > 1 {
		if result.Variables[1].Value != nil {
			scanResult.SysName = fmt.Sprintf("%s", result.Variables[1].Value)
		}
	}
	if len(result.Variables) > 2 {
		if result.Variables[2].Value != nil {
			if uptime, ok := result.Variables[2].Value.(uint32); ok {
				scanResult.SysUpTime = uptime
			}
		}
	}

	scanResult.Message = fmt.Sprintf("SNMP connection successful - Name: %s", scanResult.SysName)
	s.sendCallback(scanResult)

	return nil
}

// sendCallback safely sends a callback to the user-defined function
func (s *SNMPScanner) sendCallback(result ScanResult) {
	if s.ResultCallback != nil {
		s.ResultCallback(result)
	}
}

// scanIP scans a single IP address
func (s *SNMPScanner) scanIP(ip string) {
	defer s.wg.Done()

	// Check if host is alive
	if !s.isHostAlive(ip) {
		return // Silently skip unreachable hosts
	}

	// Send host found event
	s.sendCallback(ScanResult{
		Event:     EventHostFound,
		IP:        ip,
		Message:   "Host is reachable",
		Timestamp: time.Now(),
	})

	// Test SNMP connectivity
	err := s.testSNMP(ip)
	if err != nil {
		s.sendCallback(ScanResult{
			Event:     EventSNMPFailure,
			IP:        ip,
			Message:   "SNMP connection failed",
			Error:     err,
			Timestamp: time.Now(),
		})
	}
}

// Scan starts the scanning process
func (s *SNMPScanner) Scan(ips []string) {
	// Create worker pool
	workerChan := make(chan string, len(ips))

	// Start workers
	for i := 0; i < s.MaxWorkers; i++ {
		go func() {
			for ip := range workerChan {
				s.scanIP(ip)
			}
		}()
	}

	// Add IPs to worker channel
	for _, ip := range ips {
		s.wg.Add(1)
		workerChan <- ip
	}

	// Wait for all scans to complete
	s.wg.Wait()
	close(workerChan)

	// Send scan complete event
	s.sendCallback(ScanResult{
		Event:     EventScanComplete,
		Message:   fmt.Sprintf("Scan completed. Total IPs scanned: %d", len(ips)),
		Timestamp: time.Now(),
	})
}

// ScanFromFile reads IPs from file and starts scanning
func (s *SNMPScanner) ScanFromFile(filename string) error {
	// Read IPs from file
	entries, err := s.ReadIPsFromFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read IPs from file: %w", err)
	}

	// Expand networks to individual IPs
	ips, err := s.ExpandNetworks(entries)
	if err != nil {
		return fmt.Errorf("failed to expand networks: %w", err)
	}

	// Start scanning
	s.Scan(ips)

	return nil
}
