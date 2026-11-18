package main

import (
	"cmp"
	"slices"
	"strings"
)

// haNodeRole describes a device's High-Availability (VRRP/HSRP) role and its
// associated floating virtual IPs.
type haNodeRole struct {
	Role string   // "active" or "passive"
	VIPs []string // sorted IPv4 addresses
}

// isVirtualRouterMAC reports whether mac (in any case/separator form) is a
// standard virtual router MAC address:
//   - RFC 5798 VRRP IPv4:  00:00:5e:00:01:xx
//   - RFC 5798 VRRP IPv6:  00:00:5e:00:02:xx
//   - Cisco HSRPv1:        00:00:0c:07:ac:xx
//   - Cisco HSRPv2:        00:00:0c:9f:f0:xx .. 00:00:0c:9f:ff:xx
//   - Cisco GLBP:          00:07:b4:00:xx:yy
func isVirtualRouterMAC(mac string) bool {
	c := canonicalMAC(mac)
	if c == "" {
		return false
	}
	return strings.HasPrefix(c, "00:00:5e:00:01:") ||
		strings.HasPrefix(c, "00:00:5e:00:02:") ||
		strings.HasPrefix(c, "00:00:0c:07:ac:") ||
		strings.HasPrefix(c, "00:00:0c:9f:f") ||
		strings.HasPrefix(c, "00:07:b4:00:")
}

// l3VLANKey canonicalizes an L3 SVI interface name ("Vlanif100", "Vlan100",
// "Vlan-interface100", "VLAN 100") to "vlan<N>". Non-SVI interfaces return "".
func l3VLANKey(ifDescr string) string {
	s := strings.ToLower(strings.Trim(ifDescr, "\" \t"))
	if !strings.HasPrefix(s, "vlan") {
		return ""
	}
	rest := strings.TrimPrefix(s, "vlan")
	rest = strings.TrimPrefix(rest, "-interface")
	rest = strings.TrimPrefix(rest, "if")
	rest = strings.TrimLeft(rest, "-_ ")
	if rest == "" {
		return ""
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return ""
		}
	}
	return "vlan" + strings.TrimLeft(rest, "0")
}

func sortUniqueVIPs(vips map[string]bool) []string {
	if len(vips) == 0 {
		return nil
	}
	out := make([]string, 0, len(vips))
	for ip := range vips {
		if parseIPv4(ip) != "" {
			out = append(out, ip)
		}
	}
	slices.SortFunc(out, compareIPs)
	return out
}

// computeHARoles classifies polled switches/routers in snapshot as "active"
// (VRRP/HSRP Master) or "passive" (pure VRRP/HSRP Backup/Standby), keyed by
// both graphDeviceNodeID(d) and d.IP.
//
// Primary source: SNMP VRRP-MIB (d.VRRPInfo). A device with >=1 master
// instance is "active"; one with 0 master instances and >=1 backup/initialize
// instances is "passive".
//
// Fallback source (when d.VRRPInfo is absent, e.g. cached snapshots before the
// next SNMP poll or HSRP/GLBP routers): compares operational L3 VLAN SVIs, ARP
// virtual-router MAC bindings, and FDB learned virtual-router MACs across L3
// routers (>=2 operational SVIs). A router that learns the virtual MACs on its
// SVIs while a peer L3 router shares those SVIs without learning them is
// "passive"; the owning peer is "active". Downstream L2 switches (1 management
// SVI) are never marked passive.
func computeHARoles(snapshot map[string]*DeviceData) map[string]haNodeRole {
	out := make(map[string]haNodeRole)
	if len(snapshot) == 0 {
		return out
	}

	ips := sortedDeviceIPs(snapshot)
	byIP := make(map[string]haNodeRole)

	// 1. Direct SNMP VRRP-MIB classification.
	for _, ip := range ips {
		d := snapshot[ip]
		if d == nil || d.VRRPInfo == nil || len(d.VRRPInfo.Instances) == 0 {
			continue
		}
		masters, backups := 0, 0
		vipSet := make(map[string]bool)
		for _, inst := range d.VRRPInfo.Instances {
			switch inst.State {
			case "master":
				masters++
			case "backup", "initialize":
				backups++
			}
			for _, vip := range inst.VIPs {
				vipSet[vip] = true
			}
		}
		role := ""
		if masters > 0 {
			role = "active"
		} else if backups > 0 {
			role = "passive"
		}
		if role != "" {
			byIP[ip] = haNodeRole{Role: role, VIPs: sortUniqueVIPs(vipSet)}
		}
	}

	// 2. FDB + ARP + L3 SVI fallback for devices without SNMP VRRPInfo.
	type arpVR struct {
		vip string
		mac string
	}
	vlanIfs := make(map[string]map[string]bool, len(ips))
	learnedVR := make(map[string]map[string]bool, len(ips))
	arpVRByVLAN := make(map[string]map[string]arpVR, len(ips))

	for _, ip := range ips {
		d := snapshot[ip]
		if d == nil {
			continue
		}
		ifByIdx := make(map[int]string)
		vset := make(map[string]bool)
		for _, iface := range d.Interfaces {
			if iface.IfOperStatus != 1 {
				continue
			}
			if key := l3VLANKey(iface.IfDescr); key != "" {
				vset[key] = true
				ifByIdx[iface.IfIndex] = key
			}
		}
		vlanIfs[ip] = vset

		fset := make(map[string]bool)
		for _, m := range d.MACTable {
			if isVirtualRouterMAC(m.MACAddress) {
				fset[canonicalMAC(m.MACAddress)] = true
			}
		}
		learnedVR[ip] = fset

		amap := make(map[string]arpVR)
		for _, a := range d.ARPTable {
			vkey := ifByIdx[a.Interface]
			cmac := canonicalMAC(a.MACAddress)
			if vkey != "" && isVirtualRouterMAC(cmac) && fset[cmac] {
				amap[vkey] = arpVR{vip: a.IPAddress, mac: cmac}
			}
		}
		arpVRByVLAN[ip] = amap
	}

	for _, ip := range ips {
		if _, already := byIP[ip]; already {
			continue
		}
		vset := vlanIfs[ip]
		if len(vset) < 2 {
			continue
		}
		masters, backups := 0, 0
		vipSet := make(map[string]bool)

		// Check SVIs where this L3 switch learns a virtual router MAC owned by a peer L3 switch.
		for vkey, entry := range arpVRByVLAN[ip] {
			ownedByPeer := false
			for _, peerIP := range ips {
				if peerIP == ip {
					continue
				}
				peerL3 := len(vlanIfs[peerIP]) >= 2 || byIP[peerIP].Role == "active"
				if peerL3 && vlanIfs[peerIP][vkey] && !learnedVR[peerIP][entry.mac] {
					ownedByPeer = true
					break
				}
			}
			if ownedByPeer {
				backups++
				vipSet[entry.vip] = true
			}
		}

		// Check SVIs where a peer L3 backup switch (>=2 virtual-MAC SVIs) learns our virtual MAC.
		for _, peerIP := range ips {
			if peerIP == ip || len(arpVRByVLAN[peerIP]) < 2 {
				continue
			}
			for vkey, entry := range arpVRByVLAN[peerIP] {
				if vset[vkey] && !learnedVR[ip][entry.mac] {
					masters++
					vipSet[entry.vip] = true
				}
			}
		}

		role := ""
		if masters > 0 {
			role = "active"
		} else if backups >= 2 {
			role = "passive"
		}
		if role != "" {
			byIP[ip] = haNodeRole{Role: role, VIPs: sortUniqueVIPs(vipSet)}
		}
	}

	for _, ip := range ips {
		r, ok := byIP[ip]
		if !ok || r.Role == "" {
			continue
		}
		d := snapshot[ip]
		if nodeID := graphDeviceNodeID(d); nodeID != "" {
			out[nodeID] = r
		}
		out[ip] = r
	}
	return out
}

// addHARoles annotates GraphData nodes with their HA role ("active" / "passive")
// and floating VIPs, and promotes data.Core to an active configured gateway
// when the first configured gateway has failed over to passive.
func addHARoles(data *GraphData, snapshot map[string]*DeviceData) {
	if data == nil || len(snapshot) == 0 {
		return
	}
	roles := computeHARoles(snapshot)
	if len(roles) == 0 {
		return
	}
	nodeRole := make(map[string]string, len(roles))
	for i := range data.Nodes {
		id := data.Nodes[i].ID
		r, ok := roles[id]
		if !ok && data.Nodes[i].IP != "" {
			r, ok = roles[data.Nodes[i].IP]
		}
		if ok {
			data.Nodes[i].HARole = r.Role
			data.Nodes[i].VIPs = r.VIPs
			nodeRole[id] = r.Role
		}
	}

	// If the primary configured gateway is currently passive (VRRP failover),
	// prefer an active configured gateway as the Tree root.
	if data.Core != "" && nodeRole[data.Core] == "passive" {
		nodeExists := make(map[string]bool, len(data.Nodes))
		for _, n := range data.Nodes {
			nodeExists[n.ID] = true
		}
		for _, gwIP := range gatewayList() {
			d, ok := snapshot[gwIP]
			if !ok || d == nil {
				continue
			}
			cand := cmp.Or(graphDeviceNodeID(d), gwIP)
			if nodeExists[cand] && nodeRole[cand] == "active" {
				data.Core = cand
				break
			}
		}
	}
}
