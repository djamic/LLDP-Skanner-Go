package voip

import (
	"regexp"
	"strings"

	"lldp_scanner/modules/kit"
)

// Yealink model and firmware patterns observed across T19/T2x/T3x/T4x/T5x/T6x,
// VP59, CP9xx conference phones, and W5x/W60/W70/W80/W90 DECT bases:
//   - SysName: "SIP-T30P", "SIP-T31P", "SIP-T34W", "SIP-T48U", "SIP-T57W", "VP59", "W70B"
//   - SysDesc: "124.85.0.35", "108.86.0.90", "96.86.0.75" (4-part dotted firmware)
//   - PortDesc: "WAN PORT"
var (
	yealinkModelRe    = regexp.MustCompile(`(?i)\b(SIP-(?:T\d{2}[A-Z0-9]*|VP\d+[A-Z0-9]*)|VP59|MP5\d[A-Z0-9]*|CP9\d{2}[A-Z0-9]*|W[56789]0[BP]|W5[236]P|T[23456]\d[A-Z]{1,2})\b`)
	yealinkFirmwareRe = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,4})\b`)
)

func init() {
	RegisterRule(Rule{
		ID:               "yealink",
		Brand:            "Yealink",
		Priority:         100,
		DedicatedVendors: []string{"yealink"},
		Match:            matchYealink,
	})
}

func matchYealink(ev Evidence) (model, firmware string, ok bool) {
	isVendor := kit.HasWord(ev.Vendor, "yealink") ||
		kit.HasWord(ev.SysName, "yealink") ||
		kit.HasWord(ev.SysDesc, "yealink")

	combined := strings.TrimSpace(ev.SysName + " " + firstLine(ev.SysDesc))
	if m := yealinkModelRe.FindStringSubmatch(combined); len(m) > 1 {
		candidate := strings.ToUpper(m[1])
		// Bare TxxX tokens without "SIP-" require Yealink vendor or CapPhone
		if strings.HasPrefix(candidate, "SIP-") || isVendor || ev.Capabilities&CapPhone != 0 {
			model = candidate
		}
	}

	if !isVendor && model == "" {
		return "", "", false
	}

	if model == "" {
		sn := strings.TrimSpace(ev.SysName)
		if sn != "" && !strings.Contains(sn, " ") {
			model = sn
		}
	}

	desc := firstLine(ev.SysDesc)
	if m := yealinkFirmwareRe.FindStringSubmatch(desc); len(m) > 1 {
		firmware = m[1]
	} else if desc != "" && !strings.EqualFold(desc, model) && !kit.HasWord(desc, "yealink") {
		firmware = desc
	}

	return model, firmware, true
}
