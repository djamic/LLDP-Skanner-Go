package voip

import (
	"regexp"
	"strings"
)

// Grandstream VoIP phones, video phones, DECT, Wi-Fi phones, and ATAs:
//   - SysName: "GRP2613_c0:74:ad:00:00:11", "GXP1625_c0:74:ad:00:00:12"
//   - SysDesc: "GRP2613 1.0.7.33", "GXP1625 1.0.7.8", "GRP2614 1.0.9.99"
//   - PortDesc: "eth0"
//   - Non-phone exclusions: GWN76xx access points, GWN78xx switches, GWN70xx routers
var (
	grandstreamPhoneRe   = regexp.MustCompile(`(?i)\b(GXP\d{4}[A-Z0-9]*|GRP\d{4}[A-Z0-9]*|GXV\d{4}[A-Z0-9]*|DP7\d{2}[A-Z0-9]*|WP8\d{2}[A-Z0-9]*|GAC\d{4}[A-Z0-9]*|GHP\d{3}[A-Z0-9]*|HT8\d{2}[A-Z0-9]*|GXW\d{4}[A-Z0-9]*)\b`)
	grandstreamExcludeRe = regexp.MustCompile(`(?i)\bGWN(?:70|76|77|78)\d{2}[A-Z0-9]*\b`)
	grandstreamVerRe     = regexp.MustCompile(`\b(\d+\.\d+\.\d+\.\d+)\b`)
)

func init() {
	RegisterRule(Rule{
		ID:               "grandstream",
		Brand:            "Grandstream",
		Priority:         100,
		DedicatedVendors: []string{"grandstream"},
		Exclude: func(ev Evidence) bool {
			return grandstreamExcludeRe.MatchString(ev.SysName) || grandstreamExcludeRe.MatchString(ev.SysDesc)
		},
		Match: matchGrandstream,
	})
}

func matchGrandstream(ev Evidence) (model, firmware string, ok bool) {
	isVendor := HasWord(ev.Vendor, "grandstream") ||
		HasWord(ev.SysName, "grandstream") ||
		HasWord(ev.SysDesc, "grandstream")

	// Try SysDesc first ("GRP2613 1.0.7.33") then SysName ("GRP2613_c0:74:ad:...")
	desc := firstLine(ev.SysDesc)
	sn := strings.TrimSpace(ev.SysName)
	if idx := strings.IndexByte(sn, '_'); idx > 0 {
		sn = sn[:idx]
	}

	for _, src := range []string{desc, sn, ev.SysName} {
		if m := grandstreamPhoneRe.FindStringSubmatch(src); len(m) > 1 {
			model = strings.ToUpper(m[1])
			break
		}
	}

	if !isVendor && model == "" {
		return "", "", false
	}

	if model == "" && sn != "" && !strings.Contains(sn, " ") {
		model = sn
	}

	if m := grandstreamVerRe.FindStringSubmatch(desc); len(m) > 1 {
		firmware = m[1]
	} else if model != "" && strings.HasPrefix(strings.ToUpper(desc), model+" ") {
		firmware = strings.TrimSpace(desc[len(model):])
	}

	return model, firmware, true
}
