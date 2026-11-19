package voip

import (
	"regexp"
	"strings"
)

var (
	avayaModelRe     = regexp.MustCompile(`(?i)\b(AVX[A-Z0-9]{4,}|J1[235678]9|96[01245]1G?|96[02345]8G?|B1[789]9)\b`)
	panasonicModelRe = regexp.MustCompile(`(?i)\b(KX-(?:HDV|UT|NT|TGP|TPA)\d{2,4}[A-Z0-9]*)\b`)
	ciscoPhoneModelRe = regexp.MustCompile(`(?i)\b(CP-\d{4}[A-Z0-9]*)\b`)
	fanvilModelRe     = regexp.MustCompile(`(?i)\b(X[1-7][A-Z0-9]{0,3}|V6[1-7][A-Z0-9]*|H[2358]\d?[A-Z0-9]*|i[1-6]\d[A-Z0-9]*)\b`)
)

func init() {
	// Avaya IP phones (e.g. AVXC28D65, J100/9600 series)
	RegisterRule(Rule{
		ID:               "avaya",
		Brand:            "Avaya",
		Priority:         90,
		DedicatedVendors: []string{"avaya"},
		Exclude: func(ev Evidence) bool {
			low := strings.ToLower(ev.SysDesc + " " + ev.SysName)
			return strings.Contains(low, "ethernet routing switch") || strings.Contains(low, "ers-")
		},
		Match: func(ev Evidence) (string, string, bool) {
			isVendor := HasWord(ev.Vendor, "avaya") || HasWord(ev.SysDesc, "avaya")
			combined := strings.TrimSpace(ev.SysName + " " + firstLine(ev.SysDesc))
			model := ""
			if m := avayaModelRe.FindStringSubmatch(combined); len(m) > 1 {
				model = strings.ToUpper(m[1])
			}
			if !isVendor && !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ev.SysName)), "AVX") {
				return "", "", false
			}
			if model == "" {
				model = strings.TrimSpace(ev.SysName)
			}
			fw := firstLine(ev.SysDesc)
			if strings.EqualFold(fw, model) {
				fw = ""
			}
			return model, fw, true
		},
	})

	// Panasonic SIP phones (KX-HDV230RU, KX-UT, KX-NT, KX-TGP).
	// Multi-category vendor: never match by OUI alone without KX-* model or CapPhone.
	RegisterRule(Rule{
		ID:       "panasonic",
		Brand:    "Panasonic",
		Priority: 90,
		Match: func(ev Evidence) (string, string, bool) {
			combined := strings.TrimSpace(ev.SysName + " " + firstLine(ev.SysDesc))
			if m := panasonicModelRe.FindStringSubmatch(combined); len(m) > 1 {
				fw := firstLine(ev.SysDesc)
				if strings.EqualFold(fw, "panasonic") || strings.EqualFold(fw, m[1]) {
					fw = ""
				}
				return strings.ToUpper(m[1]), fw, true
			}
			if ev.Capabilities&CapPhone != 0 && (HasWord(ev.Vendor, "panasonic") || HasWord(ev.SysDesc, "panasonic")) {
				model := strings.TrimSpace(ev.SysName)
				fw := firstLine(ev.SysDesc)
				if strings.EqualFold(fw, "panasonic") {
					fw = ""
				}
				return model, fw, true
			}
			return "", "", false
		},
	})

	// Fanvil IP / Hotel phones (OUI 68:69:2e, e.g. H81, X3U, V64)
	RegisterRule(Rule{
		ID:               "fanvil",
		Brand:            "Fanvil",
		Priority:         90,
		DedicatedVendors: []string{"fanvil"},
		Match: func(ev Evidence) (string, string, bool) {
			isVendor := HasWord(ev.Vendor, "fanvil") || HasWord(ev.SysDesc, "fanvil")
			sn := strings.TrimSpace(ev.SysName)
			// Some Fanvil hotel phones (e.g. H81 on OUI 68:69:2e) have CapPhone + WAN Port
			if !isVendor && !(ev.Capabilities&CapPhone != 0 && strings.HasPrefix(strings.ToLower(cleanPortDesc(ev.PortDesc)), "wan port") && fanvilModelRe.MatchString(sn)) {
				return "", "", false
			}
			model := sn
			if m := fanvilModelRe.FindStringSubmatch(sn + " " + firstLine(ev.SysDesc)); len(m) > 1 && model == "" {
				model = m[1]
			}
			return model, firstLine(ev.SysDesc), true
		},
	})

	// Cisco IP Phones (multi-category vendor: requires Cisco IP Phone/CP-xxxx or CapPhone)
	RegisterRule(Rule{
		ID:       "cisco-voip",
		Brand:    "Cisco",
		Priority: 85,
		Match: func(ev Evidence) (string, string, bool) {
			combined := strings.TrimSpace(ev.SysName + " " + firstLine(ev.SysDesc))
			hasCiscoIPPhone := strings.Contains(strings.ToLower(combined), "cisco ip phone")
			if m := ciscoPhoneModelRe.FindStringSubmatch(combined); len(m) > 1 {
				model := strings.ToUpper(m[1])
				fw := ""
				if _, after, ok := strings.Cut(firstLine(ev.SysDesc), ","); ok {
					fw = strings.TrimSpace(after)
				}
				return model, fw, true
			}
			if hasCiscoIPPhone || (ev.Capabilities&CapPhone != 0 && (HasWord(ev.Vendor, "cisco") || strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ev.SysName)), "SEP"))) {
				return strings.TrimSpace(ev.SysName), firstLine(ev.SysDesc), true
			}
			return "", "", false
		},
	})

	// Additional dedicated enterprise VoIP vendors for plug-and-play OUI & LLDP support
	for _, v := range []struct {
		id, brand string
		words     []string
	}{
		{"poly", "Poly", []string{"polycom"}},
		{"snom", "Snom", []string{"snom"}},
		{"mitel", "Mitel", []string{"mitel", "aastra"}},
		{"gigaset", "Gigaset", []string{"gigaset"}},
		{"audiocodes", "AudioCodes", []string{"audiocodes"}},
		{"akuvox", "Akuvox", []string{"akuvox"}},
		{"flyingvoice", "Flyingvoice", []string{"flyingvoice"}},
	} {
		v := v
		RegisterRule(Rule{
			ID:               v.id,
			Brand:            v.brand,
			Priority:         80,
			DedicatedVendors: v.words,
			Match: func(ev Evidence) (string, string, bool) {
				matched := false
				for _, w := range v.words {
					if HasWord(ev.Vendor, w) || HasWord(ev.SysDesc, w) || HasWord(ev.SysName, w) {
						matched = true
						break
					}
				}
				if !matched {
					return "", "", false
				}
				return strings.TrimSpace(ev.SysName), firstLine(ev.SysDesc), true
			},
		})
	}
}
