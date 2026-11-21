package voip

import (
	"regexp"
	"strings"

	"lldp_scanner/modules/kit"
)

var (
	avayaERSRe        = regexp.MustCompile(`(?i)\bERS[- ]?\d{3,4}`)
	avayaModelRe      = regexp.MustCompile(`(?i)\b(AVX[A-Z0-9]{4,}|J1[235678]9|96[01245]1G?|96[02345]8G?|B1[789]9)\b`)
	panasonicModelRe  = regexp.MustCompile(`(?i)\b(KX-(?:HDV|UT|NT|TGP|TPA)\d{2,4}[A-Z0-9]*)\b`)
	ciscoPhoneModelRe = regexp.MustCompile(`(?i)\b(CP-\d{4}[A-Z0-9]*)\b`)
	fanvilModelRe     = regexp.MustCompile(`(?i)\b(X[1-7][A-Z0-9]{0,3}|V6[1-7][A-Z0-9]*|H[2358]\d?[A-Z0-9]*|i[1-6]\d[A-Z0-9]*)\b`)
)

func init() {
	// Avaya IP phones (e.g. AVXC28D65, J100/9600 series). Avaya makes
	// switches (ERS) and PBXs too: no dedicated VoIP vendor, a phone by its
	// model or the telephone capability.
	RegisterRule(Rule{
		ID:       "avaya",
		Brand:    "Avaya",
		Priority: 90,
		Exclude: func(ev Evidence) bool {
			if !kit.HasWord(ev.Vendor, "avaya") && !kit.HasWord(ev.SysDesc, "avaya") {
				return false
			}
			text := ev.SysDesc + " " + ev.SysName
			return strings.Contains(strings.ToLower(text), "ethernet routing switch") || avayaERSRe.MatchString(text)
		},
		Match: func(ev Evidence) (string, string, bool) {
			isVendor := kit.HasWord(ev.Vendor, "avaya") || kit.HasWord(ev.SysDesc, "avaya")
			combined := strings.TrimSpace(ev.SysName + " " + firstLine(ev.SysDesc))
			model := ""
			if m := avayaModelRe.FindStringSubmatch(combined); len(m) > 1 {
				model = strings.ToUpper(m[1])
			}
			avx := strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ev.SysName)), "AVX")
			if !avx && !(isVendor && (model != "" || ev.Capabilities&CapPhone != 0)) {
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
			if ev.Capabilities&CapPhone != 0 && (kit.HasWord(ev.Vendor, "panasonic") || kit.HasWord(ev.SysDesc, "panasonic")) {
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
			isVendor := kit.HasWord(ev.Vendor, "fanvil") || kit.HasWord(ev.SysDesc, "fanvil")
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
			if hasCiscoIPPhone || (ev.Capabilities&CapPhone != 0 && (kit.HasWord(ev.Vendor, "cisco") || strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ev.SysName)), "SEP"))) {
				return strings.TrimSpace(ev.SysName), firstLine(ev.SysDesc), true
			}
			return "", "", false
		},
	})

	// Additional enterprise VoIP vendors for plug-and-play OUI & LLDP
	// support. Mitel (PBX controllers) and AudioCodes (gateways, SBCs) make
	// more than phones: no dedicated VoIP vendors, a phone with the
	// telephone capability only.
	for _, v := range []struct {
		id, brand string
		words     []string
		dedicated bool
	}{
		{"poly", "Poly", []string{"polycom"}, true},
		{"snom", "Snom", []string{"snom"}, true},
		{"mitel", "Mitel", []string{"mitel", "aastra"}, false},
		{"gigaset", "Gigaset", []string{"gigaset"}, true},
		{"audiocodes", "AudioCodes", []string{"audiocodes"}, false},
		{"akuvox", "Akuvox", []string{"akuvox"}, true},
		{"flyingvoice", "Flyingvoice", []string{"flyingvoice"}, true},
	} {
		r := Rule{
			ID:       v.id,
			Brand:    v.brand,
			Priority: 80,
			Match: func(ev Evidence) (string, string, bool) {
				if !v.dedicated && ev.Capabilities&CapPhone == 0 {
					return "", "", false
				}
				matched := false
				for _, w := range v.words {
					if kit.HasWord(ev.Vendor, w) || kit.HasWord(ev.SysDesc, w) || kit.HasWord(ev.SysName, w) {
						matched = true
						break
					}
				}
				if !matched {
					return "", "", false
				}
				return strings.TrimSpace(ev.SysName), firstLine(ev.SysDesc), true
			},
		}
		if v.dedicated {
			r.DedicatedVendors = v.words
		}
		RegisterRule(r)
	}
}
