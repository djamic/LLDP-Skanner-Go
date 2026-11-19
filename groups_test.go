package main

import (
	"cmp"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// groupTableFiles are the web UI files with a generated copy of deviceGroups'
// tables, and the copy each one has.
var groupTableFiles = []struct {
	path string
	text func() string
}{
	{"static/app.js", groupTablesAppJS},
	{"static/tree.js", groupTablesTreeJS},
	{"static/index.html", groupFilterBarHTML},
	{"static/history.html", groupTablesHistoryJS},
}

// TestGroupTables checks that the UI's tables are deviceGroups' (groups.go),
// and rewrites them with -update. It checks too that every group has an SVG
// icon, that the DOCX converter names every report colour, and that every
// category the MAC identity gives is a group.
func TestGroupTables(t *testing.T) {
	keys := make(map[string]bool)
	for _, d := range deviceGroups {
		if keys[d.Key] {
			t.Errorf("group %q is twice in deviceGroups", d.Key)
		}
		keys[d.Key] = true
	}

	for _, f := range groupTableFiles {
		src, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := groupRegion(string(src), f.text())
		if err != nil {
			t.Errorf("%s: %v", f.path, err)
			continue
		}
		if got == string(src) {
			continue
		}
		if *update {
			if err := os.WriteFile(f.path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		t.Errorf("%s: its groups.go tables are not deviceGroups' (run go test -run TestGroupTables -update)", f.path)
	}

	appJS, err := os.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range deviceGroups {
		if !strings.Contains(string(appJS), `<symbol id="topo-icon-`+d.Key+`"`) {
			t.Errorf("static/app.js has no SVG symbol topo-icon-%s", d.Key)
		}
	}

	for _, path := range []string{"instrumens/md2docx_gost_linux.py", "instrumens/md2docx_gost_cyrillic_linux.py"} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`(?s)group_label_map = \{(.*?)\}`).FindSubmatch(src)
		if m == nil {
			t.Errorf("%s: no group_label_map", path)
			continue
		}
		for key, colors := range reportGroupColors {
			if !strings.Contains(string(m[1]), "'"+colors[0]+"'") {
				t.Errorf("%s: group_label_map does not name %s, the colour of %s", path, colors[0], key)
			}
		}
	}

	for prefix, role := range ouiRegistry {
		if role.Category != "" && !keys[role.Category] && role.Category != "network" {
			t.Errorf("ouiRegistry %s: category %q is not a group", prefix, role.Category)
		}
	}
	for _, rule := range ouiCategoryWords {
		if !keys[rule.category] && rule.category != "network" {
			t.Errorf("ouiCategoryWords: category %q is not a group", rule.category)
		}
	}
}

// groupRegion replaces the lines between src's "BEGIN groups.go" line and
// its "END groups.go" line with text, each line indented as the BEGIN line.
func groupRegion(src, text string) (string, error) {
	lines := strings.SplitAfter(src, "\n")
	begin, end := -1, -1
	for i, l := range lines {
		switch {
		case strings.Contains(l, "BEGIN groups.go"):
			if begin >= 0 {
				return "", fmt.Errorf("two BEGIN groups.go lines")
			}
			begin = i
		case strings.Contains(l, "END groups.go"):
			end = i
		}
	}
	if begin < 0 || end < begin {
		return "", fmt.Errorf("no BEGIN groups.go ... END groups.go lines")
	}
	indent := lines[begin][:len(lines[begin])-len(strings.TrimLeft(lines[begin], " "))]
	var b strings.Builder
	for _, l := range lines[:begin+1] {
		b.WriteString(l)
	}
	for _, l := range strings.SplitAfter(strings.TrimSuffix(text, "\n"), "\n") {
		b.WriteString(indent + strings.TrimSuffix(l, "\n") + "\n")
	}
	for _, l := range lines[end:] {
		b.WriteString(l)
	}
	return b.String(), nil
}

// jsQuote is s as a single-quoted JavaScript string.
func jsQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// groupTablesAppJS is app.js's copy: the colours, the graph's canvas colours
// and icon sizes, the type names, the info panel's icons and the export
// popup's groups.
func groupTablesAppJS() string {
	var b strings.Builder
	b.WriteString("const groupColors = {\n")
	for _, d := range deviceGroups {
		fmt.Fprintf(&b, "    %s: %s,\n", jsQuote(d.Key), jsQuote(d.Color))
	}
	b.WriteString("};\nconst uiGroupCanvasColors = {\n")
	for _, d := range deviceGroups {
		if d.CanvasColor != "" {
			fmt.Fprintf(&b, "    %s: %s,\n", jsQuote(d.Key), jsQuote(d.CanvasColor))
		}
	}
	b.WriteString("};\nconst uiGroupIconSizes = {\n")
	for _, d := range deviceGroups {
		if d.IconSize != 0 {
			fmt.Fprintf(&b, "    %s: %d,\n", jsQuote(d.Key), d.IconSize)
		}
	}
	b.WriteString("};\nconst uiTypeNames = {\n")
	for _, d := range deviceGroups {
		fmt.Fprintf(&b, "    %s: %s,\n", jsQuote(d.Key), jsQuote(d.Emoji+" "+d.Name))
	}
	b.WriteString("};\nconst groupIcons = {\n")
	for _, d := range deviceGroups {
		fmt.Fprintf(&b, "    %s: %s,\n", jsQuote(d.Key), jsQuote(d.Emoji))
	}
	b.WriteString("};\nconst uiExportGroups = [\n")
	for _, d := range deviceGroups {
		emoji := cmp.Or(d.ExportEmoji, d.Emoji)
		fmt.Fprintf(&b, "    { id: %s, label: %s, checked: %t },\n", jsQuote(d.Key), jsQuote(emoji+" "+d.longName()), d.ExportOn)
	}
	b.WriteString("];\n")
	return b.String()
}

// groupTablesTreeJS is tree.js's copy: the Tree tab's icons (the info
// panel's) and child order.
func groupTablesTreeJS() string {
	var b strings.Builder
	b.WriteString("const treeGroupIcons = {\n")
	for _, d := range deviceGroups {
		fmt.Fprintf(&b, "    %s: %s,\n", jsQuote(d.Key), jsQuote(d.Emoji))
	}
	b.WriteString("};\nconst treeGroupRanks = {\n")
	for _, d := range deviceGroups {
		if d.TreeRank != 2 {
			fmt.Fprintf(&b, "    %s: %d,\n", jsQuote(d.Key), d.TreeRank)
		}
	}
	b.WriteString("};\n")
	return b.String()
}

// groupTablesHistoryJS is history.html's copy: what a device is behind.
func groupTablesHistoryJS() string {
	var b strings.Builder
	b.WriteString("const viaNames = {\n")
	for _, d := range deviceGroups {
		if d.Via != "" {
			fmt.Fprintf(&b, "    %s: %s,\n", jsQuote(d.Key), jsQuote(d.Via))
		}
	}
	b.WriteString("};\n")
	return b.String()
}

// groupFilterBarHTML is index.html's filter bar: a checkbox per group, and
// the Passive (HA standby) one after the routers.
func groupFilterBarHTML() string {
	attr := strings.NewReplacer(`&`, `&amp;`, `<`, `&lt;`, `>`, `&gt;`, `"`, `&quot;`)
	var b strings.Builder
	for _, d := range deviceGroups {
		title, checked := "", " checked"
		if d.FilterTitle != "" {
			title = ` title="` + attr.Replace(d.FilterTitle) + `"`
		}
		if d.FilterOff {
			checked = ""
		}
		fmt.Fprintf(&b, "<label class=\"filter-cb\"%s><input type=\"checkbox\" data-group=\"%s\"%s\n", title, d.Key, checked)
		fmt.Fprintf(&b, "        onchange=\"applyFilters()\"><span class=\"fc-dot\" style=\"background:%s\"></span><span>%s</span><span class=\"fc-cnt\" id=\"fc-%s\">0</span></label>\n",
			d.Color, attr.Replace(d.Filter), d.Key)
		if d.Key == "router" {
			b.WriteString("<label class=\"filter-cb\" title=\"Show/hide passive (VRRP/HSRP standby) switches\"><input type=\"checkbox\" id=\"filterPassive\" checked\n")
			b.WriteString("        onchange=\"applyFilters()\"><span class=\"fc-dot\" style=\"background:#78909C\"></span><span>Passive</span><span class=\"fc-cnt\" id=\"fc-passive\">0</span></label>\n")
		}
	}
	return b.String()
}
