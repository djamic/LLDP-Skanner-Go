package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestStructureIndex keeps structure.md's function index (the part between
// its "BEGIN generated" and "END generated" lines) the code's: every Go
// file of the program and its modules, and the web UI's scripts, with each
// function's and type's first doc sentence and the functions that call it.
// Run `go test -run TestStructureIndex -update` after changing the code.
func TestStructureIndex(t *testing.T) {
	src, err := os.ReadFile("structure.md")
	if err != nil {
		t.Fatal(err)
	}
	index := structureIndex(t)
	const begin, end = "<!-- BEGIN generated", "<!-- END generated -->"
	s := string(src)
	i, j := strings.Index(s, begin), strings.Index(s, end)
	if i < 0 || j < i {
		t.Fatal("structure.md has no BEGIN generated ... END generated lines")
	}
	i += strings.Index(s[i:], "\n") + 1
	got := s[:i] + index + s[j:]
	if got == s {
		return
	}
	if *update {
		if err := os.WriteFile("structure.md", []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Error("structure.md's function index is not the code's (run go test -run TestStructureIndex -update)")
}

// structureDecl is one function, method or type of the index.
type structureDecl struct {
	name, kind, doc string // kind: "func", "method (T)", "type"
	callers         []string
}

func structureIndex(t *testing.T) string {
	var b strings.Builder
	b.WriteString("\n")
	pkgs := []struct{ dir, name string }{{".", "main"}}
	mods, _ := filepath.Glob("modules/*")
	slices.Sort(mods)
	for _, m := range mods {
		if st, err := os.Stat(m); err == nil && st.IsDir() {
			pkgs = append(pkgs, struct{ dir, name string }{m, "modules/" + filepath.Base(m)})
		}
	}
	if top, _ := filepath.Glob("modules/*.go"); len(top) > 0 {
		pkgs = append(pkgs, struct{ dir, name string }{"modules", "modules"})
	}
	cross := structureCrossCallers(t, pkgs)
	for _, p := range pkgs {
		structureGoPackage(t, &b, p.dir, p.name, cross)
	}
	structureJS(t, &b)
	return b.String()
}

// structureCrossCallers maps "modules/voip.Detect" to the functions of the
// other packages that use it (as "main.classifyNode").
func structureCrossCallers(t *testing.T, pkgs []struct{ dir, name string }) map[string]map[string]bool {
	cross := map[string]map[string]bool{}
	fset := token.NewFileSet()
	for _, p := range pkgs {
		files, _ := filepath.Glob(filepath.Join(p.dir, "*.go"))
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			imports := map[string]string{} // local name → "modules/voip"
			for _, im := range f.Imports {
				ip := strings.Trim(im.Path.Value, `"`)
				rel, ok := strings.CutPrefix(ip, "lldp_scanner/")
				if !ok {
					continue
				}
				local := filepath.Base(rel)
				if im.Name != nil {
					local = im.Name.Name
				}
				imports[local] = rel
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				caller := filepath.Base(p.name) + "." + structureFuncName(fd)
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok {
						if x, ok := sel.X.(*ast.Ident); ok && imports[x.Name] != "" {
							key := imports[x.Name] + "." + sel.Sel.Name
							if cross[key] == nil {
								cross[key] = map[string]bool{}
							}
							cross[key][caller] = true
						}
					}
					return true
				})
			}
		}
	}
	return cross
}

// structureGoPackage writes one Go package's files, their declarations and
// each one's callers: in the package, and in the packages that import it.
func structureGoPackage(t *testing.T, b *strings.Builder, dir, name string, cross map[string]map[string]bool) {
	fset := token.NewFileSet()
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	slices.Sort(files)
	type parsed struct {
		path string
		f    *ast.File
	}
	var all []parsed
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, parsed{path, f})
	}
	if len(all) == 0 {
		return
	}
	// who refers to whom: a function's body names a top-level function or
	// type (a bare name), or a method (after a dot)
	plain, methods := map[string]bool{}, map[string]bool{}
	for _, p := range all {
		for _, d := range p.f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil {
					methods[d.Name.Name] = true
				} else {
					plain[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					if ts, ok := sp.(*ast.TypeSpec); ok {
						plain[ts.Name.Name] = true
					}
				}
			}
		}
	}
	callers := map[string]map[string]bool{} // "f:name" or "m:name" → callers
	for _, p := range all {
		for _, d := range p.f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			caller := structureFuncName(fd)
			add := func(key string) {
				if callers[key] == nil {
					callers[key] = map[string]bool{}
				}
				callers[key][caller] = true
			}
			sels := map[*ast.Ident]bool{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					sels[n.Sel] = true
					if methods[n.Sel.Name] {
						add("m:" + n.Sel.Name)
					}
				case *ast.Ident:
					if !sels[n] && plain[n.Name] && n.Name != fd.Name.Name {
						add("f:" + n.Name)
					}
				}
				return true
			})
		}
	}

	fmt.Fprintf(b, "### Package `%s`\n\n", name)
	for _, p := range all {
		var decls []structureDecl
		for _, d := range p.f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				kind := "func"
				if d.Recv != nil && len(d.Recv.List) > 0 {
					kind = "method (" + structureRecv(d.Recv.List[0].Type) + ")"
				}
				key := "f:" + d.Name.Name
				if d.Recv != nil {
					key = "m:" + d.Name.Name
				}
				set := maps.Clone(callers[key])
				if d.Recv == nil {
					for c := range cross[name+"."+d.Name.Name] {
						if set == nil {
							set = map[string]bool{}
						}
						set[c] = true
					}
				}
				decls = append(decls, structureDecl{name: d.Name.Name, kind: kind, doc: structureSentence(d.Doc), callers: structureCallers(set)})
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					ts, ok := sp.(*ast.TypeSpec)
					if !ok {
						continue
					}
					doc := ts.Doc
					if doc == nil {
						doc = d.Doc
					}
					set := maps.Clone(callers["f:"+ts.Name.Name])
					for c := range cross[name+"."+ts.Name.Name] {
						if set == nil {
							set = map[string]bool{}
						}
						set[c] = true
					}
					decls = append(decls, structureDecl{name: ts.Name.Name, kind: "type", doc: structureSentence(doc), callers: structureCallers(set)})
				}
			}
		}
		fmt.Fprintf(b, "#### `%s`\n\n", filepath.ToSlash(p.path))
		if fileDoc := structureSentence(p.f.Doc); fileDoc != "" {
			fmt.Fprintf(b, "%s\n\n", fileDoc)
		}
		if len(decls) == 0 {
			b.WriteString("(no functions or types)\n\n")
			continue
		}
		for _, d := range decls {
			structureLine(b, d)
		}
		b.WriteString("\n")
	}
}

func structureFuncName(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		return structureRecv(fd.Recv.List[0].Type) + "." + fd.Name.Name
	}
	return fd.Name.Name
}

func structureRecv(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.StarExpr:
		return structureRecv(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr:
		return structureRecv(e.X)
	}
	return "?"
}

func structureCallers(set map[string]bool) []string {
	var out []string
	for c := range set {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

// structureSentence is a doc comment's first sentence, at most 220 bytes.
func structureSentence(doc *ast.CommentGroup) string {
	if doc == nil {
		return ""
	}
	return structureFirst(doc.Text())
}

var structureSentenceEnd = regexp.MustCompile(`[.:;]\s`)

func structureFirst(text string) string {
	text = strings.Join(strings.Fields(strings.SplitN(text, "\n\n", 2)[0]), " ")
	if loc := structureSentenceEnd.FindStringIndex(text + " "); loc != nil && loc[0] > 0 {
		text = text[:loc[0]+1]
	}
	if len(text) > 220 {
		cut := strings.LastIndex(text[:220], " ")
		if cut < 0 {
			cut = 220
		}
		text = text[:cut] + " …"
	}
	return strings.ReplaceAll(text, "|", "\\|")
}

func structureLine(b *strings.Builder, d structureDecl) {
	fmt.Fprintf(b, "- **`%s`** %s", d.name, d.kind)
	if d.doc != "" {
		fmt.Fprintf(b, " — %s", d.doc)
	}
	if len(d.callers) > 0 {
		shown := d.callers
		more := ""
		if len(shown) > 8 {
			more = fmt.Sprintf(" (+%d more)", len(shown)-8)
			shown = shown[:8]
		}
		fmt.Fprintf(b, " ← %s%s", strings.Join(shown, ", "), more)
	}
	b.WriteString("\n")
}

// structureJS writes the web UI's scripts: their top-level functions, the
// first line of the comment above each, and who calls them (the functions
// of every script, and the pages' attributes).
func structureJS(t *testing.T, b *strings.Builder) {
	type script struct {
		path, src string
	}
	var scripts []script
	for _, path := range []string{"static/app.js", "static/tree.js", "static/modules.js", "static/credentials.js", "static/login.js"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		scripts = append(scripts, script{path, string(data)})
	}
	if data, err := os.ReadFile("static/history.html"); err == nil {
		s := string(data)
		if i := strings.LastIndex(s, "<script>"); i >= 0 {
			s = s[i+len("<script>"):]
			if j := strings.Index(s, "</script>"); j >= 0 {
				s = s[:j]
			}
			// the inline script is indented: top-level functions at 8 spaces
			var lines []string
			for _, l := range strings.Split(s, "\n") {
				lines = append(lines, strings.TrimPrefix(l, "        "))
			}
			scripts = append(scripts, script{"static/history.html (inline script)", strings.Join(lines, "\n")})
		}
	}
	funcRe := regexp.MustCompile(`(?m)^(?:async )?function ([A-Za-z_$][\w$]*)\(`)
	type fn struct {
		name, doc, body string
	}
	byScript := map[string][]fn{}
	defined := map[string]bool{}
	for _, sc := range scripts {
		lines := strings.Split(sc.src, "\n")
		for i := 0; i < len(lines); i++ {
			m := funcRe.FindStringSubmatch(lines[i])
			if m == nil {
				continue
			}
			var doc []string
			for k := i - 1; k >= 0 && strings.HasPrefix(lines[k], "//"); k-- {
				doc = append([]string{strings.TrimSpace(strings.TrimPrefix(lines[k], "//"))}, doc...)
			}
			end := i + 1
			for end < len(lines) && lines[end] != "}" {
				end++
			}
			body := strings.Join(lines[i+1:min(end+1, len(lines))], "\n")
			byScript[sc.path] = append(byScript[sc.path], fn{m[1], structureFirst(strings.Join(doc, "\n")), body})
			defined[m[1]] = true
			i = end
		}
	}
	callers := map[string]map[string]bool{}
	ident := regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	add := func(name, caller string) {
		if callers[name] == nil {
			callers[name] = map[string]bool{}
		}
		callers[name][caller] = true
	}
	for _, sc := range scripts {
		for _, f := range byScript[sc.path] {
			for _, id := range ident.FindAllString(f.body, -1) {
				if defined[id] && id != f.name {
					add(id, f.name)
				}
			}
		}
	}
	for _, page := range []string{"static/index.html", "static/history.html", "static/login.html"} {
		data, err := os.ReadFile(page)
		if err != nil {
			continue
		}
		for _, m := range regexp.MustCompile(`on[a-z]+="([^"]*)"`).FindAllStringSubmatch(string(data), -1) {
			for _, id := range ident.FindAllString(m[1], -1) {
				if defined[id] {
					add(id, filepath.Base(page))
				}
			}
		}
	}
	b.WriteString("### Web UI scripts\n\n")
	for _, sc := range scripts {
		fmt.Fprintf(b, "#### `%s`\n\n", sc.path)
		if len(byScript[sc.path]) == 0 {
			b.WriteString("(no top-level functions)\n\n")
			continue
		}
		for _, f := range byScript[sc.path] {
			structureLine(b, structureDecl{name: f.name, kind: "function", doc: f.doc, callers: structureCallers(callers[f.name])})
		}
		b.WriteString("\n")
	}
}
