import os
import argparse
import re
import sys
import uuid
import subprocess
import pypandoc
from docx import Document
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

def load_ignored_words(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def lat2cyr(text):
    # Exception handling for morpheme boundaries where 'ts' is NOT 'ц'
    exceptions = {
        "ruxsatsiz": "рухсатсиз",
        "Ruxsatsiz": "Рухсатсиз",
        "RUXSATSIZ": "РУХСАТСИЗ",
        "sanoatsiz": "саноатсиз",
        "Sanoatsiz": "Саноатсиз"
    }
    for lat, cyr in exceptions.items():
        text = text.replace(lat, cyr)

    mapping = [
        ("sh", "ш"), ("Sh", "Ш"), ("SH", "Ш"),
        ("ch", "ч"), ("Ch", "Ч"), ("CH", "Ч"),
        ("o'", "ў"), ("o`", "ў"), ("o‘", "ў"), ("oʻ", "ў"), 
        ("O'", "Ў"), ("O`", "Ў"), ("O‘", "Ў"), ("Oʻ", "Ў"),
        ("g'", "ғ"), ("g`", "ғ"), ("g‘", "ғ"), ("gʻ", "ғ"), 
        ("G'", "Ғ"), ("G`", "Ғ"), ("G‘", "Ғ"), ("Gʻ", "Ғ"),
        ("yo", "ё"), ("Yo", "Ё"), ("YO", "Ё"),
        ("yu", "ю"), ("Yu", "Ю"), ("YU", "Ю"),
        ("ya", "я"), ("Ya", "Я"), ("YA", "Я"),
        ("ts", "ц"), ("Ts", "Ц"), ("TS", "Ц"),
        ("a", "а"), ("A", "А"),
        ("b", "б"), ("B", "Б"),
        ("d", "д"), ("D", "Д"),
        ("e", "е"), ("E", "Е"),
        ("f", "ф"), ("F", "Ф"),
        ("g", "г"), ("G", "Г"),
        ("h", "ҳ"), ("H", "Ҳ"),
        ("i", "и"), ("I", "И"),
        ("j", "ж"), ("J", "Ж"),
        ("k", "к"), ("K", "К"),
        ("l", "л"), ("L", "Л"),
        ("m", "м"), ("M", "М"),
        ("n", "н"), ("N", "Н"),
        ("o", "о"), ("O", "О"),
        ("p", "п"), ("P", "П"),
        ("q", "қ"), ("Q", "Қ"),
        ("r", "р"), ("R", "Р"),
        ("s", "с"), ("S", "С"),
        ("t", "т"), ("T", "Т"),
        ("u", "у"), ("U", "У"),
        ("v", "в"), ("V", "В"),
        ("w", "в"), ("W", "В"),
        ("x", "х"), ("X", "Х"),
        ("y", "й"), ("Y", "Й"),
        ("z", "з"), ("Z", "З"),
        ("c", "с"), ("C", "С"),
        ("'", "ъ"), ("`", "ъ"), ("‘", "ъ"), ("ʻ", "ъ")
    ]
    for lat, cyr in mapping:
        text = text.replace(lat, cyr)
    return text

def safe_lat2cyr(text, ignored_words):
    placeholders = {}
    counter = 0
    
    # Sort ignored words by length (longest first) to prevent partial matches
    sorted_ignored = sorted(ignored_words, key=len, reverse=True)
    
    # Protect ignored words using regex word boundaries to avoid replacing substrings
    for word in sorted_ignored:
        pattern = r'\b' + re.escape(word) + r'\b'
        
        matches = re.finditer(pattern, text)
        for match in matches:
            original = match.group(0)
            token = f"TKN999{counter}888TKN" # Use numbers and safe characters
            placeholders[token] = original
            counter += 1
            
        # Manually replace using a function to inject the new counter-based tokens
        def repl(match):
            nonlocal counter
            # We already mapped them above, but we need to re-find which token belongs to this match
            # Actually, let's just use a simpler replacement map
            val = match.group(0)
            token = f"T999{len(placeholders)}888T"
            placeholders[token] = val
            return token
            
        text = re.sub(pattern, repl, text)

    # Convert the rest to Cyrillic
    text = lat2cyr(text)
    
    # Restore the protected terms
    for token, original_word in placeholders.items():
        text = text.replace(lat2cyr(token), original_word) # Just in case T becomes Т
        
    return text

def apply_gost_style(doc):
    style = doc.styles['Normal']
    font = style.font
    font.name = 'Times New Roman'
    font.size = Pt(14)
    font.color.rgb = RGBColor(0, 0, 0)
    
    pf = style.paragraph_format
    pf.line_spacing = 1.5
    pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    pf.first_line_indent = Cm(1.25)
    pf.space_after = Pt(0)
    pf.space_before = Pt(0)

def set_run_font(run, size=14, bold=False, italic=False):
    run.font.name = 'Times New Roman'
    run.font.size = Pt(size)
    run.font.color.rgb = RGBColor(0, 0, 0)
    if bold: run.bold = True
    if italic: run.italic = True
    return run

def add_latex_math(paragraph, latex_string, is_block=False):
    md = f"$${latex_string}$$" if is_block else f"${latex_string}$"
    tmp_path = f"tmp_math_cyr_{uuid.uuid4().hex}.docx"
    try:
        pypandoc.convert_text(md, 'docx', format='markdown', outputfile=tmp_path)
        tmp_doc = Document(tmp_path)
        
        math_element = None
        for tmp_p in tmp_doc.paragraphs:
            xml = tmp_p._element.xml
            if "oMath" in xml:
                if is_block:
                    omaths = tmp_p._element.xpath('.//m:oMathPara')
                    if not omaths:
                        omaths = tmp_p._element.xpath('.//m:oMath')
                else:
                    omaths = tmp_p._element.xpath('.//m:oMath')
                
                if omaths:
                    math_element = omaths[0]
                break
                
        if math_element is not None:
            print(f"DEBUG: Successfully extracted math element. is_block={is_block}, tag={math_element.tag}")
            paragraph._element.append(math_element)
        else:
            print(f"DEBUG: Failed to extract math component for {latex_string}")
            paragraph.add_run(latex_string)
    except Exception as e:
        print(f"Pandoc math parsing failed for '{latex_string}': {e}")
        paragraph.add_run(latex_string)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except:
                pass

def parse_mermaid(code):
    """Parse mermaid flowchart code into nodes and edges."""
    nodes = {}
    edges = []
    lines = code.strip().split('\n')

    def extract_node(token):
        token = token.strip()
        if not token: return None
        patterns = [
            (r'^(\w+)\(\[(.+?)\]\)$', 'Start/End'),
            (r'^(\w+)\(\((.+?)\)\)$', 'On-page reference'),
            (r'^(\w+)\[\[(.+?)\]\]$', 'Subprocess'),
            (r'^(\w+)\[/(.+?)/\]$',   'Data'),
            (r'^(\w+)\[\((.+?)\)\]$', 'Database'),
            (r'^(\w+)\{(.+?)\}$',     'Decision'),
            (r'^(\w+)\[(.+?)\]$',     'Process'),
            (r'^(\w+)\((.+?)\)$',     'Start/End'),
        ]
        for pat, shape in patterns:
            m = re.match(pat, token, re.DOTALL)
            if m:
                nid = m.group(1)
                label = m.group(2).strip().strip('"').strip("'")
                label = label.replace('\\n', '\n').replace('<br>', '\n')
                return (nid, label, shape)
        m = re.match(r'^(\w+)$', token)
        if m: return (m.group(1), m.group(1), 'Process')
        return None

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('%%') or stripped.startswith('classDef') or \
           stripped.startswith('class ') or stripped.startswith('flowchart') or \
           stripped.startswith('graph') or stripped == 'end' or stripped.startswith('subgraph'):
            continue
        edge_patterns = [
            r'(.+?)\s*-->\s*\|(.+?)\|\s*(.+)',
            r'(.+?)\s*--\s+(.+?)\s+-->\s*(.+)',
            r'(.+?)\s*-->\s*(.+)',
        ]
        matched = False
        for ep_idx, ep in enumerate(edge_patterns):
            m = re.match(ep, stripped)
            if m:
                if ep_idx < 2:
                    src_str, label_str, dst_str = m.group(1).strip(), m.group(2).strip().strip('"'), m.group(3).strip()
                else:
                    src_str, label_str, dst_str = m.group(1).strip(), '', m.group(2).strip()
                for src_token in [s.strip() for s in src_str.split('&')]:
                    sn = extract_node(src_token)
                    if sn:
                        if sn[0] not in nodes: nodes[sn[0]] = {'label': sn[1], 'shape': sn[2]}
                    else: sn = (src_token, src_token, 'Process')
                    for dst_token in [d.strip() for d in dst_str.split('&')]:
                        dn = extract_node(dst_token)
                        if dn:
                            if dn[0] not in nodes: nodes[dn[0]] = {'label': dn[1], 'shape': dn[2]}
                        else: dn = (dst_token, dst_token, 'Process')
                        edges.append({'src': sn[0], 'dst': dn[0], 'label': label_str})
                matched = True; break
        if not matched:
            node = extract_node(stripped)
            if node and node[0] not in nodes:
                nodes[node[0]] = {'label': node[1], 'shape': node[2]}
    return nodes, edges

def draw_in_visio(visio_app, nodes, edges, output_vsdx, output_png=None):
    """Draw flowchart directly in Visio using COM automation. Also exports PNG image."""
    try:
        doc = visio_app.Documents.Add("")
        page = doc.Pages(1)
        stencil = visio_app.Documents.OpenEx("BASFLO_U.VSSX", 64)
        shape_map = {
            'Process': 'Process', 'Decision': 'Decision', 'Start/End': 'Start/End',
            'Subprocess': 'Subprocess', 'Data': 'Data', 'Database': 'Database',
            'On-page reference': 'On-page reference',
        }
        masters = {}
        for key, name_u in shape_map.items():
            try: masters[key] = stencil.Masters.ItemU(name_u)
            except: masters[key] = stencil.Masters.ItemU('Process')
        connector_master = stencil.Masters.ItemU('Dynamic connector')

        node_ids = list(nodes.keys())
        children = {nid: [] for nid in node_ids}
        parents = {nid: [] for nid in node_ids}
        for edge in edges:
            if edge['src'] in children and edge['dst'] in node_ids:
                children[edge['src']].append(edge['dst'])
                parents[edge['dst']].append(edge['src'])
        roots = [nid for nid in node_ids if not parents[nid]] or (node_ids[:1] if node_ids else [])
        levels = {}
        queue = list(roots)
        for r in roots: levels[r] = 0
        visited = set(roots)
        while queue:
            cur = queue.pop(0)
            for ch in children.get(cur, []):
                if ch not in visited:
                    levels[ch] = levels[cur] + 1
                    visited.add(ch); queue.append(ch)
        mx = max(levels.values()) if levels else 0
        for nid in node_ids:
            if nid not in levels: mx += 1; levels[nid] = mx
        level_nodes = {}
        for nid, lvl in levels.items(): level_nodes.setdefault(lvl, []).append(nid)
        page_w, page_h = 11.69, max(8.27, len(level_nodes) * 1.8 + 2)
        try:
            page.PageSheet.Cells("PageWidth").FormulaU = f"{page_w} in"
            page.PageSheet.Cells("PageHeight").FormulaU = f"{page_h} in"
            # Force Orthogonal (Right Angle) routing at the page level 
            page.PageSheet.Cells("RouteStyle").FormulaU = "1"
        except: pass
        visio_shapes = {}
        for lvl in sorted(level_nodes.keys()):
            nids = level_nodes[lvl]
            spacing = min(page_w / (len(nids) + 1), 3.0)
            start_x = (page_w - (len(nids) - 1) * spacing) / 2
            y = page_h - 1.5 - lvl * 1.8
            for idx, nid in enumerate(nids):
                info = nodes[nid]
                shape = page.Drop(masters.get(info['shape'], masters['Process']), start_x + idx * spacing, y)
                shape.Text = info['label']
                # Increase shape width based on text length to prevent text overflow for 14pt font
                text_len = len(info['label'])
                if text_len > 10:
                    calc_width = min(4.5, max(1.5, 0.15 * text_len))
                    try: shape.Cells("Width").FormulaU = f"{calc_width} in"
                    except: pass
                # Increase shape height slightly for multiline
                if '\n' in info['label']:
                    lines_count = info['label'].count('\n') + 1
                    try: shape.Cells("Height").FormulaU = f"{0.4 + (lines_count * 0.25)} in"
                    except: pass
                # GOST Styles for shapes (14 pt)
                shape.Cells("Char.Font").FormulaU = "23" # Times New Roman
                shape.Cells("Char.Size").FormulaU = "14 pt"
                shape.Cells("LineWeight").FormulaU = "1.25 pt"
                shape.Cells("LineColor").FormulaU = "0" # Black
                visio_shapes[nid] = shape
        for edge in edges:
            if edge['src'] not in visio_shapes or edge['dst'] not in visio_shapes: continue
            conn = page.Drop(connector_master, 0, 0)
            conn.Cells("BeginX").GlueTo(visio_shapes[edge['src']].Cells("PinX"))
            conn.Cells("EndX").GlueTo(visio_shapes[edge['dst']].Cells("PinX"))
            # GOST Styles for connectors
            conn.Cells("LineWeight").FormulaU = "1.25 pt"
            conn.Cells("LineColor").FormulaU = "0" # Black
            try:
                conn.Cells("RouteStyle").FormulaU = "1" # Right angle
                conn.Cells("Rounding").FormulaU = "0 in" # NO curves
                conn.Cells("EndArrow").FormulaU = "13" # Solid Flowchart Arrow
                conn.Cells("EndArrowSize").FormulaU = "2" # Medium size
            except: pass
            
            if edge.get('label'):
                conn.Text = edge['label']
                conn.Cells("Char.Font").FormulaU = "23" # Times New Roman
                conn.Cells("Char.Size").FormulaU = "12 pt"
        try: 
            page.Layout()
            page.ResizeToFitContents()
            # Add padding to page dimensions to prevent clipping on the edges
            pw = page.PageSheet.Cells("PageWidth").ResultIU
            ph = page.PageSheet.Cells("PageHeight").ResultIU
            page.PageSheet.Cells("PageWidth").FormulaU = f"{pw + 0.5} in"
            page.PageSheet.Cells("PageHeight").FormulaU = f"{ph + 0.5} in"
            
            # Shift all shapes gently towards center by 0.25 in
            for shp in page.Shapes:
                try:
                    px = shp.Cells("PinX").ResultIU
                    py = shp.Cells("PinY").ResultIU
                    shp.Cells("PinX").FormulaU = f"{px + 0.25} in"
                    shp.Cells("PinY").FormulaU = f"{py + 0.25} in"
                except: pass
        except: pass
        doc.SaveAs(os.path.abspath(output_vsdx))
        
        # Export PNG image for inline embedding
        if output_png:
            try:
                page.Export(os.path.abspath(output_png))
            except Exception as e:
                print(f"  PNG export error: {e}")
        
        doc.Close()
        return os.path.exists(os.path.abspath(output_vsdx))
    except Exception as e:
        print(f"  Visio error: {e}"); return False

def pre_generate_diagrams(md_filepath):
    """Pre-scan the markdown for mermaid blocks and generate PNG images for each."""
    png_files = {}
    with open(md_filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    in_mermaid = False
    mermaid_lines = []
    mermaid_idx = 0
    vsdx_dir = os.path.join(os.path.dirname(os.path.abspath(md_filepath)), '..', 'visio_objects')
    os.makedirs(vsdx_dir, exist_ok=True)
    
    import win32com.client
    visio_app = win32com.client.Dispatch('Visio.Application')
    try: visio_app.Visible = False
    except: pass
    try: visio_app.AlertResponse = 7
    except: pass
    try:
        visio_app.Settings.SetRasterExportResolution(2)
        visio_app.Settings.SetRasterExportSize(2)
        visio_app.Settings.SetRasterExportColorFormat(23)
    except: pass
    
    try:
        for line in lines:
            if line.strip() == '```mermaid':
                in_mermaid = True
                mermaid_lines = []
                continue
            if in_mermaid:
                if line.strip() == '```':
                    in_mermaid = False
                    mermaid_idx += 1
                    code = "\n".join(mermaid_lines)
                    vsdx_path = os.path.join(vsdx_dir, f'diagram_{mermaid_idx}.vsdx')
                    png_path = os.path.join(vsdx_dir, f'diagram_{mermaid_idx}.png')
                    nodes, edges = parse_mermaid(code)
                    print(f"  Diagram {mermaid_idx}: ({len(nodes)} nodes, {len(edges)} edges)", end=' ')
                    if draw_in_visio(visio_app, nodes, edges, vsdx_path, png_path):
                        if os.path.exists(png_path):
                            png_files[mermaid_idx] = os.path.abspath(png_path)
                            print("OK")
                        else:
                            print("PNG missing")
                    else:
                        print("FAILED")
                else:
                    mermaid_lines.append(line.rstrip('\n').rstrip('\r'))
                    
    finally:
        try: visio_app.Quit()
        except: pass
    
    print(f"  Total diagrams pre-generated: {len(png_files)}")
    return png_files

def parse_inline(paragraph, text, size=14, ignored_words=[]):
    """Parses simple inline bold formatting **...**, italic *...*, and inline math $...$ applying Cyrillic where appropriate."""
    parts = re.split(r'(\*\*.*?\*\*)', text)
    for part in parts:
        if part.startswith('**') and part.endswith('**') and len(part) > 3:
            run = paragraph.add_run(safe_lat2cyr(part[2:-2], ignored_words))
            set_run_font(run, size=size, bold=True)
        else:
            math_parts = re.split(r'(\$.*?\$)', part)
            for mp in math_parts:
                if mp.startswith('$') and mp.endswith('$') and len(mp) > 1:
                    add_latex_math(paragraph, mp[1:-1].strip(), is_block=False)
                else:
                    subparts = re.split(r'(\*.*?\*)', mp)
                    for sp in subparts:
                        if sp.startswith('*') and sp.endswith('*') and len(sp) > 2:
                            run = paragraph.add_run(safe_lat2cyr(sp[1:-1], ignored_words))
                            set_run_font(run, size=size, italic=True)
                        else:
                            if sp:
                                run = paragraph.add_run(safe_lat2cyr(sp, ignored_words))
                                set_run_font(run, size=size)

def configure_margins(doc):
    for section in doc.sections:
        section.top_margin = Cm(2)
        section.bottom_margin = Cm(2)
        section.left_margin = Cm(3)
        section.right_margin = Cm(1.5)

def parse_markdown_to_docx(md_filepath, docx_filepath):
    # Load ignore file if exists in the same folder as the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ignore_file = os.path.join(script_dir, 'ignore_words.txt')
    ignored_words = load_ignored_words(ignore_file)

    # Pre-generate all Mermaid diagram PNG images BEFORE DOCX creation
    print(f"[Visio] Mermaid diagrammalarni PNG ga eksport qilish...")
    png_files = pre_generate_diagrams(md_filepath)

    doc = Document()
    apply_gost_style(doc)
    configure_margins(doc)
    
    with open(md_filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    in_table = False
    in_math_block = False
    in_mermaid_block = False
    math_lines = []
    mermaid_counter = 0
    mermaid_lines = []
    table_data = []
    
    def add_table_to_doc(data):
        if not data: return
        filtered = [row for row in data if not re.match(r'^[|\s\-:]+$', ''.join(row))]
        if not filtered: return
        
        table = doc.add_table(rows=len(filtered), cols=max(len(row) for row in filtered))
        table.style = 'Table Grid'
        table.autofit = True
        
        for i, row in enumerate(filtered):
            for j, cell_text in enumerate(row):
                if j < len(table.columns):
                    cell = table.cell(i, j)
                    cell.text = "" 
                    p = cell.paragraphs[0]
                    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
                    p.paragraph_format.first_line_indent = Cm(0)
                    parse_inline(p, cell_text.strip(), size=12, ignored_words=ignored_words)
                    if i == 0:
                        for r in p.runs: r.bold = True
                                
        doc.add_paragraph() 
        
    i = 0
    while i < len(lines):
        line = lines[i].strip('\n')
        
        if line.strip().startswith('|') and line.strip().endswith('|'):
            in_table = True
            row = [c.strip() for c in line.strip().strip('|').split('|')]
            if row and not row[0]: row = row[1:]
            if row and not row[-1]: row = row[:-1]
            table_data.append(row)
            i += 1
            continue
        elif in_table:
            add_table_to_doc(table_data)
            in_table = False
            table_data = []
            
        if not line.strip():
            i += 1
            continue
            
        # Mermaid Block
        if line.strip() == '```mermaid':
            in_mermaid_block = True
            mermaid_lines = []
            i += 1
            continue
            
        if in_mermaid_block:
            if line.strip() == '```':
                in_mermaid_block = False
                mermaid_counter += 1
                
                # Insert PNG image inline (like formulas)
                png_path = png_files.get(mermaid_counter)
                if png_path and os.path.exists(png_path):
                    p = doc.add_paragraph()
                    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    p.paragraph_format.first_line_indent = Cm(0)
                    p.paragraph_format.space_before = Pt(12)
                    p.paragraph_format.space_after = Pt(12)
                    run = p.add_run()
                    run.add_picture(png_path, width=Cm(15))
                else:
                    p = doc.add_paragraph()
                    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    p.paragraph_format.first_line_indent = Cm(0)
                    run = p.add_run(f"[Diagramma {mermaid_counter} yuklanmadi]")
                    set_run_font(run, size=10)
            else:
                mermaid_lines.append(line)
            i += 1
            continue
            
        # Single-line Math Block ($$ ... $$)
        math_block_match = re.match(r'^\$\$(.*?)\$\$$', line.strip())
        if math_block_match:
            p = doc.add_paragraph()
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(12)
            add_latex_math(p, math_block_match.group(1).strip(), is_block=True)
            i += 1
            continue

        # Multi-line Math Block ($$ ... $$)
        if line.strip() == '$$':
            if not in_math_block:
                in_math_block = True
                math_lines = []
            else:
                in_math_block = False
                p = doc.add_paragraph()
                p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
                p.paragraph_format.first_line_indent = Cm(0)
                p.paragraph_format.space_before = Pt(12)
                p.paragraph_format.space_after = Pt(12)
                
                # Combine math lines into a single centered string
                math_text = "\n".join(math_lines).strip()
                add_latex_math(p, math_text, is_block=True)
            i += 1
            continue
            
        if in_math_block:
            math_lines.append(line)
            i += 1
            continue
            
        header_match = re.match(r'^(#{1,6})\s+(.*)', line)
        if header_match:
            level = len(header_match.group(1))
            text = header_match.group(2).replace('**', '')
            
            p = doc.add_paragraph()
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(14)
            
            run = p.add_run(safe_lat2cyr(text, ignored_words))
            set_run_font(run, size=14 if level > 1 else 16, bold=True)
            i += 1
            continue
            
        img_match = re.match(r'^!\[(.*?)\]\((.*?)\)', line.strip())
        if img_match:
            alt_text = img_match.group(1)
            img_path = img_match.group(2)
            base_dir = os.path.dirname(md_filepath)
            full_img_path = os.path.normpath(os.path.join(base_dir, img_path))
            
            p = doc.add_paragraph()
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(6)
            try:
                if os.path.exists(full_img_path):
                    r = p.add_run()
                    r.add_picture(full_img_path, width=Cm(15))
                else:
                    set_run_font(p.add_run(safe_lat2cyr(f"[Rasm topilmadi: {full_img_path}]", ignored_words)), italic=True)
            except Exception as e:
                set_run_font(p.add_run(safe_lat2cyr(f"[Rasm yuklashda xato: {str(e)}]", ignored_words)), italic=True)
                
            i += 1
            continue
            
        list_match = re.match(r'^(\*|-|\d+\.)\s+(.*)', line)
        if list_match:
            p = doc.add_paragraph()
            text = list_match.group(2)
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.left_indent = Cm(1.25)
            bullet = list_match.group(1)
            
            r_bullet = p.add_run(safe_lat2cyr('•\t' if bullet in ['*', '-'] else f'{bullet}\t', ignored_words))
            set_run_font(r_bullet, size=14)
            parse_inline(p, text, size=14, ignored_words=ignored_words)
            i += 1
            continue

        # Skip horizontal rules
        if line.strip().startswith('***') or line.strip().startswith('---'):
            i += 1
            continue

        stripped = line.strip()
        p = doc.add_paragraph()

        # === GOST ELEMENT DETECTION ===
        
        # 1. Table number: "**X.Y-жадвал.**" or "**X.Y-jadval.**" → RIGHT, BOLD
        if re.match(r'^\*\*\d+\.\d+-?(жадвал|jadval)\.?\*\*$', stripped, re.IGNORECASE):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(2)
            parse_inline(p, stripped, size=14, ignored_words=ignored_words)
            i += 1
            continue

        # 2. Figure caption: "X.Y-расм." or "X.Y-rasm." (NOT bold!) → CENTER
        if re.match(r'^(\*\*)?\d+\.\d+-?(расм|rasm)\.', stripped, re.IGNORECASE):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(12)
            # Strip bold markers if present — figure captions must NOT be bold
            clean_text = stripped.replace('**', '')
            run = p.add_run(safe_lat2cyr(clean_text, ignored_words))
            set_run_font(run, size=14, bold=False)
            i += 1
            continue

        # 3. Chapter header: "**I БОБ." or "**II BOB." etc. → CENTER, BOLD
        if re.match(r'^\*\*(I{1,4}V?|V?I{0,3})\s+(БОБ|BOB)\.', stripped):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(24)
            p.paragraph_format.space_after = Pt(14)
            parse_inline(p, stripped, size=14, ignored_words=ignored_words)
            i += 1
            continue

        # 4. Section header: "**1.1. Text**" or "**2.3. Text**" → CENTER, BOLD
        if re.match(r'^\*\*\d+\.\d+\.?\s+', stripped) and stripped.endswith('**'):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(14)
            parse_inline(p, stripped, size=14, ignored_words=ignored_words)
            i += 1
            continue

        # 5. Chapter conclusion: "**...bob bo'yicha xulosa...**" → CENTER, BOLD
        if re.match(r'^\*\*.*(боб бўйича хулосалар|bob bo.yicha xulosa|ХУЛОСАЛАР|XULOSA).*\*\*$', stripped, re.IGNORECASE):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(14)
            parse_inline(p, stripped, size=14, ignored_words=ignored_words)
            i += 1
            continue

        # 6. "КИРИШ" / "KIRISH" header → CENTER, BOLD
        if re.match(r'^\*\*(КИРИШ|KIRISH)\*\*$', stripped, re.IGNORECASE):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(14)
            parse_inline(p, stripped, size=14, ignored_words=ignored_words)
            i += 1
            continue

        # 7. References header → CENTER, BOLD
        if re.match(r'^\*\*(ФОЙДАЛАНИЛГАН|FOYDALANILGAN).*\*\*$', stripped, re.IGNORECASE):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(14)
            parse_inline(p, stripped, size=14, ignored_words=ignored_words)
            i += 1
            continue

        # 8. Bold-only short line (likely a table title after table number) → CENTER, BOLD
        if stripped.startswith('**') and stripped.endswith('**') and len(stripped) < 200 and '\n' not in stripped:
            if len(doc.paragraphs) >= 2:
                prev_p = doc.paragraphs[-2]
                prev_text = prev_p.text.strip()
                if re.match(r'^\d+\.\d+-?(жадвал|jadval)\.?$', prev_text, re.IGNORECASE):
                    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    p.paragraph_format.first_line_indent = Cm(0)
                    p.paragraph_format.space_after = Pt(6)
                    parse_inline(p, stripped, size=14, ignored_words=ignored_words)
                    i += 1
                    continue

        # DEFAULT: Regular body text → JUSTIFY, 1.25cm indent
        p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.paragraph_format.first_line_indent = Cm(1.25)
            
        parse_inline(p, stripped, size=14, ignored_words=ignored_words)
        i += 1

    if in_table:
        add_table_to_doc(table_data)

    doc.save(docx_filepath)
    print(f"[{docx_filepath}] muvaffaqiyatli saqlandi (GOST standart, Kirill yozuvi, 14pt).")
    if ignored_words:
        print(f"Himoyalangan terminlar ({len(ignored_words)} ta) o'zgartirilmadi.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert MD to Cyrillic DOCX obeying GOST standards.')
    parser.add_argument('input', help='Input Markdown file')
    parser.add_argument('output', help='Output DOCX file')
    args = parser.parse_args()
    parse_markdown_to_docx(args.input, args.output)
