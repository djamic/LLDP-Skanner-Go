#!/usr/bin/env python3
"""
MD → DOCX (GOST standart) — Linux versiya
Mermaid diagrammalarni mermaid-cli (mmdc) orqali PNG ga aylantiradi.
Visio COM o'rniga kross-platform yechim.

Usage:
    python3 instrumens/md2docx_gost_linux.py input.md output.docx
"""
import os
import argparse
import sys
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
import subprocess
import shutil
import pypandoc
from docx import Document
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

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

# --- Batch LaTeX Math Cache ---
_math_cache = {}  # latex_string -> (omath_xml_bytes, is_block)

def _batch_convert_math(latex_strings_with_mode):
    """
    Batch-convert multiple LaTeX strings into OMath XML elements in ONE pypandoc call.
    Input: list of (latex_string, is_block) tuples.
    Populates _math_cache with results.
    """
    if not latex_strings_with_mode:
        return
    
    # Build a single markdown with all formulas separated by markers
    md_parts = []
    for latex_str, is_block in latex_strings_with_mode:
        if is_block:
            md_parts.append(f"\n\n$${latex_str}$$\n\n")
        else:
            md_parts.append(f"\nINLINE_MATH_MARKER ${latex_str}$\n")
    
    combined_md = "\n".join(md_parts)
    tmp_path = f"/tmp/tmp_math_batch_{uuid.uuid4().hex}.docx"
    try:
        pypandoc.convert_text(combined_md, 'docx', format='markdown', outputfile=tmp_path)
        tmp_doc = Document(tmp_path)
        
        math_idx = 0
        for tmp_p in tmp_doc.paragraphs:
            xml_str = tmp_p._element.xml
            if "oMath" not in xml_str:
                continue
            if math_idx >= len(latex_strings_with_mode):
                break
                
            latex_str, is_block = latex_strings_with_mode[math_idx]
            
            if is_block:
                omaths = tmp_p._element.xpath('.//m:oMathPara')
                if not omaths:
                    omaths = tmp_p._element.xpath('.//m:oMath')
            else:
                omaths = tmp_p._element.xpath('.//m:oMath')
            
            if omaths:
                from lxml import etree
                _math_cache[latex_str] = (etree.tostring(omaths[0]), is_block)
            math_idx += 1
    except Exception as e:
        print(f"Batch math conversion failed: {e}")
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except:
                pass


def add_latex_math(paragraph, latex_string, is_block=False):
    """
    Leverages cached OMath XML (from batch pre-processing) or falls back
    to single pypandoc conversion for native MS Word equations.
    """
    # Try cache first (populated by _batch_convert_math)
    if latex_string in _math_cache:
        from lxml import etree
        xml_bytes, _ = _math_cache[latex_string]
        math_element = etree.fromstring(xml_bytes)
        paragraph._element.append(math_element)
        return
    
    # Fallback: single conversion
    md = f"$${latex_string}$$" if is_block else f"${latex_string}$"
    tmp_path = f"/tmp/tmp_math_{uuid.uuid4().hex}.docx"
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
            paragraph._element.append(math_element)
        else:
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


def parse_mermaid_nodes_edges(mermaid_code):
    """Parse mermaid graph code and extract nodes (id->label) and edges."""
    nodes = {}  # id -> label
    edges = []  # [(src_id, dst_id, label)]
    
    # Pre-process: join multiline labels (lines inside ["..."] that span multiple lines)
    raw_lines = mermaid_code.strip().split('\n')
    lines = []
    buffer = ''
    in_bracket = False
    for raw_line in raw_lines:
        if in_bracket:
            buffer += '\n' + raw_line
            # Check if closing bracket found
            if '"]' in raw_line or "']" in raw_line or '])' in raw_line or '})' in raw_line:
                in_bracket = False
                lines.append(buffer)
                buffer = ''
        else:
            # Check if line has opening bracket without matching close
            stripped = raw_line.strip()
            has_open = bool(re.search(r'\w+\["[^"]*$', stripped) or re.search(r"\w+\['[^']*$", stripped))
            if has_open:
                in_bracket = True
                buffer = raw_line
            else:
                lines.append(raw_line)
    if buffer:
        lines.append(buffer)
    
    def extract_node(token):
        token = token.strip()
        if not token:
            return None
        patterns = [
            r'^(\w+)\(\[(.+?)\]\)$',
            r'^(\w+)\(\((.+?)\)\)$',
            r'^(\w+)\[\[(.+?)\]\]$',
            r'^(\w+)\[/(.+?)/\]$',
            r'^(\w+)\[\((.+?)\)\]$',
            r'^(\w+)\{(.+?)\}$',
            r'^(\w+)\[(.+?)\]$',
            r'^(\w+)\((.+?)\)$',
        ]
        for pat in patterns:
            m = re.match(pat, token, re.DOTALL)
            if m:
                nid = m.group(1)
                label = m.group(2).strip().strip('"').strip("'")
                label = label.replace('\\n', '\n').replace('<br>', '\n')
                return (nid, label)
        m = re.match(r'^(\w+)$', token)
        if m:
            return (m.group(1), m.group(1))
        return None
    
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('%%') or stripped.startswith('classDef') or \
           stripped.startswith('class ') or stripped.startswith('flowchart') or \
           stripped.startswith('graph') or stripped == 'end' or stripped.startswith('subgraph') or \
           stripped.startswith('style '):
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
                    src_str, label_str, dst_str = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
                else:
                    src_str, label_str, dst_str = m.group(1).strip(), '', m.group(2).strip()
                
                for src_token in [s.strip() for s in src_str.split('&')]:
                    sn = extract_node(src_token)
                    if sn:
                        if sn[0] not in nodes: nodes[sn[0]] = sn[1]
                    else:
                        sn = (src_token, src_token)
                    for dst_token in [d.strip() for d in dst_str.split('&')]:
                        dn = extract_node(dst_token)
                        if dn:
                            if dn[0] not in nodes: nodes[dn[0]] = dn[1]
                        else:
                            dn = (dst_token, dst_token)
                        edges.append((sn[0], dn[0], label_str))
                matched = True
                break
        
        if not matched:
            node = extract_node(stripped)
            if node and node[0] not in nodes:
                nodes[node[0]] = node[1]
    
    return nodes, edges


def mermaid_to_graphviz(mermaid_code):
    """Convert mermaid graph code to Graphviz DOT format with proper tree hierarchy."""
    from collections import defaultdict, deque
    
    nodes, edges = parse_mermaid_nodes_edges(mermaid_code)
    
    adj = defaultdict(set)
    for src, dst, label in edges:
        adj[src].add(dst)
        adj[dst].add(src)
    
    all_node_ids = set(nodes.keys())
    for src, dst, _ in edges:
        all_node_ids.add(src)
        all_node_ids.add(dst)
    
    def get_ip_from_label(nid):
        label = nodes.get(nid, '')
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)', label)
        return m.group(1) if m else ''
    
    def root_score(nid):
        degree = len(adj[nid])
        ip = get_ip_from_label(nid)
        subnet_bonus = 0
        if '.254.' in ip:
            subnet_bonus = 1000
        elif '.253.' in ip:
            subnet_bonus = 500
        return degree + subnet_bonus
    
    connected_nodes = [nid for nid in all_node_ids if len(adj[nid]) > 0]
    if not connected_nodes:
        connected_nodes = list(all_node_ids)
    
    root = max(connected_nodes, key=root_score) if connected_nodes else list(all_node_ids)[0]
    
    # Build edge label lookup
    edge_labels = {}
    for src, dst, label in edges:
        edge_labels[(src, dst)] = label
        edge_labels[(dst, src)] = label
    
    visited = set()
    tree_edges = []
    queue = deque([root])
    visited.add(root)
    
    while queue:
        current = queue.popleft()
        for neighbor in adj[current]:
            if neighbor not in visited:
                visited.add(neighbor)
                tree_edges.append((current, neighbor))
                queue.append(neighbor)
    
    isolated = all_node_ids - visited
    
    dot_lines = [
        'digraph topology {',
        '    rankdir=LR;',
        '    splines=ortho;',
        '    nodesep=0.5;',
        '    ranksep=1.0;',
        '    bgcolor=white;',
        '    dpi=300;',
        '',
        '    node [',
        '        shape=box,',
        '        style="filled,rounded",',
        '        fillcolor="#E8F4FD",',
        '        color="#2196F3",',
        '        fontname="Helvetica",',
        '        fontsize=11,',
        '        penwidth=1.5,',
        '        margin="0.2,0.1"',
        '    ];',
        '',
        '    edge [',
        '        color="#555555",',
        '        arrowsize=0.7,',
        '        penwidth=1.2,',
        '        fontname="Helvetica",',
        '        fontsize=7,',
        '        fontcolor="#666666",',
        '    ];',
        '',
    ]
    
    # Parse style directives from mermaid for colored nodes
    mermaid_lines = mermaid_code.strip().split('\n')
    styled_nodes = {}
    for line in mermaid_lines:
        stripped = line.strip()
        style_match = re.match(r'^style\s+(\w+)\s+fill:(#\w+)', stripped)
        if style_match:
            styled_nodes[style_match.group(1)] = style_match.group(2)
    
    # Detect round-shaped nodes as hubs
    hub_nodes = set()
    for line in mermaid_lines:
        stripped = line.strip()
        m = re.match(r'^(\w+)\(\((.+?)\)\)$', stripped)
        if m:
            hub_nodes.add(m.group(1))
    
    # The BFS root (the core) keeps the fill of its group: it used to be
    # filled #FF9800, the colour the legend names 'Hub', so the core switch
    # looked like a Shadow-IT hub. A thick dark border marks it instead.
    if root in nodes:
        label = nodes[root].replace('\n', '\\n').replace('"', '\\"')
        fill = styled_nodes.get(root)
        if fill:
            shape = 'ellipse' if root in hub_nodes else 'box'
            dot_lines.append(f'    "{root}" [label="{label}", fillcolor="{fill}", fontcolor="white", color="#212121", penwidth=3.5, fontsize=12, shape={shape}];')
        else:
            dot_lines.append(f'    "{root}" [label="{label}", color="#212121", penwidth=3.5, fontsize=12];')
    
    for nid in all_node_ids:
        if nid == root:
            continue
        label = nodes.get(nid, nid).replace('\n', '\\n').replace('"', '\\"')
        if nid in styled_nodes:
            fill = styled_nodes[nid]
            shape = 'ellipse' if nid in hub_nodes else 'box'
            dot_lines.append(f'    "{nid}" [label="{label}", fillcolor="{fill}", fontcolor="white", color="{fill}", penwidth=2.0, shape={shape}];')
        elif nid in isolated:
            dot_lines.append(f'    "{nid}" [label="{label}", fillcolor="#EEEEEE", color="#999999"];')
        else:
            dot_lines.append(f'    "{nid}" [label="{label}"];')
    
    dot_lines.append('')
    
    for parent, child in tree_edges:
        elabel = edge_labels.get((parent, child), '')
        if elabel and '↔' in elabel:
            parts = elabel.split('↔')
            tail = parts[0].strip().replace('"', '\\"')
            head = parts[1].strip().replace('"', '\\"')
            dot_lines.append(f'    "{parent}" -> "{child}" [taillabel="{tail}", headlabel="{head}", labeldistance=2.5, labelangle=25];')
        elif elabel:
            elabel_safe = elabel.replace('"', '\\"')
            dot_lines.append(f'    "{parent}" -> "{child}" [xlabel="{elabel_safe}"];')
        else:
            dot_lines.append(f'    "{parent}" -> "{child}";')
    # Build legend from unique colors used
    group_label_map = {
        '#4A90E2': 'Switch', '#64B5F6': 'Unpolled switch', '#E24A4A': 'Router', '#FF9800': 'Hub', '#FFC107': 'Mini hub', '#4DB6AC': 'AP hub',
        '#8BC34A': 'Endpoint', '#00BCD4': 'Wi-Fi AP / Random MAC',
        '#9C27B0': 'VM', '#26C6DA': 'Hypervisor', '#FF6F00': 'BMC/iLO',
        '#E91E63': 'Camera', '#3F51B5': 'Phone', '#9575CD': 'Mobile', '#607D8B': 'IoT',
        '#795548': 'Printer', '#FF5722': 'Server', '#9E9E9E': 'Unknown',
    }
    used_colors = {}
    for nid, fill in styled_nodes.items():
        if fill not in used_colors:
            lbl = group_label_map.get(fill, fill)
            used_colors[fill] = lbl
    
    if used_colors:
        dot_lines.append('')
        dot_lines.append('    subgraph cluster_legend {')
        dot_lines.append('        label="Izoh";')
        dot_lines.append('        style=rounded;')
        dot_lines.append('        color="#AAAAAA";')
        dot_lines.append('        fontname="Helvetica";')
        dot_lines.append('        fontsize=12;')
        dot_lines.append('        bgcolor="#F8F8F8";')
        dot_lines.append('        rankdir=TB;')
        
        legend_ids = []
        for i, (color, label) in enumerate(used_colors.items()):
            lid = f'legend_{i}'
            legend_ids.append(lid)
            dot_lines.append(f'        {lid} [label="{label}", fillcolor="{color}", fontcolor="white", color="{color}", shape=box, fontsize=10, margin="0.15,0.06"];')
        
        if len(legend_ids) > 1:
            chain = ' -> '.join(legend_ids)
            dot_lines.append(f'        {chain} [style=invis];')
        
        dot_lines.append('    }')
    
    dot_lines.append('}')
    return '\n'.join(dot_lines)


def _render_single_diagram(args):
    """Render a single DOT diagram to PNG. Used by ThreadPoolExecutor."""
    idx, dot_code, png_dir, md_basename, dot_path = args
    dot_path_file = os.path.join(png_dir, f'{md_basename}_diagram_{idx}.dot')
    png_path = os.path.join(png_dir, f'{md_basename}_diagram_{idx}.png')
    
    with open(dot_path_file, 'w', encoding='utf-8') as df:
        df.write(dot_code)
    
    try:
        result = subprocess.run(
            [dot_path, '-Tpng', dot_path_file, '-o', png_path],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0 and os.path.exists(png_path):
            return (idx, os.path.abspath(png_path), 'OK')
        else:
            return (idx, None, f'FAILED ({result.stderr.strip()[:100]})')
    except subprocess.TimeoutExpired:
        return (idx, None, 'TIMEOUT')
    except Exception as e:
        return (idx, None, f'ERROR ({e})')
    finally:
        try:
            os.remove(dot_path_file)
        except:
            pass


def pre_generate_diagrams(md_filepath):
    """Pre-scan the markdown for mermaid blocks and generate PNG images using Graphviz.
    Renders diagrams in parallel using ThreadPoolExecutor."""
    png_files = {}
    
    dot_path = shutil.which('dot')
    if not dot_path:
        print("  [WARNING] Graphviz (dot) topilmadi! Diagrammalar o'tkazib yuboriladi.")
        print("  O'rnatish: sudo apt-get install -y graphviz")
        return png_files
    
    with open(md_filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    md_basename = os.path.splitext(os.path.basename(md_filepath))[0]
    
    in_mermaid = False
    mermaid_lines = []
    mermaid_idx = 0
    png_dir = os.path.join(os.path.dirname(os.path.abspath(md_filepath)), f'mermaid_{uuid.uuid4().hex[:8]}')
    os.makedirs(png_dir, exist_ok=True)
    
    # Collect all mermaid blocks first
    render_tasks = []  # (idx, dot_code, png_dir, md_basename, dot_path)
    
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
                dot_code = mermaid_to_graphviz(code)
                render_tasks.append((mermaid_idx, dot_code, png_dir, md_basename, dot_path))
            else:
                mermaid_lines.append(line.rstrip('\n').rstrip('\r'))
    
    # Render all diagrams in parallel
    if render_tasks:
        max_workers = min(len(render_tasks), os.cpu_count() or 4)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(_render_single_diagram, render_tasks))
        
        for idx, path, status in results:
            print(f"  Diagram {idx}: {status}")
            if path:
                png_files[idx] = path
    
    print(f"  Total diagrams pre-generated: {len(png_files)}")
    return png_files, png_dir


# process_label_for_visio() removed — was dead code (never called)


def parse_inline(paragraph, text, size=14):
    """Parses simple inline bold formatting **...**, italic *...*, and inline math $...$"""
    # Split by bold first
    parts = re.split(r'(\*\*.*?\*\*)', text)
    for part in parts:
        if part.startswith('**') and part.endswith('**') and len(part) > 3:
            inner = part[2:-2]
            # Recursively handle math inside bold text
            math_parts = re.split(r'(\$.*?\$)', inner)
            for mp in math_parts:
                if mp.startswith('$') and mp.endswith('$') and len(mp) > 1:
                    add_latex_math(paragraph, mp[1:-1].strip(), is_block=False)
                else:
                    if mp:
                        run = paragraph.add_run(mp)
                        set_run_font(run, size=size, bold=True)
        else:
            # Split by inline math $...$
            math_parts = re.split(r'(\$.*?\$)', part)
            for mp in math_parts:
                if mp.startswith('$') and mp.endswith('$') and len(mp) > 1:
                    add_latex_math(paragraph, mp[1:-1].strip(), is_block=False)
                else:
                    # Finally split by italic *...*
                    subparts = re.split(r'(\*.*?\*)', mp)
                    for sp in subparts:
                        if sp.startswith('*') and sp.endswith('*') and len(sp) > 2:
                            run = paragraph.add_run(sp[1:-1])
                            set_run_font(run, size=size, italic=True)
                        else:
                            if sp:
                                run = paragraph.add_run(sp)
                                set_run_font(run, size=size)

def configure_margins(doc):
    for section in doc.sections:
        section.top_margin = Cm(2)
        section.bottom_margin = Cm(2)
        section.left_margin = Cm(3)
        section.right_margin = Cm(1.5)

def _prescan_latex(md_filepath):
    """Pre-scan MD file for all LaTeX math strings and batch-convert them."""
    with open(md_filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    math_items = []  # (latex_string, is_block)
    
    # Block math: $$ ... $$
    for m in re.finditer(r'\$\$(.+?)\$\$', content, re.DOTALL):
        math_items.append((m.group(1).strip(), True))
    
    # Inline math: $ ... $ (not inside $$)
    # Remove block math first, then find inline
    content_no_block = re.sub(r'\$\$.+?\$\$', '', content, flags=re.DOTALL)
    for m in re.finditer(r'(?<!\$)\$([^$]+?)\$(?!\$)', content_no_block):
        math_items.append((m.group(1).strip(), False))
    
    if math_items:
        print(f"  [math] {len(math_items)} ta formulani batch konvert qilish...")
        _batch_convert_math(math_items)
        print(f"  [math] {len(_math_cache)} ta formula tayyor.")


def parse_markdown_to_docx(md_filepath, docx_filepath):
    # Pre-generate all Mermaid diagram PNG images BEFORE DOCX creation
    print(f"[mmdc] Mermaid diagrammalarni PNG ga eksport qilish...")
    png_files, png_dir = pre_generate_diagrams(md_filepath)
    
    # Pre-scan and batch-convert all LaTeX math
    _prescan_latex(md_filepath)
    
    doc = Document()
    apply_gost_style(doc)
    configure_margins(doc)
    
    with open(md_filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    in_table = False
    in_math_block = False
    in_mermaid_block = False
    math_lines = []
    mermaid_counter = 0  # Counter for mermaid diagrams (matches pre-generated PNG index)
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
                    cell.text = "" # Clear default
                    p = cell.paragraphs[0]
                    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
                    p.paragraph_format.first_line_indent = Cm(0)
                    parse_inline(p, cell_text.strip(), size=12)
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
                    p.paragraph_format.space_after = Pt(6)
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
            
            # Handle math inside headers
            math_parts = re.split(r'(\$.*?\$)', text)
            for mp in math_parts:
                if mp.startswith('$') and mp.endswith('$') and len(mp) > 1:
                    add_latex_math(paragraph=p, latex_string=mp[1:-1].strip(), is_block=False)
                else:
                    if mp:
                        run = p.add_run(mp)
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
                    set_run_font(p.add_run(f"[Rasm topilmadi: {full_img_path}]"), italic=True)
            except Exception as e:
                set_run_font(p.add_run(f"[Rasm yuklashda xato: {str(e)}]"), italic=True)
                
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
            
            r_bullet = p.add_run('•\t' if bullet in ['*', '-'] else f'{bullet}\t')
            set_run_font(r_bullet, size=14)
            parse_inline(p, text, size=14)
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
            parse_inline(p, stripped, size=14)
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
            run = p.add_run(clean_text)
            set_run_font(run, size=14, bold=False)
            i += 1
            continue

        # 3. Chapter header: "**I БОБ." or "**II BOB." etc. → CENTER, BOLD
        if re.match(r'^\*\*(I{1,4}V?|V?I{0,3})\s+(БОБ|BOB)\.', stripped):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(24)
            p.paragraph_format.space_after = Pt(14)
            parse_inline(p, stripped, size=14)
            i += 1
            continue

        # 4. Section header: "**1.1. Text**" or "**2.3. Text**" → CENTER, BOLD
        if re.match(r'^\*\*\d+\.\d+\.?\s+', stripped) and stripped.endswith('**'):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(14)
            parse_inline(p, stripped, size=14)
            i += 1
            continue

        # 5. Chapter conclusion: "**Birinchi bob bo'yicha xulosalar**" etc. → CENTER, BOLD
        if re.match(r'^\*\*.*(боб бўйича хулосалар|bob bo.yicha xulosa|ХУЛОСАЛАР|XULOSA).*\*\*$', stripped, re.IGNORECASE):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(14)
            parse_inline(p, stripped, size=14)
            i += 1
            continue

        # 6. "КИРИШ" / "KIRISH" header → CENTER, BOLD
        if re.match(r'^\*\*(КИРИШ|KIRISH)\*\*$', stripped, re.IGNORECASE):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(14)
            parse_inline(p, stripped, size=14)
            i += 1
            continue

        # 7. References header → CENTER, BOLD
        if re.match(r'^\*\*(ФОЙДАЛАНИЛГАН|FOYDALANILGAN).*\*\*$', stripped, re.IGNORECASE):
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(14)
            p.paragraph_format.space_after = Pt(14)
            parse_inline(p, stripped, size=14)
            i += 1
            continue

        # 8. Bold-only short line (likely a table title after table number) → CENTER, BOLD
        if stripped.startswith('**') and stripped.endswith('**') and len(stripped) < 200 and '\n' not in stripped:
            # Check if previous paragraph was a table number (RIGHT-aligned)
            if len(doc.paragraphs) >= 2:
                prev_p = doc.paragraphs[-2]  # -2 because current empty p is -1
                prev_text = prev_p.text.strip()
                if re.match(r'^\d+\.\d+-?(жадвал|jadval)\.?$', prev_text, re.IGNORECASE):
                    # This is a table title → CENTER
                    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    p.paragraph_format.first_line_indent = Cm(0)
                    p.paragraph_format.space_after = Pt(6)
                    parse_inline(p, stripped, size=14)
                    i += 1
                    continue

        # DEFAULT: Regular body text → JUSTIFY, 1.25cm indent
        p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.paragraph_format.first_line_indent = Cm(1.25)
            
        parse_inline(p, stripped, size=14)
        i += 1

    if in_table:
        add_table_to_doc(table_data)

    doc.save(docx_filepath)
    
    # Cleanup temporary mermaid PNG directory
    if png_dir and os.path.isdir(png_dir):
        try:
            shutil.rmtree(png_dir)
            print(f"  [cleanup] {png_dir} tozalandi.")
        except Exception as e:
            print(f"  [cleanup] Xato: {e}")
    print(f"[{docx_filepath}] muvaffaqiyatli saqlandi (GOST standart, qat'iy 14pt).")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert MD to DOCX obeying GOST standards (Linux).')
    parser.add_argument('input', help='Input Markdown file')
    parser.add_argument('output', help='Output DOCX file')
    args = parser.parse_args()
    parse_markdown_to_docx(args.input, args.output)
