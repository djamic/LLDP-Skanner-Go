"""
Mermaid-to-Visio Flowchart Renderer & Word OLE Embedder

Parses Mermaid flowchart code, draws shapes and connectors directly in
Microsoft Visio using COM automation, saves as .vsdx, then embeds the
Visio diagrams as OLE objects into a Word DOCX.

Usage:
    python instruments/embed_visio_objects.py md_docs/3_bob.md 3_bob_gost_latin.docx 3_bob_final.docx
"""
import os, sys, re, uuid

# ─── Mermaid Parser ───────────────────────────────────────────────────────

def parse_mermaid(code):
    """Parse mermaid flowchart code, returning nodes and edges."""
    nodes = {}   # id -> {label, shape}
    edges = []   # [{src, dst, label}]
    subgraphs = []
    
    lines = code.strip().split('\n')
    
    # Shape patterns for node definitions
    # NodeId[label]       -> rectangle (Process)
    # NodeId(label)       -> rounded (Start/End)
    # NodeId([label])     -> stadium (Start/End)
    # NodeId{label}       -> diamond (Decision)
    # NodeId[[label]]     -> subroutine (Subprocess)
    # NodeId[/label/]     -> parallelogram (Data)
    # NodeId[(label)]     -> cylinder (Database)
    # NodeId((label))     -> circle (On-page reference)
    
    def extract_node(token):
        """Parse a node token like 'A[text]' or 'B{text}' and return (id, label, shape)."""
        token = token.strip()
        if not token:
            return None
        
        # Try various bracket patterns
        patterns = [
            (r'^(\w+)\(\[(.+?)\]\)$', 'Start/End'),       # ([label])
            (r'^(\w+)\(\((.+?)\)\)$', 'On-page reference'),# ((label))
            (r'^(\w+)\[\[(.+?)\]\]$', 'Subprocess'),       # [[label]]
            (r'^(\w+)\[/(.+?)/\]$',   'Data'),             # [/label/]
            (r'^(\w+)\[\((.+?)\)\]$', 'Database'),         # [(label)]
            (r'^(\w+)\{(.+?)\}$',     'Decision'),         # {label}
            (r'^(\w+)\[(.+?)\]$',     'Process'),          # [label]
            (r'^(\w+)\((.+?)\)$',     'Start/End'),        # (label)
        ]
        
        for pat, shape in patterns:
            m = re.match(pat, token, re.DOTALL)
            if m:
                nid = m.group(1)
                label = m.group(2).strip().strip('"').strip("'")
                label = label.replace('\\n', '\n').replace('<br>', '\n')
                return (nid, label, shape)
        
        # Plain node ID (no brackets)
        m = re.match(r'^(\w+)$', token)
        if m:
            return (m.group(1), m.group(1), 'Process')
        
        return None
    
    for line in lines:
        stripped = line.strip()
        
        # Skip directives, comments, styles
        if not stripped or stripped.startswith('%%') or stripped.startswith('classDef') or \
           stripped.startswith('class ') or stripped.startswith('flowchart') or \
           stripped.startswith('graph') or stripped == 'end':
            continue
        
        # Handle subgraph
        if stripped.startswith('subgraph'):
            m = re.match(r'subgraph\s+(\w+)\s*\[?(.*?)\]?\s*$', stripped)
            if m:
                sg_id = m.group(1)
                sg_label = m.group(2).strip().strip('"') if m.group(2) else sg_id
                subgraphs.append({'id': sg_id, 'label': sg_label})
            continue
        
        # Parse edges: A --> B, A -- text --> B, A -->|text| B
        # Handle & for multiple sources: T1 & T2 & T3 --> Dest
        edge_patterns = [
            r'(.+?)\s*-->\s*\|(.+?)\|\s*(.+)',       # A -->|label| B
            r'(.+?)\s*--\s+(.+?)\s+-->\s*(.+)',      # A -- label --> B
            r'(.+?)\s*-->\s*(.+)',                    # A --> B  (no label)
        ]
        
        matched = False
        for ep_idx, ep in enumerate(edge_patterns):
            m = re.match(ep, stripped)
            if m:
                if ep_idx < 2:
                    src_str = m.group(1).strip()
                    label_str = m.group(2).strip().strip('"')
                    dst_str = m.group(3).strip()
                else:
                    src_str = m.group(1).strip()
                    label_str = ''
                    dst_str = m.group(2).strip()
                
                # Handle & operator for multiple sources
                srcs = [s.strip() for s in src_str.split('&')]
                dsts = [d.strip() for d in dst_str.split('&')]
                
                for src_token in srcs:
                    src_node = extract_node(src_token)
                    if src_node:
                        nid, nlabel, nshape = src_node
                        if nid not in nodes:
                            nodes[nid] = {'label': nlabel, 'shape': nshape}
                    else:
                        src_node = (src_token, src_token, 'Process')
                    
                    for dst_token in dsts:
                        dst_node = extract_node(dst_token)
                        if dst_node:
                            nid2, nlabel2, nshape2 = dst_node
                            if nid2 not in nodes:
                                nodes[nid2] = {'label': nlabel2, 'shape': nshape2}
                        else:
                            dst_node = (dst_token, dst_token, 'Process')
                        
                        edges.append({
                            'src': src_node[0],
                            'dst': dst_node[0],
                            'label': label_str
                        })
                
                matched = True
                break
        
        if not matched:
            # Standalone node definition
            node = extract_node(stripped)
            if node:
                nid, nlabel, nshape = node
                if nid not in nodes:
                    nodes[nid] = {'label': nlabel, 'shape': nshape}
    
    return nodes, edges, subgraphs

# ─── Visio Drawing ────────────────────────────────────────────────────────

def draw_in_visio(nodes, edges, output_vsdx):
    """Draw the flowchart in Visio using COM automation."""
    import win32com.client
    
    visio = win32com.client.Dispatch('Visio.Application')
    visio.Visible = False
    
    try:
        # Create blank document & open flowchart stencil
        doc = visio.Documents.Add("")
        page = doc.Pages(1)
        
        stencil = visio.Documents.OpenEx("BASFLO_U.VSSX", 64)  # visOpenDocked
        
        # Map mermaid shape types to Visio master NameU values
        shape_map = {
            'Process':          'Process',
            'Decision':         'Decision',
            'Start/End':        'Start/End',
            'Subprocess':       'Subprocess',
            'Data':             'Data',
            'Database':         'Database',
            'On-page reference':'On-page reference',
        }
        
        # Get master shapes
        masters = {}
        for key, name_u in shape_map.items():
            try:
                masters[key] = stencil.Masters.ItemU(name_u)
            except:
                masters[key] = stencil.Masters.ItemU('Process')
        
        connector_master = stencil.Masters.ItemU('Dynamic connector')
        
        # Calculate layout positions (top-down flow)
        # Simple approach: arrange nodes in order of first appearance
        node_ids = list(nodes.keys())
        
        # Build adjacency to determine levels using topological ordering
        children = {nid: [] for nid in node_ids}
        parents = {nid: [] for nid in node_ids}
        for edge in edges:
            if edge['src'] in children and edge['dst'] in node_ids:
                children[edge['src']].append(edge['dst'])
                parents[edge['dst']].append(edge['src'])
        
        # BFS level assignment
        roots = [nid for nid in node_ids if not parents[nid]]
        if not roots:
            roots = [node_ids[0]] if node_ids else []
        
        levels = {}
        queue = list(roots)
        for r in roots:
            levels[r] = 0
        
        visited = set(roots)
        while queue:
            current = queue.pop(0)
            for child in children.get(current, []):
                if child not in visited:
                    levels[child] = levels[current] + 1
                    visited.add(child)
                    queue.append(child)
        
        # Assign remaining unvisited nodes
        max_level = max(levels.values()) if levels else 0
        for nid in node_ids:
            if nid not in levels:
                max_level += 1
                levels[nid] = max_level
        
        # Group by level, calculate x positions
        level_nodes = {}
        for nid, lvl in levels.items():
            level_nodes.setdefault(lvl, []).append(nid)
        
        # Page dimensions (inches): standard A4 landscape ~11.69 x 8.27
        page_w = 11.69
        page_h = max(8.27, len(level_nodes) * 1.8 + 2)
        
        try:
            page.PageSheet.Cells("PageWidth").FormulaU = f"{page_w} in"
            page.PageSheet.Cells("PageHeight").FormulaU = f"{page_h} in"
        except:
            pass
        
        # Drop shapes
        visio_shapes = {}
        for lvl in sorted(level_nodes.keys()):
            nids = level_nodes[lvl]
            count = len(nids)
            spacing = min(page_w / (count + 1), 3.0)
            start_x = (page_w - (count - 1) * spacing) / 2
            y = page_h - 1.5 - lvl * 1.8  # Top-down
            
            for idx, nid in enumerate(nids):
                x = start_x + idx * spacing
                info = nodes[nid]
                shape_type = info['shape']
                master = masters.get(shape_type, masters['Process'])
                
                shape = page.Drop(master, x, y)
                shape.Text = info['label']
                
                # Resize for long text
                text_len = len(info['label'])
                if text_len > 20:
                    try:
                        shape.Cells("Width").FormulaU = f"{min(2.5, 0.15 * text_len)} in"
                    except:
                        pass
                
                # Set font size to 8pt for readability
                try:
                    shape.Cells("Char.Size").FormulaU = "8 pt"
                except:
                    pass
                
                visio_shapes[nid] = shape
        
        # Connect shapes
        for edge in edges:
            src_id = edge['src']
            dst_id = edge['dst']
            if src_id not in visio_shapes or dst_id not in visio_shapes:
                continue
            
            src_shape = visio_shapes[src_id]
            dst_shape = visio_shapes[dst_id]
            
            # Drop a dynamic connector
            conn = page.Drop(connector_master, 0, 0)
            
            # Glue begin to source, end to destination
            conn.Cells("BeginX").GlueTo(src_shape.Cells("PinX"))
            conn.Cells("EndX").GlueTo(dst_shape.Cells("PinX"))
            
            # Add label to connector if present
            if edge.get('label'):
                conn.Text = edge['label']
                try:
                    conn.Cells("Char.Size").FormulaU = "7 pt"
                except:
                    pass
        
        # Auto-layout the page
        try:
            page.Layout()
            page.ResizeToFitContents()
        except:
            pass
        
        # Save
        abs_path = os.path.abspath(output_vsdx)
        doc.SaveAs(abs_path)
        doc.Close()
        
        return os.path.exists(abs_path)
    
    except Exception as e:
        print(f"  Visio drawing error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        try:
            visio.Quit()
        except:
            pass

# ─── Main Pipeline ────────────────────────────────────────────────────────

def extract_mermaid_blocks(md_path):
    """Extract all ```mermaid blocks from the markdown file."""
    with open(md_path, 'r', encoding='utf-8') as f:
        content = f.read()
    blocks = []
    pattern = re.compile(r'```mermaid\s*\n(.*?)```', re.DOTALL)
    for match in pattern.finditer(content):
        blocks.append(match.group(1).strip())
    return blocks

def embed_visio_in_docx(docx_in, docx_out, vsdx_files):
    """Replace image shapes in DOCX with Visio OLE objects via Word COM."""
    import win32com.client
    
    word = win32com.client.Dispatch('Word.Application')
    word.Visible = False
    word.DisplayAlerts = False
    
    try:
        doc = word.Documents.Open(os.path.abspath(docx_in))
        shapes_count = doc.InlineShapes.Count
        print(f"  Word doc: {shapes_count} inline shapes")
        
        # Collect ALL inline shapes (type 17 = wdInlineShapeLinkedPicture or embedded)
        image_indices = []
        for i in range(1, shapes_count + 1):
            s = doc.InlineShapes(i)
            # Accept types: 3 (Picture), 17 (LinkedPicture), or any with Width > 200
            if s.Type in (3, 17) or s.Width > 200:
                image_indices.append(i)
        
        print(f"  Found {len(image_indices)} diagram shapes, have {len(vsdx_files)} Visio files")
        
        # Replace from end to start
        pairs = list(zip(reversed(image_indices), reversed(vsdx_files)))
        replaced = 0
        
        for shape_idx, vsdx_path in pairs:
            if not os.path.exists(vsdx_path):
                continue
            
            shape = doc.InlineShapes(shape_idx)
            rng = shape.Range
            shape.Delete()
            
            try:
                obj = doc.InlineShapes.AddOLEObject(
                    ClassType="Visio.Drawing.15",
                    FileName=os.path.abspath(vsdx_path),
                    LinkToFile=False,
                    DisplayAsIcon=False,
                    Range=rng
                )
                
                # Scale to fit page width
                if obj.Width > 450:
                    scale = 450.0 / obj.Width
                    obj.Width = int(obj.Width * scale)
                    obj.Height = int(obj.Height * scale)
                
                replaced += 1
                print(f"  Replaced shape #{shape_idx} -> Visio OLE ({obj.Width}x{obj.Height})")
            except Exception as e:
                print(f"  Failed shape #{shape_idx}: {e}")
        
        print(f"  Total: {replaced}/{len(vsdx_files)} replaced")
        
        doc.SaveAs2(os.path.abspath(docx_out))
        doc.Close(False)
    except Exception as e:
        print(f"  Word error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        word.Quit()

def main():
    if len(sys.argv) < 4:
        print("Usage: python embed_visio_objects.py <input.md> <input.docx> <output.docx>")
        sys.exit(1)
    
    md_path = sys.argv[1]
    docx_in = sys.argv[2]
    docx_out = sys.argv[3]
    
    print(f"[1/3] Extracting Mermaid blocks from {md_path}...")
    blocks = extract_mermaid_blocks(md_path)
    print(f"  Found {len(blocks)} diagrams")
    
    if not blocks:
        print("No Mermaid diagrams. Done.")
        sys.exit(0)
    
    print(f"[2/3] Drawing Visio diagrams...")
    vsdx_dir = 'visio_objects'
    os.makedirs(vsdx_dir, exist_ok=True)
    vsdx_files = []
    
    for i, code in enumerate(blocks):
        vsdx_path = os.path.join(vsdx_dir, f'diagram_{i+1}.vsdx')
        print(f"  Diagram {i+1}/{len(blocks)}...", end=' ')
        
        nodes, edges, subgraphs = parse_mermaid(code)
        print(f"({len(nodes)} nodes, {len(edges)} edges)", end=' ')
        
        if draw_in_visio(nodes, edges, vsdx_path):
            vsdx_files.append(os.path.abspath(vsdx_path))
            print(f"OK ({os.path.getsize(vsdx_path)} bytes)")
        else:
            print("FAILED")
    
    print(f"  Created {len(vsdx_files)}/{len(blocks)} VSDX files")
    
    print(f"[3/3] Embedding into {docx_out}...")
    embed_visio_in_docx(docx_in, docx_out, vsdx_files)
    
    print(f"\nDone! Output: {docx_out}")

if __name__ == '__main__':
    main()
