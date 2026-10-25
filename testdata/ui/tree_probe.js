'use strict';
// tree_probe.js tests static/tree.js, the Tree tab, and prints the record
// TestGoldenUITree pins (testdata/golden/ui_tree.json):
//
//   node tree_probe.js <tree.js> <graph.json> <index.html> <app.js>
//
// 1. The pure builder, tree.js alone in a Node vm without a DOM, on a small
//    synthetic graph: the spanning tree from the core (BFS shape), the child
//    order, the ports, the filters with re-parenting, the counts, the "Not
//    connected" folder, the escaping of server strings and the ids. Then the
//    port badge on links labelled as the live /api/graph labels them: both
//    ends of the link to the parent, whichever side of it the parent is on,
//    markers, ports the link does not name, the tooltip with the kind of the
//    link and the traffic, filters, and hostile port names.
// 2. The same on the fixture graph, testdata/golden/graph.json: every device
//    once, tree edges are links, depths are hop counts from the root, every
//    filter keeps the visible devices in place, every badge shows the ends
//    of its link, and the outlines the golden pins (default filters and only
//    'vm').
// 3. The tab itself: app.js and tree.js, unmodified, with a stub DOM, jQuery
//    and a model of jsTree (jsTreeModel). Nothing is built while the tab is
//    hidden, the filter checkboxes and the device search reach the tree, a
//    click opens the info panel, a double-click focuses the graph. The search
//    typed key by key opens rows only while it is shown and keeps the device
//    found in sight (finding F1), and a click in the info panel's list of
//    connected devices selects the device in the tree, not in the hidden
//    graph (finding F2).
//
// It sends nothing anywhere: fetch answers only what the probe hands it, and
// timers run when the probe says so. Every failed check is printed to stderr
// and the exit code is 1.

const fs = require('fs');
const vm = require('vm');

const [treePath, graphPath, indexPath, appPath] = process.argv.slice(2);
const treeSrc = fs.readFileSync(treePath, 'utf8');
const appSrc = fs.readFileSync(appPath, 'utf8');
const indexHTML = fs.readFileSync(indexPath, 'utf8');
const fixture = JSON.parse(fs.readFileSync(graphPath, 'utf8'));

const passed = [];
const failed = [];
function check(name, ok, detail) {
  if (ok) passed.push(name);
  else failed.push(`${name}${detail === undefined ? '' : ': ' + (typeof detail === 'string' ? detail : JSON.stringify(detail))}`);
}

// The filter checkboxes as index.html declares them (as app_probe.js reads them).
const checkboxes = [];
for (const m of indexHTML.matchAll(/data-group="([a-z_]+)"([^>]*)>/g)) {
  checkboxes.push({ checked: /\bchecked\b/.test(m[2]), dataset: { group: m[1] } });
}
const filterable = checkboxes.map(c => c.dataset.group);
const defaultGroups = checkboxes.filter(c => c.checked).map(c => c.dataset.group);

// app.js object literals (group colours, the info panel's icons), evaluated alone.
function appLiteral(name) {
  const m = new RegExp(`const ${name} = (\\{[\\s\\S]*?\\});`).exec(appSrc);
  return m ? vm.runInNewContext(`(${m[1]})`) : null;
}
const groupColors = appLiteral('groupColors');
const groupIcons = appLiteral('groupIcons');

// ---------------------------------------------------------------------------
// Part 1: the pure builder on a synthetic graph

const pure = vm.createContext({});
vm.runInContext(treeSrc, pure, { filename: 'tree.js' });
const T = pure; // top-level function declarations of tree.js
const treeConst = (name) => vm.runInContext(name, pure);

// node and link build /api/graph records the way GetGraphData does.
function node(id, group, sysName, extra) {
  const hostname = extra && extra.hostname;
  const n = { id, label: sysName ? `${hostname || sysName}\n${id}` : id, group, type: group };
  if (sysName) n.sysName = sysName;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(id)) n.ip = id;
  return Object.assign(n, extra || {}, { unreachable: !!(extra && extra.unreachable) });
}
function link(source, target, label) {
  const l = { source, target, label, unreachable: false };
  if (label.includes('|')) {
    const [s, t] = label.split('|');
    if (s.trim()) l.sourceLabel = s.trim();
    if (t.trim()) l.targetLabel = t.trim();
  } else if (label && label !== 'vNIC') {
    l.sourceLabel = label;
  }
  return l;
}

const R1 = '00:00:5e:00:00:01', R2 = '00:00:5e:00:00:02';
const S1 = 'aa:00:00:00:00:01', S2 = 'aa:00:00:00:00:02', S3 = 'aa:00:00:00:00:03', S9 = 'aa:00:00:00:00:09';
const H = `hub-${S2}-p5`, Y = `hyp-${S3}-ge1_0_7`;
const E1 = '00:1b:21:00:00:11', E2 = '00:1b:21:00:00:12', E9 = '00:1b:21:00:00:19';
const VM1 = '00:50:56:00:00:21', VM2 = '00:50:56:00:00:22', VM9 = '00:50:56:00:00:99';
const AP = '9c:05:d6:00:00:41', X1 = 'aa:bb:cc:00:00:66', X2 = '<b id="x">chassis</b>';
const XSS = '<img src=x onerror=alert(1)>';

function synthetic() {
  return {
    nodes: [
      node(R1, 'router', 'gw-1\n10.0.0.1'),
      node(R2, 'router', 'gw-2\n10.0.0.2'),
      node(S1, 'switch', 'core-sw\n10.0.1.1'),
      node(S2, 'switch', 'dist-2\n10.0.1.2'),
      node(S3, 'switch', 'dist-10\n10.0.1.10', { unreachable: true }),
      node(S9, 'switch', 'lost-sw\n10.9.9.9'),
      node(H, 'hub', '[HUB] Unmanaged\n2 devices'),
      node(Y, 'hypervisor', '[HYPERVISOR] VMware ESXi\n2 VMs on ge1/0/7\nVMs: 10.0.3.21, 10.0.3.22'),
      node(E1, 'endpoint', '[ENDPOINT] Intel\n10.0.2.11'),
      node(E2, 'endpoint', '[ENDPOINT] Dell\n10.0.2.12'),
      node(E9, 'endpoint', '[ENDPOINT] HP\n10.9.9.10'),
      node(VM1, 'vm', '[VM] 🐧 Linux VMware\n10.0.3.21'),
      node(VM2, 'vm', '[VM] 🪟 Windows VMware\n10.0.3.22\n[DNS] win-22', { hostname: 'win-22' }),
      node(VM9, 'vm', '[VM] 💻 VMware VM VMware'),
      node(AP, 'access_point', '[LLDP-EP] Ubiquiti\nAP-1\n10.0.4.1'),
      node(X1, 'endpoint', `[LLDP-EP]\n${XSS}\n10.0.4.66`),
      node(X2, 'endpoint', '', { hostname: '"><svg onload=alert(2)>' }),
    ],
    links: [
      link(R1, S1, 'Te1/0/1|GE1/0/1'),
      link(S1, S2, 'GE1/0/10|GE1/0/48'),
      link(S1, S3, 'GE1/0/2 1G ↓5M ↑1M|GE1/0/48'),
      link(S2, S3, 'GE1/0/47|GE1/0/47'), // a loop: dist-10 stays below core-sw
      link(R2, S2, 'port1|GE1/0/46'), // dist-2's port is on the target side
      link(S2, H, 'GE1/0/5|Hub'),
      link(H, E1, ''),
      link(H, E2, ''),
      link(S3, Y, 'ge1/0/7'),
      link(Y, VM1, 'vNIC'),
      link(Y, VM2, 'vNIC'),
      link(S3, AP, 'GE1/0/12 [MAC-REF]|eth0'),
      link(S3, X1, 'GE1/0/9 <i>x</i>|eth0 "\'&'),
      link(S3, X2, 'GE1/0/11|'),
      link(S9, E9, 'GE1/0/1|'),
      link(S1, 'no-such-node', 'GE1/0/30|'),
    ],
  };
}

const entities = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'" };
const decodeEntities = (s) => s.replace(/&(?:amp|lt|gt|quot|#39);/g, e => entities[e]);

// badge reads the port badge of a row's text back: its HTML (with the
// marker and '?' spans inside), its text as the page shows it, and its
// tooltip.
function badge(text) {
  const start = /<span class="tv-port" title="([^"]*)">/.exec(text);
  if (!start) return { html: '', text: '', title: '' };
  const from = start.index + start[0].length;
  const tags = /<span\b[^>]*>|<\/span>/g;
  tags.lastIndex = from;
  let depth = 1, end = text.length;
  for (let m; (m = tags.exec(text));) {
    depth += m[0] === '</span>' ? -1 : 1;
    if (depth === 0) { end = m.index; break; }
  }
  let html = text.slice(from, end);
  // the device the link comes from opens the badge ('254.202 '); it is read
  // apart so the port checks below see only the two ports
  let fromName = '';
  const fm = /^<span class="tv-from">([^<]*)<\/span> /.exec(html);
  if (fm) { fromName = decodeEntities(fm[1]); html = html.slice(fm[0].length); }
  return { html, text: decodeEntities(html.replace(/<[^>]*>/g, '')), title: decodeEntities(start[1]), from: fromName };
}

// row reads a jsTree node back: the spans tree.js writes.
function row(json) {
  const t = json.text;
  const span = (cls) => {
    const m = new RegExp(`<span class="${cls}"(?: title="[^"]*")?>([^<]*)</span>`).exec(t);
    return m ? decodeEntities(m[1]) : '';
  };
  const b = badge(t);
  return {
    id: json.data && json.data.node, folder: !!(json.data && json.data.folder),
    name: span('tv-name'), address: span('tv-addr'), port: b.text, portHTML: b.html, portTitle: b.title, from: b.from,
    count: span('tv-count'), icon: span('tv-icon'),
    dot: (/<span class="tv-dot" style="background:([^"]*)"/.exec(t) || [])[1] || '',
    unreachable: t.includes('tv-unreachable'),
    title: decodeEntities((/^<span class="tv-row[^"]*" title="([^"]*)"/.exec(t) || [])[1] || ''),
  };
}

// fullBadge is a badge as the page shows it: the device the link comes
// from, then the two ports.
const fullBadge = (r) => (r.from ? r.from + ' ' : '') + r.port;

// kids is a row's device rows: its children without the '↔' rows of the
// links the tree leaves out.
const kids = (n) => (n.children || []).filter(c => !(c.data && c.data.xref !== undefined));

// outline is the tree as text, one row per line, indented by depth.
function outline(json) {
  const lines = [];
  const walk = (n, depth) => {
    if (n.data && n.data.xref !== undefined) {
      lines.push('  '.repeat(depth) + decodeEntities(n.text.replace(/<[^>]*>/g, '')).replace(/\s+/g, ' ').trim() + `  #>${n.data.xref}`);
      return;
    }
    const r = row(n);
    lines.push('  '.repeat(depth) + (r.port ? `[${r.from ? r.from + ' ' : ''}${r.port}] ` : '') + `${r.icon} ${r.name}` + (r.address ? ` · ${r.address}` : '') +
      (r.count ? ` (${r.count})` : '') + (r.unreachable ? ' !unreachable' : '') +
      (r.id !== undefined ? `  #${r.id}` : ''));
    (n.children || []).forEach(c => walk(c, depth + 1));
  };
  json.forEach(n => walk(n, 0));
  return lines;
}

// rows lists every jsTree node with its parent's device id and its depth.
function rows(json) {
  const out = [];
  const walk = (n, parent, depth, folder) => {
    if (n.data && (n.data.xref !== undefined || n.data.client !== undefined)) return; // '↔' and client rows: see xrefRows, clientRows
    const r = row(n);
    out.push({ json: n, row: r, parent, depth, folder });
    (n.children || []).forEach(c => walk(c, r.folder ? null : r.id, depth + 1, folder || r.folder));
  };
  json.forEach(n => walk(n, null, 0, false));
  return out;
}

// clientRows lists the client rows of the devices a controller manages:
// each with the device row it hangs under, its MAC, id, text and plain text.
function clientRows(json) {
  const out = [];
  const walk = (n, owner) => {
    if (n.data && n.data.client !== undefined) {
      out.push({ owner, mac: n.data.client, id: n.id, q: n.data.q, text: n.text, plain: decodeEntities(n.text.replace(/<[^>]*>/g, '')).replace(/\s+/g, ' ').trim() });
      return;
    }
    (n.children || []).forEach(c => walk(c, n.data && n.data.node));
  };
  json.forEach(n => walk(n, null));
  return out;
}

// xrefRows lists the '↔' rows: each with the device row it hangs under,
// the device it points to, and its text read back.
function xrefRows(json) {
  const out = [];
  const walk = (n, owner) => {
    if (n.data && n.data.xref !== undefined) {
      out.push({ owner, target: n.data.xref, id: n.id, text: n.text, plain: decodeEntities(n.text.replace(/<[^>]*>/g, '')) });
      return;
    }
    (n.children || []).forEach(c => walk(c, n.data && n.data.node));
  };
  json.forEach(n => walk(n, null));
  return out;
}

// strayMarkup is what is left of a text once tree.js's own tags are removed:
// any <, >, quote or bare & left would be markup from the server.
const ownTags = /<span class="tv-[a-z]+(?: tv-[a-z]+)*"(?: title="[^"<>]*")?>|<span class="tv-dot" style="background:#[0-9A-Fa-f]{3,8}"><\/span>|<\/span>/g;
function strayMarkup(text) {
  const rest = text.replace(ownTags, '');
  const bad = /[<>"']|&(?!amp;|lt;|gt;|quot;|#39;)/.exec(rest);
  return bad ? rest : null;
}

// safeTree: every text holds only tree.js's tags and escaped text, ids are
// tree.js's own, and no node has jsTree attributes (li_attr, a_attr, icon)
// that would take server strings.
function safeTree(json) {
  const problems = [];
  rows(json).forEach(({ json: n }) => {
    const stray = strayMarkup(n.text);
    if (stray !== null) problems.push(`markup in ${n.id}: ${stray}`);
    if (!/^tv[df]-[A-Za-z0-9_-]+$/.test(n.id)) problems.push(`id ${n.id}`);
    (n.children || []).filter(c => c.data && (c.data.xref !== undefined || c.data.client !== undefined)).forEach(c => {
      const strayX = strayMarkup(c.text);
      if (strayX !== null) problems.push(`markup in ${c.id}: ${strayX}`);
      if (!(c.data.xref !== undefined ? /^tvx-[A-Za-z0-9_-]+$/ : /^tvw-[A-Za-z0-9_-]+$/).test(c.id)) problems.push(`id ${c.id}`);
      for (const key of ['li_attr', 'a_attr', 'icon', 'type']) if (key in c) problems.push(`${key} on ${c.id}`);
    });
    for (const key of ['li_attr', 'a_attr', 'icon', 'type']) if (key in n) problems.push(`${key} on ${n.id}`);
  });
  return problems;
}

const shownBy = (groups) => T.treeGroupFilter(groups, filterable);

{
  const data = synthetic();
  const sp = T.treeSpanning(data);
  const all = T.treeProject(sp, null, { colors: groupColors });
  const def = T.treeProject(sp, shownBy(defaultGroups), { colors: groupColors });
  const out = outline(all);

  check('synthetic: the default checkboxes show every group', JSON.stringify(def) === JSON.stringify(all));
  check('synthetic: without a core the root is the first router in id order', sp.root === R1, sp.root);
  check('synthetic: one top-level device, then the Not connected folder',
    all.length === 2 && row(all[0]).id === R1 && all[1].id === treeConst('treeFolderId'), out);
  const rs = rows(all).filter(r => !r.row.folder);
  const ids = rs.map(r => r.row.id);
  check('synthetic: every device appears once', ids.length === data.nodes.length && new Set(ids).size === ids.length, ids);
  const at = (id) => rs.find(r => r.row.id === id);
  check('synthetic: BFS: a loop link does not move a device deeper (dist-10 hangs from core-sw)', at(S3).parent === S1 && at(S2).parent === S1);
  // The loop link the tree leaves out is a '↔' row under both of its ends,
  // out of that device's port, with the device at the other end.
  const loopX = xrefRows(all);
  const s2x = loopX.find(x => x.owner === S2 && x.target === S3), s3x = loopX.find(x => x.owner === S3 && x.target === S2);
  check('synthetic: a link the tree leaves out is a ↔ row under both ends, its own port first',
    loopX.length === 2 && !!s2x && !!s3x &&
    s2x.plain.replace(/\s+/g, ' ').trim() === '↔ 1.2 GE1/0/47 → GE1/0/47 🔀 dist-10 10.0.1.10' &&
    s3x.plain.replace(/\s+/g, ' ').trim() === '↔ 1.10 GE1/0/47 → GE1/0/47 🔀 dist-2 10.0.1.2' &&
    s2x.id === T.treeXrefId(S2, S3) && /^tvx-/.test(s2x.id), loopX);
  const noDist10 = T.treeProject(sp, (node) => String(node.id) !== S3, {});
  check('synthetic: a ↔ row to a device the filter hides is left out', xrefRows(noDist10).length === 0, xrefRows(noDist10));
  const hostileX = T.treeProject(T.treeSpanning({ nodes: [
    { id: 'a', label: '<b>a</b>\n10.0.0.1', group: 'switch' }, { id: 'b', label: '"><img src=x onerror=alert(5)>\n10.0.0.2', group: 'switch' },
    { id: 'c', label: 'c\n10.0.0.3', group: 'switch' }], links: [
    { source: 'a', target: 'b', label: 'p1|q1', sourceLabel: 'p1', targetLabel: 'q1' },
    { source: 'a', target: 'c', label: 'p2|r1', sourceLabel: 'p2', targetLabel: 'r1' },
    { source: 'b', target: 'c', label: '<i>q2</i>|"r2&', sourceLabel: '<i>q2</i>', targetLabel: '"r2&' }] }), null, {});
  check('synthetic: a ↔ row holds no markup from the server', xrefRows(hostileX).length === 2 && safeTree(hostileX).length === 0 &&
    !xrefRows(hostileX).some(x => x.text.includes('<img') || x.text.includes('<i>')), [safeTree(hostileX), xrefRows(hostileX).map(x => x.text)]);
  // A device its controller manages (node.managed, a UniFi access point):
  // named by the controller, its state when not online, its clients as rows
  // below it that are no devices (no count) but are found by the search,
  // and no markup from the server anywhere
  const managedNode = { id: '70:a7:41:00:00:01', label: '[LLDP-EP] Ubiquiti\nA1qavat118\n10.0.0.12', sysName: '[LLDP-EP] Ubiquiti\nA1qavat118\n10.0.0.12', group: 'access_point',
    managed: { source: 'UniFi Network controller', controller: '10.0.0.2', name: 'A 1 qavat <118>', model: 'U6 LR', state: 'OFFLINE', firmware: '6.7.57',
      clients: [{ mac: 'de:ad:00:00:00:02', name: '<img src=x onerror=alert(7)>', ip: '10.0.1.7', kind: 'wireless' }, { mac: 'de:ad:00:00:00:01', kind: 'wired' }] } };
  const managedTree = T.treeProject(T.treeSpanning({ nodes: [{ id: 'aa:00:00:00:01:01', label: 'sw\n10.0.0.1', group: 'switch' }, managedNode],
    links: [{ source: 'aa:00:00:00:01:01', target: managedNode.id, label: 'GE1/0/5|eth0', sourceLabel: 'GE1/0/5', targetLabel: 'eth0' }] }), null, {});
  const apRow = rows(managedTree).find(r => r.row.id === managedNode.id);
  const cl = clientRows(managedTree);
  check('synthetic: a managed device is named by its controller, with its state and its clients below it',
    !!apRow && apRow.row.name === 'A 1 qavat <118>' && apRow.json.text.includes('<span class="tv-state">OFFLINE</span>') &&
    apRow.json.text.includes('📶 2') && !apRow.json.text.includes('tv-count') &&
    cl.length === 2 && cl.every(c => c.owner === managedNode.id && /^tvw-/.test(c.id)) &&
    cl[0].plain === '📶 <img src=x onerror=alert(7)> 10.0.1.7 de:ad:00:00:00:02' && cl[1].plain === '🔌 de:ad:00:00:00:01' &&
    cl[0].q.includes('10.0.1.7') && safeTree(managedTree).length === 0 && !cl[0].text.includes('<img') &&
    T.treeRowCount(managedTree[0]) === 2, [apRow && apRow.row, cl, safeTree(managedTree)]);
  check('synthetic: a managed device\'s tooltip has what its controller says',
    T.treeSpanning({ nodes: [managedNode], links: [] }).infos.get(managedNode.id).title
      .includes('UniFi Network controller 10.0.0.2 · U6 LR · OFFLINE · firmware 6.7.57\n2 clients connected'));
  check('synthetic: BFS: a router behind a switch hangs below it', at(R2).parent === S2 && at(R2).depth === 3);
  check('synthetic: child order: routers/switches, hubs/hypervisors, the rest, natural by name',
    JSON.stringify(kids(at(S1).json).map(c => row(c).name)) === JSON.stringify(['dist-2', 'dist-10']) &&
    JSON.stringify(kids(at(S2).json).map(c => row(c).id)) === JSON.stringify([R2, H]) &&
    JSON.stringify(kids(at(S3).json).map(c => row(c).id)) === JSON.stringify([Y, X2, X1, AP]),
    [kids(at(S2).json).map(c => row(c).id), kids(at(S3).json).map(c => row(c).id)]);
  check('synthetic: ports: both ends of the link to the parent, the parent\'s first on either side of the link, speed and traffic dropped, markers kept',
    at(S1).row.port === 'Te1/0/1 → GE1/0/1' && at(S3).row.port === 'GE1/0/2 → GE1/0/48' && at(R2).row.port === 'GE1/0/46 → port1' &&
    at(H).row.port === 'GE1/0/5 → ?' && at(Y).row.port === 'ge1/0/7 → ?' && at(AP).row.port === 'GE1/0/12 [MAC-REF] → eth0' &&
    at(X2).row.port === 'GE1/0/11 → ?', rs.map(r => [r.row.id, r.row.port]));
  check('synthetic: no port on hub members and VMs (their port is the parent row\'s)',
    [E1, E2, VM1, VM2].every(id => at(id).row.port === ''));
  check('synthetic: names: sysName, DNS name, LLDP name, vendor or OS of the tag line, hub and hypervisor by tag',
    at(S2).row.name === 'dist-2' && at(VM2).row.name === 'win-22' && at(AP).row.name === 'AP-1' &&
    at(E1).row.name === 'Intel' && at(VM1).row.name === '🐧 Linux VMware' && at(H).row.name === 'Unmanaged' &&
    at(Y).row.name === 'VMware ESXi' && at(X1).row.name === XSS,
    rs.map(r => [r.row.id, r.row.name]));
  check('synthetic: address: the IP, else the MAC, none for synthetic ids',
    at(S2).row.address === '10.0.1.2' && at(VM9).row.address === VM9 && at(H).row.address === '' && at(Y).row.address === '');
  check('synthetic: counts: the shown devices below each row',
    at(R1).row.count === '13' && at(S1).row.count === '12' && at(S2).row.count === '4' && at(S3).row.count === '6' &&
    at(H).row.count === '2' && at(E1).row.count === '' && row(all[1]).count === '3',
    rs.map(r => [r.row.id, r.row.count]));
  check('synthetic: the folder holds what the core does not reach, each part as its own tree',
    JSON.stringify(kids(all[1]).map(c => row(c).id)) === JSON.stringify([S9, VM9]) && at(E9).parent === S9,
    outline([all[1]]));
  check('synthetic: icon and colour per group as in the graph, red when unreachable',
    rs.every(r => r.row.icon === groupIcons[data.nodes.find(n => n.id === r.row.id).group]) &&
    at(S2).row.dot === groupColors.switch && at(VM1).row.dot === groupColors.vm && at(S3).row.dot === '#ff4444' && at(S3).row.unreachable,
    rs.map(r => [r.row.id, r.row.icon, r.row.dot]));
  check('synthetic: the tooltip names the link and both ports',
    at(S3).row.title.split('\n').includes('link: core-sw (10.0.1.1) GE1/0/2 → GE1/0/48'), at(S3).row.title);

  // Escaping (finding F86): names, ids, ports and DNS names are text.
  const problems = safeTree(all);
  const html = rs.map(r => r.json.text).join('\n');
  check('synthetic: server strings never become markup', problems.length === 0 && !html.includes('<img') &&
    !html.includes('<svg') && !html.includes('<b ') && !html.includes('<i>'), problems);
  check('synthetic: the escaped strings are in the text', at(X1).json.text.includes('&lt;img src=x onerror=alert(1)&gt;') &&
    at(X2).json.text.includes('&quot;&gt;&lt;svg onload=alert(2)&gt;') && at(X1).json.text.includes('GE1/0/9 &lt;i&gt;x&lt;/i&gt; → eth0 &quot;&#39;&amp;') &&
    at(X2).json.text.includes('endpoint · &lt;b id=&quot;x&quot;&gt;chassis&lt;/b&gt;'));
  // The search text is data jsTree never puts into the page.
  check('synthetic: the search text keeps the raw strings', at(X1).json.data.q.includes(XSS) && at(X2).json.data.q.includes(X2.toLowerCase()));
  const safeIds = [X2, 'a:b', 'a_3a_b', 'tvf-not-connected', 'Ünï'].map(T.treeSafeId);
  check('synthetic: jsTree ids are safe, stable and distinct', new Set(safeIds).size === safeIds.length &&
    safeIds.every(s => /^tvd-[A-Za-z0-9_]+$/.test(s)) && T.treeSafeId(X2) === T.treeSafeId(String(X2)), safeIds);

  // Filters: hidden devices' shown descendants move up to the nearest shown ancestor.
  const vmOnly = T.treeProject(sp, shownBy(['vm']), { colors: groupColors });
  const vmRows = rows(vmOnly).filter(r => !r.row.folder);
  check('synthetic: only VM: the VMs at the top, their switch port named', vmOnly.length === 3 &&
    vmRows.length === 3 && vmRows.every(r => data.nodes.find(n => n.id === r.row.id).group === 'vm') &&
    fullBadge(row(vmOnly[0])) === 'dist-10 (10.0.1.10) ge1/0/7 → ?' && fullBadge(row(vmOnly[1])) === 'dist-10 (10.0.1.10) ge1/0/7 → ?' &&
    row(vmOnly[2]).folder && row(vmOnly[2]).count === '1', outline(vmOnly));
  const swVm = T.treeProject(sp, shownBy(['switch', 'vm']), { colors: groupColors });
  const sv = rows(swVm).filter(r => !r.row.folder);
  const svAt = (id) => sv.find(r => r.row.id === id);
  check('synthetic: switch and VM: VMs move up to their switch, with its port', svAt(VM1).parent === S3 && svAt(VM2).parent === S3 &&
    svAt(VM1).row.port === 'ge1/0/7 → ?' && svAt(S1).parent === null && fullBadge(svAt(S1).row) === 'gw-1 (10.0.0.1) Te1/0/1 → GE1/0/1' &&
    svAt(S1).row.count === '4' && svAt(S3).row.count === '2' && svAt(S2).row.count === '', outline(swVm));
  const apFree = T.treeProject(sp, T.treeGroupFilter(['vm'], filterable.filter(g => g !== 'access_point')), {});
  check('synthetic: a group without a checkbox is always shown (as app.js uiGroupShown)',
    rows(apFree).some(r => r.row.id === AP) && !rows(apFree).some(r => r.row.id === S3));
  check('synthetic: a filter that hides every device leaves an empty tree', T.treeProject(sp, [], {}).length === 0);
  check('synthetic: groups as an array or a set filter alike',
    JSON.stringify(T.treeProject(sp, ['vm'], {})) === JSON.stringify(T.treeProject(sp, new Set(['vm']), {})));

  // The core the server sends, and the fallbacks.
  const withCore = T.treeSpanning(Object.assign(synthetic(), { core: S2 }));
  const coreTree = T.treeProject(withCore, null, {});
  const cr = rows(coreTree);
  const crAt = (id) => cr.find(r => r.row.id === id);
  check('synthetic: data.core is the root; BFS from it takes the shortest path (dist-10 via the loop)',
    withCore.root === S2 && withCore.coreFromServer && crAt(S3).parent === S2 && crAt(R1).parent === S1 &&
    crAt(S3).row.port === 'GE1/0/47 → GE1/0/47', outline(coreTree));
  check('synthetic: a core that is not a node is ignored', T.treeSpanning(Object.assign(synthetic(), { core: 'gone' })).root === R1);
  const noRouters = synthetic();
  noRouters.nodes = noRouters.nodes.filter(n => n.group !== 'router');
  check('synthetic: without routers the root is the switch with the most links', T.treeSpanning(noRouters).root === S3);
  const onlyEndpoints = { nodes: [node(E1, 'endpoint', ''), node(E2, 'endpoint', ''), node(E9, 'endpoint', '')], links: [link(E2, E9, '')] };
  check('synthetic: without switches the root is the node with the most links', T.treeSpanning(onlyEndpoints).root === E2);
  check('synthetic: an empty graph is an empty tree', T.buildTopologyTree({ nodes: [], links: [] }, null, {}).length === 0 &&
    T.buildTopologyTree(null, null, {}).length === 0);

  // Link ends resolved by d3, and the input order, change nothing.
  const resolved = synthetic();
  resolved.links.forEach(l => { l.source = { id: l.source, x: 1, y: 2 }; });
  check('synthetic: link ends that d3 resolved to node objects give the same tree',
    JSON.stringify(T.buildTopologyTree(resolved, null, { colors: groupColors })) === JSON.stringify(all));
  const shuffled = synthetic();
  shuffled.nodes.reverse();
  shuffled.links.reverse();
  check('synthetic: the tree does not depend on the order of nodes and links',
    JSON.stringify(T.buildTopologyTree(shuffled, null, { colors: groupColors })) === JSON.stringify(all));
  check('synthetic: natural, case-insensitive order', T.treeCompareText('GE1/0/2', 'GE1/0/10') < 0 &&
    T.treeCompareText('sw-9', 'sw-10') < 0 && T.treeCompareText('abc', 'ABD') < 0 && T.treeCompareText('a', 'a') === 0);
  check('synthetic: tree.js icons are the info panel\'s', JSON.stringify(treeConst('treeGroupIcons')) === JSON.stringify(groupIcons));
  const odd = T.buildTopologyTree({ nodes: [node('aa:00:00:00:00:71', '__proto__', 'x'), node('aa:00:00:00:00:72', 'constructor', 'y')], links: [] }, null, { colors: groupColors });
  check('synthetic: a group the tables do not name gets the unknown icon and the grey dot',
    rows(odd).filter(r => !r.row.folder).every(r => r.row.icon === groupIcons.unknown && r.row.dot === '#9E9E9E'), rows(odd).map(r => [r.row.icon, r.row.dot]));

  var syntheticRecord = { default: out, only_vm: outline(vmOnly), switch_and_vm: outline(swVm), core_dist_2: outline(coreTree) };
}

// The port badge on links as /api/graph has them (labels of the live graph
// of 2026-10-22): 172.20.230.253 wrote its link to 172.20.254.202, so the
// parent is the target and the traffic is on the child's port; a MAC-REF
// link whose traffic refresh dropped its '|'; a MAC-REF link with the far
// switch's port from its FDB, after a traffic refresh; an LLDP link from
// the child that names no port of the parent's; an FDB port with its VLAN;
// a hub; a pair linked from both sides; hostile port names; a switch with a
// device below it and a hostile name.
const PA = '4c:ae:a3:8d:ee:c9', PB = '88:22:5b:88:e2:40', PC = 'aa:00:00:00:01:03', PD = 'aa:00:00:00:01:04';
const PE = '00:1b:21:00:01:05', PF = 'aa:00:00:00:01:06', PG = `hub-${PA}-p40`;
const PM1 = '00:1b:21:00:01:41', PM2 = '00:1b:21:00:01:42', PX = 'aa:bb:cc:00:01:66', PX3 = 'aa:bb:cc:00:01:67';
const PK = 'aa:00:00:00:01:0a', PH = 'aa:00:00:00:01:08', PHE = '00:1b:21:00:01:09';
const XSW = '<img src=x onerror=alert(4)>';
function portGraph() {
  return {
    core: PA,
    nodes: [
      node(PA, 'switch', 'HPE\n172.20.254.202'),
      node(PB, 'switch', '172.20.230.253'),
      node(PC, 'switch', 'sw-c\n10.1.0.3'),
      node(PD, 'switch', 'sw-d\n10.1.0.4'),
      node(PE, 'endpoint', '[ENDPOINT] Intel\n10.1.0.5'),
      node(PF, 'switch', 'sw-f\n10.1.0.6'),
      node(PG, 'hub', '[HUB] Unmanaged\n2 devices'),
      node(PM1, 'endpoint', '[ENDPOINT] Dell\n10.1.0.41'),
      node(PM2, 'endpoint', '[ENDPOINT] HP\n10.1.0.42'),
      node(PX, 'endpoint', '[LLDP-EP] evil\n10.1.0.66'),
      node(PX3, 'endpoint', '[LLDP-EP] odd\n10.1.0.67'),
      node(PK, 'switch', 'sw-k\n10.1.0.10'),
      node(PH, 'switch', `${XSW}\n10.1.0.8`),
      node(PHE, 'endpoint', '[ENDPOINT] Intel\n10.1.0.9'),
    ],
    links: [
      link(PB, PA, '1/1/28 ↓40M ↑399M|TGE1/0/51'),
      link(PA, PC, 'TGE1/0/52 [MAC-REF] ↓635M ↑153M'),
      link(PD, PA, 'TGE1/0/49 [T] 1G|'),
      link(PA, PE, 'GE1/0/22 [V1500]|'),
      link(PA, PF, 'GE1/0/45 [T] 1G|'),
      link(PF, PA, 'Eth1/0/49 1G ↓2M ↑3M|GE1/0/45'),
      link(PA, PG, 'GE1/0/40|Hub'),
      link(PG, PM1, ''),
      link(PG, PM2, ''),
      link(PA, PX, '<b>GE1/0/31</b> [T] 1G ↓1M ↑2M|"><img src=x onerror=alert(3)>'),
      link(PA, PX3, 'GE1/0/32 [V1"2] 1G|eth0 [x]&amp;'),
      link(PA, PK, 'GE1/0/34 [MAC-REF] ↓1M ↑2M|Eth1/0/24'),
      link(PA, PH, 'GE1/0/33 [T] 1G|GE1/0/48'),
      link(PH, PHE, 'GE1/0/3 [V10]|'),
    ],
  };
}

{
  const data = portGraph();
  const sp = T.treeSpanning(data);
  const tree = T.treeProject(sp, null, { colors: groupColors });
  const rs = rows(tree);
  const at = (id) => rs.find(r => r.row.id === id);
  const unknown = '<span class="tv-unknown">?</span>', mark = (m) => `<span class="tv-mark">${m}</span>`;

  check('ports: the parent is the target of the link: its port first, then the child\'s, the source\'s, without its traffic',
    at(PB).parent === PA && at(PB).row.port === 'TGE1/0/51 → 1/1/28' && at(PB).row.portHTML === 'TGE1/0/51 → 1/1/28', [at(PB).parent, at(PB).row.portHTML]);
  check('ports: the parent is the source of the link: its port first',
    at(PE).row.port === 'GE1/0/22 [V1500] → ?' && at(PC).row.port === 'TGE1/0/52 [MAC-REF] → ?' && at(PG).row.port === 'GE1/0/40 → ?',
    rs.map(r => [r.row.id, r.row.port]));
  check('ports: a port the link does not name is a muted ?, on the child\'s end or on the parent\'s',
    at(PC).row.portHTML.endsWith(`→ ${unknown}`) && at(PG).row.portHTML === `GE1/0/40 → ${unknown}` &&
    at(PD).row.port === '? → TGE1/0/49 [T]' && at(PD).row.portHTML.startsWith(`${unknown} → `), [at(PC).row.portHTML, at(PD).row.portHTML]);
  check('ports: markers are small tags after the port they belong to, on the side that wrote them',
    at(PC).row.portHTML === `TGE1/0/52 ${mark('[MAC-REF]')} → ${unknown}` && at(PE).row.portHTML === `GE1/0/22 ${mark('[V1500]')} → ${unknown}` &&
    at(PD).row.portHTML === `${unknown} → TGE1/0/49 ${mark('[T]')}` && at(PF).row.portHTML === `GE1/0/45 ${mark('[T]')} → Eth1/0/49`,
    rs.map(r => r.row.portHTML));
  check('ports: the badge tooltip: both devices with their ports, the kind of the link, the speed and traffic of a port',
    at(PB).row.portTitle === 'HPE (172.20.254.202) TGE1/0/51 → 172.20.230.253 1/1/28\nLLDP link\n1/1/28: ↓40M ↑399M' &&
    at(PC).row.portTitle === 'HPE (172.20.254.202) TGE1/0/52 → sw-c (10.1.0.3) ?\nMAC-REF link\nTGE1/0/52: ↓635M ↑153M\n? = port unknown' &&
    at(PD).row.portTitle === 'HPE (172.20.254.202) ? → sw-d (10.1.0.4) TGE1/0/49\nLLDP link\nTGE1/0/49: 1G\n? = port unknown' &&
    at(PG).row.portTitle === 'HPE (172.20.254.202) GE1/0/40 → Unmanaged ?\nFDB link\n? = port unknown',
    rs.map(r => r.row.portTitle));
  check('ports: a port alone does not tell how the link was found (FDB, or LLDP without a port name or speed)',
    at(PE).row.portTitle === 'HPE (172.20.254.202) GE1/0/22 → Intel (10.1.0.5) ?\n? = port unknown', at(PE).row.portTitle);
  check('ports: hub members have no badge: they hang on the hub row\'s link', at(PM1).row.port === '' && at(PM2).row.port === '' &&
    at(PM1).parent === PG);
  check('ports: the row tooltip names the link with both ports', at(PD).row.title.split('\n').includes('link: HPE (172.20.254.202) ? → TGE1/0/49') &&
    at(PB).row.title.split('\n').includes('link: HPE (172.20.254.202) TGE1/0/51 → 1/1/28'), at(PD).row.title);

  // A pair linked from both sides: each port as its own switch's label has it.
  const reversed = portGraph();
  reversed.nodes.reverse();
  reversed.links.reverse();
  check('ports: a pair linked from both sides takes each port, its markers and its traffic from its own switch\'s label, in any order of the links',
    at(PF).row.port === 'GE1/0/45 [T] → Eth1/0/49' &&
    at(PF).row.portTitle === 'HPE (172.20.254.202) GE1/0/45 → sw-f (10.1.0.6) Eth1/0/49\nLLDP link\nGE1/0/45: 1G\nEth1/0/49: 1G ↓2M ↑3M' &&
    JSON.stringify(T.buildTopologyTree(reversed, null, { colors: groupColors })) === JSON.stringify(tree), at(PF).row);

  // Filters: a hidden device in between, a hidden parent.
  const noHub = rows(T.treeProject(sp, shownBy(filterable.filter(g => g !== 'hub')), {}));
  const m1 = noHub.find(r => r.row.id === PM1);
  check('ports: the hub filtered out: its members hang on the switch port, through the hub, their own port unknown',
    m1.parent === PA && m1.row.port === 'GE1/0/40 → ?' &&
    m1.row.portTitle === 'HPE (172.20.254.202) GE1/0/40 → Dell (10.1.0.41) ?\nFDB link\nvia Unmanaged (filtered out)\n? = port unknown', m1.row);
  const noSwitch = rows(T.treeProject(sp, shownBy(filterable.filter(g => g !== 'switch')), {}));
  const e = noSwitch.find(r => r.row.id === PE), hub = noSwitch.find(r => r.row.id === PG);
  check('ports: the parent filtered out: the badge names it, and the row tooltip says where the device is plugged in',
    e.parent === null && fullBadge(e.row) === 'HPE (172.20.254.202) GE1/0/22 [V1500] → ?' && e.row.title.endsWith('\nplugged into HPE (172.20.254.202) GE1/0/22') &&
    fullBadge(hub.row) === 'HPE (172.20.254.202) GE1/0/40 → ?' && noSwitch.find(r => r.row.id === PM1).row.port === '', [e.row, hub.row.port]);
  const onlyEndpoints = rows(T.treeProject(sp, shownBy(['endpoint']), {}));
  const lone = onlyEndpoints.find(r => r.row.id === PM1);
  check('ports: switch and hub filtered out: a hub member names the switch port it hangs on, through the hub',
    lone.parent === null && fullBadge(lone.row) === 'HPE (172.20.254.202) GE1/0/40 → ?' &&
    lone.row.portTitle === 'HPE (172.20.254.202) GE1/0/40 → Dell (10.1.0.41) ?\nFDB link\nvia Unmanaged (filtered out)\n? = port unknown', lone.row);

  // Escaping (finding F86): hostile port names, near and far, are text.
  const html = rs.map(r => r.json.text).join('\n');
  check('ports: hostile port names are text in the badge and its tooltip', safeTree(tree).length === 0 &&
    !html.includes('<img') && !html.includes('<b>') && at(PX).row.port === '<b>GE1/0/31</b> [T] → "><img src=x onerror=alert(3)>' &&
    at(PX).row.portHTML === `&lt;b&gt;GE1/0/31&lt;/b&gt; ${mark('[T]')} → &quot;&gt;&lt;img src=x onerror=alert(3)&gt;` &&
    at(PX).row.portTitle === 'HPE (172.20.254.202) <b>GE1/0/31</b> → evil (10.1.0.66) "><img src=x onerror=alert(3)>\nLLDP link\n<b>GE1/0/31</b>: 1G ↓1M ↑2M',
    [safeTree(tree), at(PX).row]);
  check('ports: a bracket that is no marker stays in the port name, and an entity in a port name is shown as it is',
    at(PX3).row.port === 'GE1/0/32 [V1"2] → eth0 [x]&amp;' && at(PX3).row.portHTML === 'GE1/0/32 [V1&quot;2] → eth0 [x]&amp;amp;', at(PX3).row);
  check('ports: a MAC-REF link names the far switch\'s port (from its FDB) after the "|", as an LLDP link does',
    at(PK).row.port === 'GE1/0/34 [MAC-REF] → Eth1/0/24' && at(PK).row.portHTML === `GE1/0/34 ${mark('[MAC-REF]')} → Eth1/0/24` &&
    at(PK).row.portTitle === 'HPE (172.20.254.202) GE1/0/34 → sw-k (10.1.0.10) Eth1/0/24\nMAC-REF link\nGE1/0/34: ↓1M ↑2M', at(PK).row);

  // A switch with a device below it and a hostile name, filtered out: its
  // name goes into the badge of the device below it, in the badge's text
  // (treePortHTML's named switch) as well as in its tooltip, as text.
  const swOut = T.treeProject(sp, shownBy(filterable.filter(g => g !== 'switch')), {});
  const below = rows(swOut).find(r => r.row.id === PHE);
  check('ports: a filtered-out switch with a hostile name is text in the badge of the device below it',
    safeTree(swOut).length === 0 && !rows(swOut).some(r => r.json.text.includes('<img')) && below.parent === null &&
    fullBadge(below.row) === `${XSW} (10.1.0.8) GE1/0/3 [V10] → ?` && below.row.portHTML.startsWith('GE1/0/3 ') &&
    below.json.text.includes('<span class="tv-from">&lt;img src=x onerror=alert(4)&gt; (10.1.0.8)</span>') &&
    below.row.portTitle === `${XSW} (10.1.0.8) GE1/0/3 → Intel (10.1.0.9) ?\n? = port unknown` &&
    below.row.title.endsWith(`\nplugged into ${XSW} (10.1.0.8) GE1/0/3`), [safeTree(swOut), below && below.row]);
  check('ports: the device search matches both ports of the link to the parent, with their markers',
    T.treeSearchMatch('1/1/28', at(PB).json) && T.treeSearchMatch('TGE1/0/51', at(PB).json) && T.treeSearchMatch('[v1500]', at(PE).json) &&
    T.treeSearchMatch('mac-ref', at(PC).json) && !T.treeSearchMatch('↓40m', at(PB).json), [at(PB).json.data.q]);
}

// ---------------------------------------------------------------------------
// Part 2: the fixture graph

// hops: breadth-first hop counts from root over the links, both directions.
function hops(data, root) {
  const adj = new Map();
  data.links.forEach(l => {
    if (l.source === l.target) return;
    if (!adj.has(l.source)) adj.set(l.source, []);
    if (!adj.has(l.target)) adj.set(l.target, []);
    adj.get(l.source).push(l.target);
    adj.get(l.target).push(l.source);
  });
  const depth = new Map([[root, 0]]);
  const queue = [root];
  for (let i = 0; i < queue.length; i++) {
    for (const v of adj.get(queue[i]) || []) {
      if (!depth.has(v)) {
        depth.set(v, depth.get(queue[i]) + 1);
        queue.push(v);
      }
    }
  }
  return depth;
}

{
  const data = { nodes: fixture.nodes, links: fixture.links };
  const sp = T.treeSpanning(data);
  const json = T.treeProject(sp, shownBy(defaultGroups), { colors: groupColors });
  const rs = rows(json);
  const devices = rs.filter(r => !r.row.folder);
  const ids = devices.map(r => r.row.id);
  const byId = new Map(data.nodes.map(n => [n.id, n]));
  const linked = new Set(data.links.map(l => `${l.source}|${l.target}`));
  const degree = new Map();
  data.links.forEach(l => { degree.set(l.source, (degree.get(l.source) || 0) + 1); degree.set(l.target, (degree.get(l.target) || 0) + 1); });
  const busiest = data.nodes.filter(n => n.group === 'switch')
    .sort((a, b) => (degree.get(b.id) || 0) - (degree.get(a.id) || 0) || (a.id < b.id ? -1 : 1))[0].id;

  check('fixture: no router and no core: the root is the switch with the most links', sp.root === busiest, [sp.root, busiest]);
  check('fixture: every device appears once', ids.length === data.nodes.length && new Set(ids).size === ids.length, [ids.length, data.nodes.length]);
  check('fixture: every tree edge is a link of the graph',
    devices.every(r => r.parent === null || linked.has(`${r.parent}|${r.row.id}`) || linked.has(`${r.row.id}|${r.parent}`)));
  const depth = hops(data, sp.root);
  const main = devices.filter(r => !r.folder);
  check('fixture: a device\'s depth is its hop count from the root', main.length === depth.size && main.every(r => depth.get(r.row.id) === r.depth),
    main.filter(r => depth.get(r.row.id) !== r.depth).slice(0, 3).map(r => [r.row.id, r.depth, depth.get(r.row.id)]));
  check('fixture: the folder holds exactly the devices the root does not reach',
    devices.filter(r => r.folder).length === data.nodes.length - depth.size && devices.filter(r => r.folder).every(r => !depth.has(r.row.id)));
  const countOk = rs.every(r => {
    let below = 0;
    const walk = (n) => kids(n).forEach(c => { below++; walk(c); });
    walk(r.json);
    return r.row.count === (below ? String(below) : '');
  });
  check('fixture: every count is the number of devices below the row', countOk);
  // inOrder: every list of siblings (the top level, the folder, each row's
  // children) is in child order.
  const inOrder = (tree) => {
    const sorted = (list) => {
      const infos = list.filter(n => n.id !== treeConst('treeFolderId')).map(n => sp.infos.get(row(n).id));
      return infos.every((k, i) => i === 0 || T.treeCompareInfo(infos[i - 1], k) < 0);
    };
    return sorted(tree) && rows(tree).every(r => sorted(kids(r.json)));
  };
  check('fixture: siblings are in child order', inOrder(json));
  // every '↔' row is a link the tree leaves out, shown under both ends
  const fx = xrefRows(json);
  const fxKey = new Set(fx.map(x => `${x.owner}>${x.target}`));
  const fxBad = fx.filter(x => sp.parent.get(x.owner) === x.target || sp.parent.get(x.target) === x.owner || !fxKey.has(`${x.target}>${x.owner}`));
  let extraTotal = 0;
  sp.extra.forEach(list => { extraTotal += list.length; });
  check('fixture: each link the tree leaves out is a ↔ row under both of its ends', fx.length === extraTotal && fx.length > 0 && fxBad.length === 0,
    [fx.length, extraTotal, fxBad.slice(0, 3)]);
  const problems = safeTree(json);
  check('fixture: no row holds markup from the server', problems.length === 0, problems.slice(0, 3));

  // The badge of every row: both ends of the link to its parent, the
  // parent's port first, read here from the link as /api/graph has it (the
  // fixture links each pair once).
  const linkOf = new Map(data.links.map(l => [`${l.source}|${l.target}`, l]));
  const sourcePort = (s) => (s ? String(s).replace(/\s+(?:\d+[MGmg]\b|[↓↑]).*$/, '') : '');
  const targetPort = (t) => (!t || t === 'Hub' ? '' : String(t));
  const wrong = [];
  let parentIsSource = 0, parentIsTarget = 0;
  devices.filter(r => r.parent !== null).forEach(r => {
    const fromParent = linkOf.get(`${r.parent}|${r.row.id}`), l = fromParent || linkOf.get(`${r.row.id}|${r.parent}`);
    const up = fromParent ? sourcePort(l.sourceLabel) : targetPort(l.targetLabel);
    const down = fromParent ? targetPort(l.targetLabel) : sourcePort(l.sourceLabel);
    const want = up || down ? `${up || '?'} → ${down || '?'}` : '';
    if (r.row.port !== want) wrong.push([r.parent, r.row.id, l.label, r.row.port, want]);
    if (want) {
      if (fromParent) parentIsSource++;
      else parentIsTarget++;
    }
  });
  check('fixture: every badge shows both ends of the link to the parent, the parent\'s port first on either side of the link',
    wrong.length === 0 && parentIsSource > 0 && parentIsTarget > 0, [wrong.slice(0, 3), parentIsSource, parentIsTarget]);
  const owner = devices.find(r => r.row.id === '88:22:5b:88:e2:40');
  check('fixture: the owner\'s link: 172.20.230.253 hangs from 172.20.254.202 port TGE1/0/51, on its own port Port28',
    owner.parent === '4c:ae:a3:8d:ee:c9' && owner.row.port === 'TGE1/0/51 → Port28' && owner.row.from === '254.202' &&
    fullBadge(owner.row) === '254.202 TGE1/0/51 → Port28' &&
    owner.row.portTitle === 'HPE (172.20.254.202) TGE1/0/51 → 172.20.230.253 Port28\nLLDP link', owner.row);
  // every badge opens with the device the link comes from: the parent's
  // short name ('254.202') when the parent is shown, so no row reads as
  // hanging on the row above it
  const shortOf = (id) => { const i = sp.infos.get(id); return i && i.short; };
  const badFrom = devices.filter(r => r.row.port && r.parent && r.row.from !== shortOf(r.parent));
  check('fixture: every badge names the device the link comes from, the parent shown above it',
    devices.some(r => r.row.port) && badFrom.length === 0, badFrom.slice(0, 5).map(r => [r.row.id, r.parent, r.row.from]));

  // Every filter of one group, and of all groups but one: the shown devices,
  // each once, below their nearest shown ancestor of the full tree, and the
  // rows that moved up sorted in with their new siblings.
  const groups = [...new Set(data.nodes.map(n => n.group))].sort();
  const fullParent = new Map(devices.map(r => [r.row.id, r.parent]));
  const filterOk = [];
  for (const g of groups) {
    for (const enabled of [[g], filterable.filter(x => x !== g)]) {
      const shown = shownBy(enabled);
      const t = T.treeProject(sp, shown, {});
      const tr = rows(t).filter(r => !r.row.folder);
      const want = data.nodes.filter(n => shown(n)).map(n => n.id).sort();
      const got = tr.map(r => r.row.id).sort();
      let ok = JSON.stringify(got) === JSON.stringify(want) && inOrder(t);
      for (const r of tr) {
        let up = fullParent.get(r.row.id);
        while (up !== null && !shown(byId.get(up))) up = fullParent.get(up);
        if (up !== r.parent) ok = false;
      }
      if (!ok) filterOk.push(enabled.join(','));
    }
  }
  check('fixture: every filter keeps each shown device once, below its nearest shown ancestor, in child order', filterOk.length === 0, filterOk);

  const vmJSON = T.treeProject(sp, shownBy(['vm']), { colors: groupColors });
  const vmRows = rows(vmJSON).filter(r => !r.row.folder);
  const vms = data.nodes.filter(n => n.group === 'vm').length;
  check('fixture: only VM: exactly the VMs', vmRows.length === vms && vmRows.every(r => byId.get(r.row.id).group === 'vm'), [vmRows.length, vms]);

  var fixtureRecord = {
    nodes: data.nodes.length,
    links: data.links.length,
    root: sp.root,
    root_name: sp.infos.get(sp.root).name,
    not_connected: devices.filter(r => r.folder).length,
    default: { rows: devices.length, outline: outline(json) },
    only_vm: { rows: vmRows.length, outline: outline(vmJSON) },
  };
}

// ---------------------------------------------------------------------------
// Part 3: the tab, with app.js, a stub DOM and a model of jsTree

function element(id) {
  const classes = new Set();
  const attrs = {};
  const listeners = {}; // bubble phase
  const captures = {};  // capture phase
  const phase = (options) => (options === true || !!(options && options.capture) ? captures : listeners);
  return {
    id, style: {}, dataset: {}, innerHTML: '', textContent: '', value: '', checked: true, hidden: false, disabled: false,
    clientWidth: 1200, clientHeight: 800, tagName: 'DIV', listeners, captures, scrolled: 0,
    classList: {
      add: (c) => classes.add(c), remove: (c) => classes.delete(c), contains: (c) => classes.has(c),
      toggle: (c, on) => { const v = on === undefined ? !classes.has(c) : !!on; if (v) classes.add(c); else classes.delete(c); return v; },
    },
    addEventListener(type, fn, options) { const l = phase(options); (l[type] = l[type] || []).push(fn); },
    removeEventListener(type, fn, options) { const l = phase(options); l[type] = (l[type] || []).filter(f => f !== fn); },
    appendChild(c) { return c; }, removeChild() {},
    setAttribute(k, v) { attrs[k] = String(v); }, getAttribute(k) { return k in attrs ? attrs[k] : null; },
    contains() { return false; }, querySelector() { return null; }, querySelectorAll() { return []; }, closest() { return null; },
    focus() {}, click() {}, scrollIntoView() { this.scrolled++; },
    getBoundingClientRect() { return { left: 0, top: 0, width: 1200, height: 800 }; },
  };
}
// dispatch delivers an event on a descendant of el (event.target) to el's
// listeners as a browser does: the capture listeners first, then, unless
// one of them stopped the event, the bubble listeners.
function dispatch(el, event) {
  let stopped = false, immediate = false;
  const ev = Object.assign({
    stopPropagation() { stopped = true; },
    stopImmediatePropagation() { stopped = immediate = true; },
  }, event);
  for (const fn of el.captures[ev.type] || []) if (!immediate) fn(ev);
  if (!stopped) for (const fn of el.listeners[ev.type] || []) if (!immediate) fn(ev);
}
// d3, mermaid and xterm stand-ins: every property and call gives the stand-in back.
function standIn() {
  const target = function () {};
  const proxy = new Proxy(target, {
    get(_, prop) {
      if (prop === 'then') return undefined;
      if (prop === Symbol.toPrimitive) return () => 0;
      if (prop === Symbol.iterator) return function* () {};
      return proxy;
    },
    apply() { return proxy; },
    construct() { return proxy; },
  });
  return proxy;
}

// A jQuery whose jstree() makes a model of a jsTree 3.3.16 instance
// (jsTreeModel); the instances it makes go to trees.
function jQueryStub(trees) {
  const $ = (el) => ({
    jstree(arg) {
      if (arg === true) return el.jstreeInstance || null;
      const inst = jsTreeModel(arg);
      el.jstreeInstance = inst;
      trees.push(inst);
      this.inst = inst;
      return this;
    },
    on(events, selector, fn) {
      if (typeof selector === 'function') { fn = selector; selector = null; }
      events.split(/\s+/).forEach(ev => { (this.inst.handlers[ev] = this.inst.handlers[ev] || []).push({ selector, fn }); });
      return this;
    },
  });
  $.jstree = { version: 'stub', root: '#' };
  return $;
}

// jsTreeModel stands in for a jsTree 3.3.16 instance: the methods tree.js
// calls and the events they fire, as jstree.js (core and search plugin)
// does. A row opens and closes with an open_node or close_node event, only
// when it changes (a row without children does not open). A search matches
// with search_callback, opens the rows above what it finds, keeps them as
// the rows it opened, shows only the rows found, those above them and those
// below them (show_only_matches, show_only_matches_children) and closes the
// rows it opened when it is replaced or cleared if close_opened_onclear is
// on. A refresh rebuilds the rows from settings.core.data and restores what
// its forget_state function returns: the open rows that still exist, then
// the selection, without opening rows. calls logs what tree.js asks;
// user.click and user.toggle are the user's clicks, which jsTree handles
// itself (not logged); model reads the rows' state for the checks.
function jsTreeModel(options) {
  const ROOT = '#';
  const inst = { options, handlers: {}, calls: [], restored: null };
  inst.settings = {
    core: Object.assign({}, options.core),
    search: Object.assign({ close_opened_onclear: true, show_only_matches: false, show_only_matches_children: false }, options.search),
  };
  let rows = new Map(); // id -> node, the root first, then depth first
  let sel = [];
  const search = { str: '', res: [], opn: [], hdn: [], som: false, smc: false };
  const emit = (ev, data) => fire(inst, ev + '.jstree', null, data);

  function load(data) {
    rows = new Map([[ROOT, { id: ROOT, parent: null, parents: [], children: [], children_d: [], state: { loaded: true } }]]);
    sel = [];
    const add = (json, parent) => {
      if (rows.has(json.id)) throw new Error(`jsTree model: duplicate id ${json.id}`);
      const n = { id: json.id, text: json.text, data: json.data, parent: parent.id, parents: [parent.id, ...parent.parents],
        children: [], children_d: [], state: { opened: !!(json.state && json.state.opened), selected: false, hidden: false } };
      rows.set(n.id, n);
      parent.children.push(n.id);
      (json.children || []).forEach(c => add(c, n));
    };
    (data || []).forEach(json => add(json, rows.get(ROOT)));
    const below = (n) => n.children.reduce((all, c) => all.concat(c, below(rows.get(c))), []);
    rows.forEach(n => { n.children_d = below(n); });
  }
  const node = (x) => {
    if (x && typeof x === 'object') x = x.nodeId !== undefined ? x.nodeId : x.id; // a node, or an anchor
    return rows.get(x) || false;
  };
  const ids = (x) => (Array.isArray(x) ? x.map(y => node(y).id) : node(x).id);
  const isClosed = (n) => !!n && n.id !== ROOT && n.children.length > 0 && !n.state.opened;
  function open(x) {
    if (Array.isArray(x)) { x.slice().forEach(open); return true; }
    const n = node(x);
    if (!n || n.id === ROOT || !isClosed(n)) return false;
    n.state.opened = true;
    emit('open_node', { node: n });
    return true;
  }
  function close(x) {
    if (Array.isArray(x)) { x.slice().forEach(close); return true; }
    const n = node(x);
    if (!n || n.id === ROOT || isClosed(n)) return false;
    n.state.opened = false;
    emit('close_node', { node: n });
    return true;
  }
  function show(x) {
    if (Array.isArray(x)) { x.slice().forEach(show); return true; }
    const n = node(x);
    if (!n || n.id === ROOT || !n.state.hidden) return false;
    n.state.hidden = false;
    return true;
  }
  function select(x, suppress, preventOpen, e) {
    const n = node(x);
    if (!n || n.id === ROOT) return false;
    if (!n.state.selected) {
      n.state.selected = true;
      sel.push(n.id);
      if (!preventOpen) n.parents.forEach(open); // _open_to
      emit('select_node', { node: n, selected: sel, event: e });
      if (!suppress) emit('changed', { action: 'select_node', node: n, selected: sel.slice(), event: e });
    }
    return true;
  }
  function deselectAll(suppress) {
    const old = sel;
    sel = [];
    old.forEach(id => { if (rows.has(id)) rows.get(id).state.selected = false; });
    emit('deselect_all', { selected: [], node: old });
    if (!suppress) emit('changed', { action: 'deselect_all', selected: [], old_selection: old });
  }
  function clearSearch() {
    if (inst.settings.search.close_opened_onclear) close(search.opn);
    if (search.som && search.res.length) show(search.hdn); // the plugin's own handler runs first
    emit('clear_search', { nodes: [], str: search.str, res: search.res });
    Object.assign(search, { str: '', res: [], opn: [] });
  }
  function find(str) {
    if (String(str).trim() === '') return clearSearch();
    if (search.res.length) clearSearch();
    const s = inst.settings.search;
    Object.assign(search, { str: String(str), res: [], opn: [], som: s.show_only_matches, smc: s.show_only_matches_children });
    const res = [], above = [];
    rows.get(ROOT).children_d.forEach(id => {
      const v = rows.get(id);
      if (v.text && !v.state.hidden && s.search_callback(String(str), v)) {
        res.push(id);
        above.push(...v.parents);
      }
    });
    if (res.length) {
      [...new Set(above)].forEach(id => { if (id !== ROOT && open(id) === true) search.opn.push(id); });
      search.res = res;
    }
    if (search.som && res.length) { // the plugin's own handler runs first
      const shown = new Set();
      res.forEach(id => {
        const v = rows.get(id);
        [id, ...v.parents, ...(search.smc ? v.children_d : [])].forEach(x => shown.add(x));
      });
      search.hdn = [];
      rows.forEach(n => { if (n.id !== ROOT && !n.state.hidden) { n.state.hidden = true; search.hdn.push(n.id); } });
      shown.forEach(x => { if (x !== ROOT) rows.get(x).state.hidden = false; });
    }
    emit('search', { nodes: [], str: String(str), res: search.res, show_only_matches: search.som });
  }
  const getState = () => {
    const all = [...rows.values()].filter(n => n.id !== ROOT);
    return { core: { open: all.filter(n => n.state.opened).map(n => n.id), loaded: [], scroll: { left: 0, top: 0 },
      selected: all.filter(n => n.state.selected).map(n => n.id) } };
  };
  const log = (...call) => inst.calls.push(call);

  Object.assign(inst, {
    get_node: node,
    get_selected: (full) => (full ? sel.map(node) : sel.slice()),
    is_open: (x) => !!node(x) && !!node(x).state.opened,
    is_hidden: (x) => node(x).state.hidden === true,
    search(str) { log('search', str); find(str); },
    clear_search() { log('clear_search'); clearSearch(); },
    open_node(x) { log('open_node', ids(x)); return open(x); },
    close_node(x) { log('close_node', ids(x)); return close(x); },
    toggle_node(x) {
      const n = node(x);
      log('toggle_node', n.id);
      if (isClosed(n)) return open(n);
      if (n.state.opened) return close(n);
    },
    open_all() {
      log('open_all');
      rows.forEach(n => open(n));
      emit('open_all', { node: rows.get(ROOT) });
    },
    close_all() {
      log('close_all');
      [...rows.values()].reverse().forEach(n => { if (n.state.opened) close(n); });
      emit('close_all', { node: rows.get(ROOT) });
    },
    show_node(x) { log('show_node', ids(x)); return show(x); },
    select_node(x, suppress, preventOpen, e) { log('select_node', ids(x)); return select(x, suppress, preventOpen, e); },
    deselect_all(suppress) { log('deselect_all'); deselectAll(suppress); },
    refresh(skipLoading, forgetState) {
      log('refresh', skipLoading);
      let state = forgetState === true ? {} : getState();
      if (typeof forgetState === 'function') state = forgetState.call(inst, state);
      inst.restored = JSON.parse(JSON.stringify(state));
      load(inst.settings.core.data);
      const core = state.core || {};
      if (Array.isArray(core.open)) open(core.open.filter(id => rows.has(id)));
      if (Array.isArray(core.selected)) {
        deselectAll(false);
        core.selected.forEach(id => select(id, false, true));
      }
      emit('set_state', {});
      emit('refresh', {});
    },
    user: {
      // a click on a row: activate_node (one selection, no reselect)
      click(id) {
        const n = node(id), e = { type: 'click' };
        if (!(n.state.selected && sel.length === 1)) {
          deselectAll(true);
          select(n, false, false, e);
        }
        emit('activate_node', { node: n, event: e });
      },
      // a click on a row's open/close icon
      toggle(id) {
        const n = node(id);
        if (isClosed(n)) open(n);
        else if (n.state.opened) close(n);
      },
    },
    model: {
      openIds: () => [...rows.values()].filter(n => n.id !== ROOT && n.state.opened).map(n => n.id),
      parentIds: () => [...rows.values()].filter(n => n.id !== ROOT && n.children.length).map(n => n.id),
      selected: () => sel.slice(),
      hidden: (id) => !!rows.get(id) && rows.get(id).state.hidden,
      // inSight: drawn, not hidden by a search and below open rows only
      inSight: (id) => {
        const n = rows.get(id);
        return !!n && !n.state.hidden && n.parents.every(p => p === ROOT || rows.get(p).state.opened);
      },
    },
  });
  load(options.core.data);
  return inst;
}
function fire(inst, ev, thisArg, ...args) {
  (inst.handlers[ev] || []).forEach(h => h.fn.apply(thisArg || null, [{ type: ev }, ...args]));
}

// page loads app.js and tree.js into a fresh page: its own elements, filter
// checkboxes (as index.html has them), timers (with their delays), jsTree
// models and the /api/graph answer (page.graph; none until it is set).
function page() {
  const elements = new Map();
  const byId = (id) => { if (!elements.has(id)) elements.set(id, element(id)); return elements.get(id); };
  const boxes = checkboxes.map(c => ({ checked: c.checked, dataset: { group: c.dataset.group } }));
  const trees = [];
  const timers = [];
  const p = { byId, boxes, trees, timers, graph: null };
  const sandbox = {
    document: {
      getElementById: byId,
      querySelector() { return null; },
      querySelectorAll(sel) { return sel.includes('data-group') ? boxes : []; },
      addEventListener() {}, removeEventListener() {},
      createElement(tag) { return element(tag); },
      body: element('body'),
    },
    console: { log() {}, info() {}, warn() {}, error(...a) { failed.push('console.error: ' + a.join(' ')); }, debug() {} },
    d3: standIn(), mermaid: standIn(), Terminal: standIn(), FitAddon: standIn(),
    jQuery: jQueryStub(trees),
    fetch: (url) => (url === '/api/graph' && p.graph ? Promise.resolve({ json: () => Promise.resolve(p.graph) }) : new Promise(() => {})),
    setInterval: () => 0, clearInterval() {},
    setTimeout: (fn, ms) => { timers.push({ fn, ms, done: false }); return timers.length; },
    clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].done = true; },
    alert() {}, confirm: () => false, prompt: () => null,
    localStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
    WebSocket: function () { throw new Error('tree_probe: no WebSocket'); },
  };
  sandbox.window = { innerWidth: 1280, innerHeight: 800, location: { href: '' }, document: sandbox.document, addEventListener() {}, open() {} };
  sandbox.location = sandbox.window.location;
  const ctx = vm.createContext(sandbox);
  vm.runInContext(appSrc, ctx, { filename: 'app.js' });
  vm.runInContext(treeSrc, ctx, { filename: 'tree.js' });
  p.run = (code) => vm.runInContext(code, ctx);
  p.runTimers = () => { for (let i = 0; i < timers.length; i++) if (!timers[i].done) { timers[i].done = true; timers[i].fn(); } };
  timers.forEach(t => { t.done = true; }); // app.js's own start-up timers are not part of this
  return p;
}

async function viewChecks() {
  const P = page();
  const { byId, run, runTimers, trees } = P;
  run(`var __spans = 0, __projects = 0;
    const __span = treeSpanning, __project = treeProject;
    treeSpanning = function (d) { __spans++; return __span(d); };
    treeProject = function (s, f, o) { __projects++; return __project(s, f, o); };
    var __panned = [];
    panToDevice = function (d) { __panned.push(d.id); };`);
  const state = () => run('({ tab: treeState.tab, stale: treeState.stale, spans: __spans, projects: __projects, made: treeState.instance !== null })');
  check('view: tree.js adds itself to app.js uiViewListeners', run('uiViewListeners.length') === 1 && run('uiViewListeners[0] === treeOnGraphChange'));

  P.graph = synthetic();
  await run('loadNetworkData()');
  let s = state();
  check('view: a data load while the Tree tab is hidden only marks the tree stale', s.stale && s.spans === 0 && s.projects === 0 && !s.made, s);

  const search = byId('deviceSearch');
  const typed = () => search.listeners.input.forEach(fn => fn({ target: search }));
  search.value = 'GW-1'; // typed on the graph tab, before the first visit
  typed();
  runTimers();
  run("selectViewTab('tree')");
  s = state();
  const tree = trees[0];
  check('view: opening the tab builds the tree once and makes the jsTree', s.made && s.spans === 1 && s.projects === 1 && trees.length === 1 && !s.stale, s);
  check('view: jsTree runs with the search plugin, no theme icons, no double-click toggle',
    tree.options.plugins.includes('search') && tree.options.core.themes.icons === false && tree.options.core.dblclick_toggle === false &&
    tree.options.search.show_only_matches === true && tree.options.search.search_callback === run('treeSearchMatch'));
  check('view: the top-level devices start open, the folder closed',
    tree.settings.core.data.every(n => (n.id === 'tvf-not-connected') === !(n.state && n.state.opened)));
  check('view: the tab shows the tree and covers the graph', byId('viewStage').classList.contains('tree-active') &&
    byId('treeView').hidden === false && byId('viewTabTree').getAttribute('aria-selected') === 'true' &&
    byId('viewTabGraph').getAttribute('aria-selected') === 'false');
  check('view: the status line counts the devices', byId('treeStatus').textContent === '17 of 17 devices shown · root: gw-1 · 3 not connected',
    byId('treeStatus').textContent);
  check('view: a search typed before the first visit waits until jsTree has loaded', tree.calls.length === 0, tree.calls);
  fire(tree, 'ready.jstree');
  check('view: on ready the search box is applied once', JSON.stringify(tree.calls) === '[["search","gw-1"]]', tree.calls);
  search.value = '';
  typed();
  runTimers();
  check('view: an emptied search box clears the search', JSON.stringify(tree.calls.slice(1)) === '[["clear_search"]]', tree.calls);
  tree.calls.length = 0;
  run("selectViewTab('graph'); selectViewTab('tree');");
  check('view: an empty search box does nothing more (a search redraws the tree)', tree.calls.length === 0, tree.calls);
  check('view: the rows opened at the start are remembered as open', JSON.stringify(run('[...treeState.open]')) === JSON.stringify([T.treeSafeId(R1)]));

  run("selectViewTab('graph'); selectViewTab('tree');");
  s = state();
  check('view: switching tabs back and forth does not rebuild', s.spans === 1 && s.projects === 1, s);
  check('view: the graph tab hides the tree again', (run("selectViewTab('graph')"), byId('treeView').hidden === true && !byId('viewStage').classList.contains('tree-active')));

  P.graph = synthetic();
  await run('loadNetworkData()');
  s = state();
  check('view: a data load while hidden does no work', s.spans === 1 && s.projects === 1 && s.stale, s);
  const callsBefore = tree.calls.length;
  run("selectViewTab('tree')");
  s = state();
  check('view: back on the tab the new data is built once, and the same tree is not refreshed',
    s.spans === 2 && s.projects === 2 && !tree.calls.slice(callsBefore).some(c => c[0] === 'refresh'), [s, tree.calls.slice(callsBefore)]);

  // The user opens the rows down to the hypervisor and selects a VM below
  // it; jsTree reports both. A filter that hides them must not forget them.
  const r1Id = T.treeSafeId(R1), s1Id = T.treeSafeId(S1), s3Id = T.treeSafeId(S3), yId = T.treeSafeId(Y), vm1Id = T.treeSafeId(VM1);
  const sameSet = (a, b) => JSON.stringify([...new Set(a)].sort()) === JSON.stringify([...new Set(b)].sort());
  [s1Id, s3Id, yId].forEach(id => tree.user.toggle(id));
  tree.user.click(vm1Id);
  runTimers(); // the click's info panel
  run('closeInfoPanel()');
  fire(tree, 'changed.jstree', null, { action: 'select_node', selected: [], node: {} }); // jsTree's own, no event
  check('view: opened rows and the selection a user makes are remembered',
    sameSet(run('[...treeState.open]'), [r1Id, s1Id, s3Id, yId]) && run('treeState.selected') === vm1Id, run('[...treeState.open]'));
  // A click on the '↔' row of the loop link under dist-2 goes to dist-10.
  const s2Id = T.treeSafeId(S2);
  tree.user.toggle(s2Id);
  tree.user.click(T.treeXrefId(S2, S3));
  runTimers();
  check('view: a click on a ↔ row selects the device at the other end of the link and opens its info, and opens or closes no row',
    run('treeState.selected') === s3Id && JSON.stringify(tree.model.selected()) === JSON.stringify([s3Id]) &&
    sameSet(run('[...treeState.open]'), [r1Id, s1Id, s2Id, s3Id, yId]) &&
    byId('infoPanel').style.display === 'block' && byId('infoPanelTitle').textContent === 'dist-10',
    [run('treeState.selected'), run('[...treeState.open]'), byId('infoPanelTitle').textContent]);
  run('closeInfoPanel()');
  tree.user.toggle(s2Id);
  tree.user.click(vm1Id);
  runTimers();
  run('closeInfoPanel()');

  const vmBox = P.boxes.find(c => c.dataset.group === 'vm');
  const hypBox = P.boxes.find(c => c.dataset.group === 'hypervisor');
  vmBox.checked = false;
  hypBox.checked = false;
  const k0 = tree.calls.length;
  run('applyFilters()');
  s = state();
  const after = tree.calls.slice(k0);
  const shownIds = rows(tree.settings.core.data).map(r => r.row.id);
  check('view: unchecking filters while the tab is shown refreshes the tree, without rebuilding the spanning tree',
    s.spans === 2 && s.projects === 3 && JSON.stringify(after) === JSON.stringify([['refresh', true]]) &&
    ![VM1, VM2, VM9, Y].some(id => shownIds.includes(id)) && shownIds.includes(S3), after);
  check('view: the refreshed data opens nothing itself', tree.settings.core.data.every(n => !n.state));
  check('view: a refresh restores the remembered open rows and selection, also those the filter hides now',
    sameSet(tree.restored.core.open, [r1Id, s1Id, s3Id, yId]) && sameSet(tree.model.openIds(), [r1Id, s1Id, s3Id]) &&
    JSON.stringify(tree.restored.core.selected) === JSON.stringify([vm1Id]) && tree.restored.core.scroll.top === 0, tree.restored);

  search.value = 'Dist-10 ';
  typed();
  runTimers();
  check('view: the device search box searches the tree (trimmed, lower case)', JSON.stringify(tree.calls.slice(-1)) === '[["search","dist-10"]]', tree.calls.slice(-2));
  const k = tree.calls.length;
  vmBox.checked = true;
  hypBox.checked = true;
  run('applyFilters()');
  check('view: checking them again brings the rows back, opened and selected as before',
    rows(tree.settings.core.data).some(r => r.row.id === VM1) && tree.restored.core.open.includes(yId) &&
    JSON.stringify(tree.restored.core.selected) === JSON.stringify([vm1Id]) &&
    sameSet(tree.model.openIds(), [r1Id, s1Id, s3Id, yId]) && JSON.stringify(tree.model.selected()) === JSON.stringify([vm1Id]), tree.restored);
  const searchCalls = tree.calls.slice(k).filter(c => ['search', 'clear_search', 'refresh'].includes(c[0]));
  check('view: a refresh under a search clears it first and applies it again on the new rows',
    JSON.stringify(searchCalls) === JSON.stringify([['clear_search'], ['refresh', true], ['search', 'dist-10']]), tree.calls.slice(k));
  tree.user.toggle(yId);
  check('view: a row the user closes is forgotten', !run('treeState.open.has(' + JSON.stringify(yId) + ')'));
  run('treeCollapseAll()');
  check('view: "Collapse all" forgets every open row', run('treeState.open.size') === 0 && tree.model.openIds().length === 0);

  run("selectViewTab('graph')");
  const n = tree.calls.length;
  search.value = 'gw';
  typed();
  runTimers();
  check('view: typing while the graph is shown leaves the tree alone', tree.calls.length === n, tree.calls.slice(n));
  run("selectViewTab('tree')");
  check('view: back on the tab the search box is applied', JSON.stringify(tree.calls.slice(-1)) === '[["search","gw"]]', tree.calls.slice(-2));
  search.value = '';
  typed();
  runTimers();
  check('view: an empty search box clears the search', JSON.stringify(tree.calls.slice(-1)) === '[["clear_search"]]');

  const swRow = tree.get_node(T.treeSafeId(S2));
  tree.user.click(swRow.id);
  check('view: a click toggles the row', JSON.stringify(tree.calls.slice(-1)) === JSON.stringify([['toggle_node', swRow.id]]));
  check('view: the info panel waits for a possible double-click', byId('infoPanel').style.display !== 'block');
  runTimers();
  check('view: a click opens the graph\'s info panel for the device', byId('infoPanel').style.display === 'block' &&
    byId('infoPanelTitle').textContent === 'dist-2' && byId('infoIP').textContent === '10.0.1.2', byId('infoPanelTitle').textContent);
  check('view: "Show in graph" is enabled for a selected device', byId('treeShowInGraph').disabled === false);

  const vmRow = tree.get_node(T.treeSafeId(VM1));
  tree.user.click(vmRow.id);
  const anchor = { nodeId: vmRow.id };
  (tree.handlers.dblclick || []).forEach(h => h.selector === '.jstree-anchor' && h.fn.call(anchor, { type: 'dblclick' }));
  runTimers();
  check('view: a double-click switches to the graph and pans to the device, the panel closed',
    run('treeState.tab') === 'graph' && JSON.stringify(run('__panned')) === JSON.stringify([VM1]) &&
    byId('infoPanel').style.display === 'none', [run('treeState.tab'), run('__panned'), byId('infoPanel').style.display]);
  run("selectViewTab('tree')");
  run('treeShowSelectedInGraph()');
  check('view: "Show in graph" focuses the selected device', JSON.stringify(run('__panned')) === JSON.stringify([VM1, VM1]));

  run("selectViewTab('tree')");
  const list = byId('deviceList');
  const clickItem = (id) => list.listeners.click.forEach(fn => fn({ target: { closest: () => ({ dataset: { deviceId: id } }) } }));
  clickItem(E9);
  check('view: a click in the device list selects the device in the tree', JSON.stringify(tree.calls.slice(-1)) === JSON.stringify([['select_node', T.treeSafeId(E9)]]));
  run("selectViewTab('graph')");
  const m = tree.calls.length;
  clickItem(E1);
  check('view: on the graph tab the device list does not touch the tree', tree.calls.length === m);

  check('view: what jsTree gets holds no server markup', safeTree(tree.settings.core.data).length === 0 &&
    !rows(tree.settings.core.data).some(r => r.json.text.includes('<img')));
}

// A second page: the tab opened before /api/graph answered, the search note,
// and a click's info panel when the graph tab is shown meanwhile.
async function earlyChecks() {
  const P = page();
  const { byId, run, trees } = P;
  run("selectViewTab('tree')");
  const tree = trees[0];
  check('view: a tab opened before /api/graph answered shows an empty tree and says it waits',
    !!tree && tree.settings.core.data.length === 0 && byId('treeStatus').textContent === 'Waiting for /api/graph ...', byId('treeStatus').textContent);
  fire(tree, 'ready.jstree');
  P.graph = synthetic();
  await run('loadNetworkData()');
  check('view: when the first devices come, their top level opens',
    tree.calls.some(c => c[0] === 'refresh') && JSON.stringify(tree.restored.core.open) === JSON.stringify([T.treeSafeId(R1)]), tree.restored);

  fire(tree, 'search.jstree', null, { res: [], str: 'nothing' });
  check('view: a search that finds nothing says so (jsTree then hides nothing)', byId('treeSearchStatus').textContent === 'no device matches "nothing"');
  fire(tree, 'search.jstree', null, { res: ['a', 'b'], str: 'x' });
  check('view: a search says how many devices it found', byId('treeSearchStatus').textContent === '2 found');
  fire(tree, 'clear_search.jstree', null, {});
  check('view: clearing the search clears the note', byId('treeSearchStatus').textContent === '');

  tree.user.click(T.treeSafeId(S2));
  run("selectViewTab('graph')");
  P.runTimers();
  check('view: a click\'s info panel does not open once the graph tab is shown', byId('infoPanel').style.display !== 'block');
}

// A third page: the device search on the tab, typed one key at a time as a
// user types it (finding F1: the rows each search opened stayed open, and
// were remembered as the user's, so the tree ended up nearly all open).
async function searchChecks() {
  const P = page();
  const { byId, run, runTimers, trees } = P;
  P.graph = synthetic();
  await run('loadNetworkData()');
  run("selectViewTab('tree')");
  const tree = trees[0];
  fire(tree, 'ready.jstree');
  const id = T.treeSafeId;
  const search = byId('deviceSearch');
  const type = (text) => { search.value = text; search.listeners.input.forEach(fn => fn({ target: search })); runTimers(); };
  const typeKeys = (text) => { for (let i = 1; i <= text.length; i++) type(text.slice(0, i)); };
  const sameSet = (a, b) => JSON.stringify([...new Set(a)].sort()) === JSON.stringify([...new Set(b)].sort());
  const remembered = () => run('[...treeState.open]');
  const searched = () => tree.calls.filter(c => c[0] === 'search').map(c => c[1]);
  const above = (dev) => tree.get_node(id(dev)).parents.filter(p => p !== '#');
  const note = () => byId('treeSearchStatus').textContent;
  const folder = treeConst('treeFolderId');

  check('search: the tab starts with its top level open', sameSet(tree.model.openIds(), [id(R1)]) && sameSet(remembered(), [id(R1)]));
  type('d');
  check('search: a 1-character query does not search the tree, and the note says so',
    searched().length === 0 && note() === 'type 2 or more characters to search the tree', [searched(), note()]);
  const delays = P.timers.filter(t => t.ms !== undefined).map(t => t.ms);
  check('search: the tree waits for a pause in the typing longer than a key takes (400 ms)',
    run('typeof treeSearchDelay !== "undefined" && treeSearchDelay') === 400 && delays[delays.length - 1] === 400, delays.slice(-1));

  // many found and nothing selected: clearing closes all the search opened
  typeKeys('dist');
  check('search: every query of 2 or more characters is searched, the rows above what it finds opened',
    JSON.stringify(searched()) === JSON.stringify(['di', 'dis', 'dist']) && tree.model.inSight(id(S2)) && tree.model.inSight(id(S3)) &&
    tree.model.openIds().includes(id(S1)) && note() === '2 found', [searched(), tree.model.openIds(), note()]);
  check('search: the rows a search opens are not remembered as the user\'s', sameSet(remembered(), [id(R1)]), remembered());
  type('');
  check('search: clearing it closes every row it opened (2 found, none selected)',
    sameSet(tree.model.openIds(), [id(R1)]) && sameSet(remembered(), [id(R1)]) && note() === '', tree.model.openIds());

  // typed key by key: "wi" finds the switches and opens the folder of the
  // lost one, "win" only the Windows VM: the folder closes again, and the
  // one device found stays in sight when the box is cleared.
  typeKeys('win-22');
  check('search: each new search closes the rows the one before opened',
    JSON.stringify(searched().slice(3)) === JSON.stringify(['wi', 'win', 'win-', 'win-2', 'win-22']) &&
    !tree.model.openIds().includes(folder) && sameSet(tree.model.openIds(), [id(R1), ...above(VM2)]) && note() === '1 found', tree.model.openIds());
  type('');
  check('search: when it is cleared, the one device found stays in sight, its rows the user\'s now, and the tree scrolls to it',
    tree.model.inSight(id(VM2)) && sameSet(tree.model.openIds(), [id(R1), ...above(VM2)]) && sameSet(remembered(), tree.model.openIds()) &&
    byId(id(VM2) + '_anchor').scrolled === 1, [tree.model.openIds(), remembered(), byId(id(VM2) + '_anchor').scrolled]);

  const endpoints = P.boxes.find(c => c.dataset.group === 'endpoint');
  endpoints.checked = false;
  run('applyFilters()');
  endpoints.checked = true;
  run('applyFilters()');
  check('search: a filter change afterwards opens the user\'s rows only',
    sameSet(tree.restored.core.open, [id(R1), ...above(VM2)]) && sameSet(tree.model.openIds(), [id(R1), ...above(VM2)]), tree.restored.core.open);

  // a refresh under a search: the rows the search opened are not restored
  run('treeCollapseAll()');
  type('win-22');
  const hubs = P.boxes.find(c => c.dataset.group === 'hub');
  hubs.checked = false;
  run('applyFilters()');
  check('search: a refresh under a search restores none of its rows as the user\'s, and searches again',
    tree.restored.core.open.length === 0 && remembered().length === 0 && tree.model.inSight(id(VM2)) &&
    sameSet(run('[...(treeState.searchOpen || [])]'), above(VM2)), [tree.restored.core.open, remembered()]);
  hubs.checked = true;
  run('applyFilters()');
  run('treeCollapseAll()');
  type('');
  check('search: rows the user closed during a search stay closed when it is cleared',
    tree.model.openIds().length === 0 && remembered().length === 0, tree.model.openIds());

  // the device the user selects among those found stays in sight
  type('dist');
  tree.user.click(id(S3)); // the click opens dist-10 too
  runTimers();
  run('closeInfoPanel()');
  type('');
  check('search: the device the user selected during a search stays in sight when it is cleared, nothing else opened',
    tree.model.inSight(id(S3)) && sameSet(tree.model.openIds(), [...above(S3), id(S3)]) && sameSet(remembered(), tree.model.openIds()) &&
    byId(id(S3) + '_anchor').scrolled === 1, tree.model.openIds());
  run('treeCollapseAll()');
  type('dist'); // dist-10 is still selected
  tree.user.toggle(id(S1)); // the user closes core-sw: dist-10 goes out of sight
  type('');
  check('search: a selected device the user put out of sight during a search keeps no row open',
    tree.model.openIds().length === 0 && remembered().length === 0, tree.model.openIds());
  type('gw'); // gw-1 and gw-2: opens gw-1, core-sw and dist-2 above gw-2
  tree.user.toggle(id(S2));
  tree.user.toggle(id(S2)); // the user closes dist-2 and opens it again: it is the user's now
  type('');
  check('search: a row the search opened that the user closed and opened again stays open when it is cleared',
    tree.model.openIds().includes(id(S2)) && remembered().includes(id(S2)), tree.model.openIds());

  // "Expand all" during a search: every row is the user's, none closes
  run('treeCollapseAll()');
  type('gw');
  run('treeExpandAll()');
  type('');
  check('search: after "Expand all" during a search, clearing it leaves every row open',
    sameSet(tree.model.openIds(), tree.model.parentIds()) && sameSet(remembered(), tree.model.parentIds()), tree.model.openIds());

  type('di');
  type('d');
  check('search: back to 1 character, the search is cleared', JSON.stringify(tree.calls.slice(-1)) === '[["clear_search"]]' &&
    note() === 'type 2 or more characters to search the tree', [tree.calls.slice(-2), note()]);
}

// A fourth page: the info panel's list of connected devices on the Tree tab
// (finding F2: a click there switched the hidden graph to that device's
// neighbourhood and its zoom, and nothing happened in the tree).
async function panelChecks() {
  const P = page();
  const { byId, run, runTimers, trees } = P;
  P.graph = synthetic();
  await run('loadNetworkData()');
  run(`var __highlighted = [];
    const __highlight = highlightNodeFromPanel;
    highlightNodeFromPanel = function (id) { __highlighted.push(id); return __highlight(id); };`);
  run("selectViewTab('tree')");
  const tree = trees[0];
  fire(tree, 'ready.jstree');
  const id = T.treeSafeId;
  const list = byId('infoNeighbors');
  const listed = () => [...list.innerHTML.matchAll(/data-node-id="([^"]*)"/g)].map(m => decodeEntities(m[1]));
  // clickListed clicks the line of a device in the list (row, a stand-in of
  // the line's element, which a second click may reuse) and returns it.
  const clickListed = (dev, row) => {
    row = row || element('peer');
    row.setAttribute('data-node-id', dev);
    dispatch(list, { type: 'click', target: { closest: (sel) => (sel === '[data-node-id]' ? row : null) } });
    return row;
  };
  const graph = () => run('({ mode: filterState.mode, selected: filterState.selectedNodeId, drawn: currentNodes.size, highlighted: __highlighted.slice() })');
  const note = () => byId('treeSearchStatus').textContent;
  const search = byId('deviceSearch');
  const type = (text) => { search.value = text; search.listeners.input.forEach(fn => fn({ target: search })); runTimers(); };

  // dist-2 is open; the user clicks it, which closes it and opens its panel
  tree.user.toggle(id(S1));
  tree.user.toggle(id(S2));
  tree.user.click(id(S2));
  runTimers();
  check('panel: a click on a row closes it and opens its info panel with the devices connected to it',
    byId('infoPanelTitle').textContent === 'dist-2' && [S1, S3, R2, H].every(x => listed().includes(x)) && !tree.model.inSight(id(R2)), listed());
  const before = graph();
  clickListed(R2);
  const after = graph();
  check('panel: on the Tree tab a click on a connected device does not reach app.js, which would switch the graph to it',
    after.highlighted.length === 0, after);
  check('panel: ... the graph keeps its filter mode and its devices', after.mode === 'ALL' && after.selected === null && after.drawn === before.drawn, [before, after]);
  check('panel: ... the device is selected in the tree, in sight and scrolled to',
    JSON.stringify(tree.model.selected()) === JSON.stringify([id(R2)]) && run('treeState.selected') === id(R2) &&
    tree.model.inSight(id(R2)) && byId(id(R2) + '_anchor').scrolled === 1, [tree.model.selected(), tree.model.openIds()]);
  check('panel: ... and the panel stays open on its device', byId('infoPanel').style.display === 'block' && byId('infoPanelTitle').textContent === 'dist-2');

  run("selectViewTab('graph')");
  clickListed(S1);
  check('panel: on the graph tab the same click still shows that device with its neighbours', graph().highlighted.join() === S1 &&
    graph().mode === 'CONNECTED' && graph().selected === S1, graph());
  run('resetView()');
  run("selectViewTab('tree')");

  const hubs = P.boxes.find(c => c.dataset.group === 'hub');
  hubs.checked = false;
  run('applyFilters()');
  const hubLine = clickListed(H);
  check('panel: a connected device the filters hide: the tree says so and nothing else changes',
    note() === 'Unmanaged is not in the tree: its group (hub) is filtered out' && byId('treeSearchStatus').title === note() &&
    graph().highlighted.length === 1 && graph().mode === 'ALL' && JSON.stringify(tree.model.selected()) === JSON.stringify([id(R2)]),
    [note(), tree.model.selected()]);
  check('panel: ... and its line in the list says why, where the user clicked',
    hubLine.classList.contains('tv-not-in-tree') && hubLine.getAttribute('data-tree-note') === 'filtered out (hub)', hubLine.getAttribute('data-tree-note'));
  hubs.checked = true;
  run('applyFilters()');
  clickListed(H, hubLine);
  check('panel: once the filter shows it again, a click on that line selects it and the line is plain again',
    JSON.stringify(tree.model.selected()) === JSON.stringify([id(H)]) && !hubLine.classList.contains('tv-not-in-tree'), tree.model.selected());
  run('closeInfoPanel()');

  tree.user.click(id(S1));
  runTimers();
  const lost = clickListed('no-such-node'); // a link to a node the graph does not have
  check('panel: a connected device the graph does not have: the tree says so', note() === 'no-such-node is not in the tree' &&
    lost.getAttribute('data-tree-note') === 'not in the tree', note());
  type('dist-2');
  check('panel: a search for dist-2 hides dist-10', tree.model.hidden(id(S3)) && listed().includes(S3));
  clickListed(S3);
  check('panel: a connected device the search hides is shown, selected and in sight',
    !tree.model.hidden(id(S3)) && tree.model.inSight(id(S3)) && JSON.stringify(tree.model.selected()) === JSON.stringify([id(S3)]) &&
    graph().mode === 'ALL', [tree.model.selected(), tree.model.hidden(id(S3))]);
  type('');
  check('panel: ... and it stays in sight when the search is cleared', tree.model.inSight(id(S3)) && !tree.model.hidden(id(S3)));
}

viewChecks().then(earlyChecks).then(searchChecks).then(panelChecks).then(() => {
  if (failed.length) {
    process.stderr.write(failed.map(f => 'FAIL ' + f).join('\n') + '\n');
    process.exit(1);
  }
  process.stdout.write(JSON.stringify({ checks: passed, synthetic: syntheticRecord, fixture: fixtureRecord }) + '\n');
}, (err) => {
  process.stderr.write('tree_probe: ' + (err && err.stack || err) + '\n');
  process.exit(1);
});
