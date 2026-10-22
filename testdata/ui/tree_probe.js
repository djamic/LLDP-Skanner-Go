'use strict';
// tree_probe.js tests static/tree.js, the Tree tab, and prints the record
// TestGoldenUITree pins (testdata/golden/ui_tree.json):
//
//   node tree_probe.js <tree.js> <graph.json> <index.html> <app.js>
//
// 1. The pure builder, tree.js alone in a Node vm without a DOM, on a small
//    synthetic graph: the spanning tree from the core (BFS shape), the child
//    order, the ports, the filters with re-parenting, the counts, the "Not
//    connected" folder, the escaping of server strings and the ids.
// 2. The same on the fixture graph, testdata/golden/graph.json: every device
//    once, tree edges are links, depths are hop counts from the root, every
//    filter keeps the visible devices in place, and the outlines the golden
//    pins (default filters and only 'vm').
// 3. The tab itself: app.js and tree.js, unmodified, with a stub DOM, jQuery
//    and jsTree. Nothing is built while the tab is hidden, the filter
//    checkboxes and the device search reach the tree, a click opens the info
//    panel, a double-click focuses the graph.
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

// row reads a jsTree node back: the spans tree.js writes.
function row(json) {
  const t = json.text;
  const span = (cls) => {
    const m = new RegExp(`<span class="${cls}"(?: title="[^"]*")?>([^<]*)</span>`).exec(t);
    return m ? decodeEntities(m[1]) : '';
  };
  return {
    id: json.data && json.data.node, folder: !!(json.data && json.data.folder),
    name: span('tv-name'), address: span('tv-addr'), port: span('tv-port'), count: span('tv-count'), icon: span('tv-icon'),
    dot: (/<span class="tv-dot" style="background:([^"]*)"/.exec(t) || [])[1] || '',
    unreachable: t.includes('tv-unreachable'),
    title: decodeEntities((/^<span class="tv-row[^"]*" title="([^"]*)"/.exec(t) || [])[1] || ''),
  };
}

// outline is the tree as text, one row per line, indented by depth.
function outline(json) {
  const lines = [];
  const walk = (n, depth) => {
    const r = row(n);
    lines.push('  '.repeat(depth) + `${r.icon} ${r.name}` + (r.address ? ` · ${r.address}` : '') +
      (r.port ? ` [${r.port}]` : '') + (r.count ? ` (${r.count})` : '') + (r.unreachable ? ' !unreachable' : '') +
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
    const r = row(n);
    out.push({ json: n, row: r, parent, depth, folder });
    (n.children || []).forEach(c => walk(c, r.folder ? null : r.id, depth + 1, folder || r.folder));
  };
  json.forEach(n => walk(n, null, 0, false));
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
  check('synthetic: BFS: a router behind a switch hangs below it', at(R2).parent === S2 && at(R2).depth === 3);
  check('synthetic: child order: routers/switches, hubs/hypervisors, the rest, natural by name',
    JSON.stringify(at(S1).json.children.map(c => row(c).name)) === JSON.stringify(['dist-2', 'dist-10']) &&
    JSON.stringify(at(S2).json.children.map(c => row(c).id)) === JSON.stringify([R2, H]) &&
    JSON.stringify(at(S3).json.children.map(c => row(c).id)) === JSON.stringify([Y, X2, X1, AP]),
    [at(S2).json.children.map(c => row(c).id), at(S3).json.children.map(c => row(c).id)]);
  check('synthetic: ports: the parent\'s own port, speed and traffic and [MAC-REF] dropped, target side read',
    at(S1).row.port === 'Te1/0/1' && at(S3).row.port === 'GE1/0/2' && at(R2).row.port === 'GE1/0/46' &&
    at(H).row.port === 'GE1/0/5' && at(Y).row.port === 'ge1/0/7' && at(AP).row.port === 'GE1/0/12',
    rs.map(r => [r.row.id, r.row.port]));
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
    JSON.stringify(all[1].children.map(c => row(c).id)) === JSON.stringify([S9, VM9]) && at(E9).parent === S9,
    outline([all[1]]));
  check('synthetic: icon and colour per group as in the graph, red when unreachable',
    rs.every(r => r.row.icon === groupIcons[data.nodes.find(n => n.id === r.row.id).group]) &&
    at(S2).row.dot === groupColors.switch && at(VM1).row.dot === groupColors.vm && at(S3).row.dot === '#ff4444' && at(S3).row.unreachable,
    rs.map(r => [r.row.id, r.row.icon, r.row.dot]));
  check('synthetic: the tooltip names the link and both ports',
    at(S3).row.title.split('\n').includes('link: core-sw (10.0.1.1) GE1/0/2 ↔ GE1/0/48'), at(S3).row.title);

  // Escaping (finding F86): names, ids, ports and DNS names are text.
  const problems = safeTree(all);
  const html = rs.map(r => r.json.text).join('\n');
  check('synthetic: server strings never become markup', problems.length === 0 && !html.includes('<img') &&
    !html.includes('<svg') && !html.includes('<b ') && !html.includes('<i>'), problems);
  check('synthetic: the escaped strings are in the text', at(X1).json.text.includes('&lt;img src=x onerror=alert(1)&gt;') &&
    at(X2).json.text.includes('&quot;&gt;&lt;svg onload=alert(2)&gt;') && at(X1).json.text.includes('GE1/0/9 &lt;i&gt;x&lt;/i&gt;') &&
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
    row(vmOnly[0]).port === 'dist-10 (10.0.1.10) ge1/0/7' && row(vmOnly[1]).port === 'dist-10 (10.0.1.10) ge1/0/7' &&
    row(vmOnly[2]).folder && row(vmOnly[2]).count === '1', outline(vmOnly));
  const swVm = T.treeProject(sp, shownBy(['switch', 'vm']), { colors: groupColors });
  const sv = rows(swVm).filter(r => !r.row.folder);
  const svAt = (id) => sv.find(r => r.row.id === id);
  check('synthetic: switch and VM: VMs move up to their switch, with its port', svAt(VM1).parent === S3 && svAt(VM2).parent === S3 &&
    svAt(VM1).row.port === 'ge1/0/7' && svAt(S1).parent === null && svAt(S1).row.port === 'gw-1 (10.0.0.1) Te1/0/1' &&
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
    crAt(S3).row.port === 'GE1/0/47', outline(coreTree));
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
    const walk = (n) => (n.children || []).forEach(c => { below++; walk(c); });
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
    return sorted(tree) && rows(tree).every(r => sorted(r.json.children || []));
  };
  check('fixture: siblings are in child order', inOrder(json));
  const problems = safeTree(json);
  check('fixture: no row holds markup from the server', problems.length === 0, problems.slice(0, 3));

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
// Part 3: the tab, with app.js, a stub DOM and a stub jsTree

function element(id) {
  const classes = new Set();
  const attrs = {};
  const listeners = {};
  return {
    id, style: {}, dataset: {}, innerHTML: '', textContent: '', value: '', checked: true, hidden: false, disabled: false,
    clientWidth: 1200, clientHeight: 800, tagName: 'DIV', listeners,
    classList: {
      add: (c) => classes.add(c), remove: (c) => classes.delete(c), contains: (c) => classes.has(c),
      toggle: (c, on) => { const v = on === undefined ? !classes.has(c) : !!on; if (v) classes.add(c); else classes.delete(c); return v; },
    },
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    removeEventListener(type, fn) { listeners[type] = (listeners[type] || []).filter(f => f !== fn); },
    appendChild(c) { return c; }, removeChild() {},
    setAttribute(k, v) { attrs[k] = String(v); }, getAttribute(k) { return k in attrs ? attrs[k] : null; },
    contains() { return false; }, querySelector() { return null; }, querySelectorAll() { return []; }, closest() { return null; },
    focus() {}, click() {}, scrollIntoView() {}, getBoundingClientRect() { return { left: 0, top: 0, width: 1200, height: 800 }; },
  };
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

// A jQuery with a jsTree stand-in: it records what tree.js asks of it; the
// instances it makes go to trees.
function jQueryStub(trees) {
  const $ = (el) => ({
    jstree(arg) {
      if (arg === true) return el.jstreeInstance || null;
      const handlers = {};
      const inst = {
        options: arg, handlers, calls: [], selected: null,
        settings: { core: { data: arg.core.data } },
        // jsTree hands the state it saved (open rows, scroll, selection)
        // to a forget_state function and restores what that returns.
        refresh(skipLoading, forgetState) {
          const saved = { core: { open: [...(this.openNow || [])], scroll: { left: 0, top: 0 }, selected: [] } };
          this.restored = typeof forgetState === 'function' ? forgetState(saved) : saved;
          this.calls.push(['refresh', skipLoading]);
          fire(this, 'refresh.jstree');
        },
        clear_search() { this.calls.push(['clear_search']); },
        search(q) { this.calls.push(['search', q]); },
        toggle_node(n) { this.calls.push(['toggle_node', n.id]); },
        open_all() { this.calls.push(['open_all']); },
        close_all() { this.calls.push(['close_all']); },
        deselect_all() { this.selected = null; },
        select_node(id) { this.selected = id; this.calls.push(['select_node', id]); },
        get_selected() { return this.selected ? [this.get_node(this.selected)] : []; },
        get_node(x) {
          const id = x && typeof x === 'object' ? x.nodeId : x;
          let found = false;
          const walk = (list) => list.forEach(n => { if (n.id === id) found = n; walk(n.children || []); });
          walk(this.settings.core.data);
          return found;
        },
      };
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
  $.jstree = { version: 'stub' };
  return $;
}
function fire(inst, ev, thisArg, ...args) {
  (inst.handlers[ev] || []).forEach(h => h.fn.apply(thisArg || null, [{ type: ev }, ...args]));
}

// page loads app.js and tree.js into a fresh page: its own elements, filter
// checkboxes (as index.html has them), timers, jsTree stand-ins and the
// /api/graph answer (page.graph; none until it is set).
function page() {
  const elements = new Map();
  const byId = (id) => { if (!elements.has(id)) elements.set(id, element(id)); return elements.get(id); };
  const boxes = checkboxes.map(c => ({ checked: c.checked, dataset: { group: c.dataset.group } }));
  const trees = [];
  const timers = [];
  const p = { byId, boxes, trees, graph: null };
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
    setTimeout: (fn) => { timers.push({ fn, done: false }); return timers.length; },
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

  // The user opens the hypervisor row and selects a VM below it; jsTree
  // reports both. A filter that hides them must not forget them.
  const yId = T.treeSafeId(Y), vm1Id = T.treeSafeId(VM1);
  fire(tree, 'open_node.jstree', null, { node: { id: yId } });
  fire(tree, 'changed.jstree', null, { action: 'select_node', selected: [vm1Id], event: { type: 'click' } });
  fire(tree, 'changed.jstree', null, { action: 'select_node', selected: [], node: {} }); // jsTree's own, no event
  check('view: opened rows and the selection a user makes are remembered', run('treeState.open.has(' + JSON.stringify(yId) + ') && treeState.selected') === vm1Id);
  tree.openNow = [T.treeSafeId(R1), yId];

  const vmBox = P.boxes.find(c => c.dataset.group === 'vm');
  const hypBox = P.boxes.find(c => c.dataset.group === 'hypervisor');
  vmBox.checked = false;
  hypBox.checked = false;
  run('applyFilters()');
  s = state();
  const after = tree.calls.slice(callsBefore);
  const shownIds = rows(tree.settings.core.data).map(r => r.row.id);
  check('view: unchecking filters while the tab is shown refreshes the tree, without rebuilding the spanning tree',
    s.spans === 2 && s.projects === 3 && JSON.stringify(after) === JSON.stringify([['refresh', true]]) &&
    ![VM1, VM2, VM9, Y].some(id => shownIds.includes(id)) && shownIds.includes(S3), after);
  check('view: the refreshed data opens nothing itself', tree.settings.core.data.every(n => !n.state));
  check('view: a refresh restores the remembered open rows and selection, also those the filter hides now',
    JSON.stringify(tree.restored.core.open) === JSON.stringify([T.treeSafeId(R1), yId]) &&
    JSON.stringify(tree.restored.core.selected) === JSON.stringify([vm1Id]) && tree.restored.core.scroll.top === 0, tree.restored);
  tree.openNow = [T.treeSafeId(R1)];

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
    JSON.stringify(tree.restored.core.selected) === JSON.stringify([vm1Id]), tree.restored);
  check('view: a refresh under a search clears it first and applies it again on the new rows',
    JSON.stringify(tree.calls.slice(k)) === JSON.stringify([['clear_search'], ['refresh', true], ['search', 'dist-10']]), tree.calls.slice(k));
  fire(tree, 'close_node.jstree', null, { node: { id: yId } });
  check('view: a row the user closes is forgotten', !run('treeState.open.has(' + JSON.stringify(yId) + ')'));
  fire(tree, 'close_all.jstree', null, { node: { id: '#' } });
  check('view: "Collapse all" forgets every open row', run('treeState.open.size') === 0);

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
  tree.selected = swRow.id;
  fire(tree, 'activate_node.jstree', null, { node: swRow });
  check('view: a click toggles the row', JSON.stringify(tree.calls.slice(-1)) === JSON.stringify([['toggle_node', swRow.id]]));
  check('view: the info panel waits for a possible double-click', byId('infoPanel').style.display !== 'block');
  runTimers();
  check('view: a click opens the graph\'s info panel for the device', byId('infoPanel').style.display === 'block' &&
    byId('infoPanelTitle').textContent === 'dist-2' && byId('infoIP').textContent === '10.0.1.2', byId('infoPanelTitle').textContent);
  check('view: "Show in graph" is enabled for a selected device', byId('treeShowInGraph').disabled === false);

  const vmRow = tree.get_node(T.treeSafeId(VM1));
  tree.selected = vmRow.id;
  fire(tree, 'activate_node.jstree', null, { node: vmRow });
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

  fire(tree, 'activate_node.jstree', null, { node: tree.get_node(T.treeSafeId(S2)) });
  run("selectViewTab('graph')");
  P.runTimers();
  check('view: a click\'s info panel does not open once the graph tab is shown', byId('infoPanel').style.display !== 'block');
}

viewChecks().then(earlyChecks).then(() => {
  if (failed.length) {
    process.stderr.write(failed.map(f => 'FAIL ' + f).join('\n') + '\n');
    process.exit(1);
  }
  process.stdout.write(JSON.stringify({ checks: passed, synthetic: syntheticRecord, fixture: fixtureRecord }) + '\n');
}, (err) => {
  process.stderr.write('tree_probe: ' + (err && err.stack || err) + '\n');
  process.exit(1);
});
