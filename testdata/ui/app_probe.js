'use strict';
// app_probe.js runs static/app.js, unmodified, in a Node vm sandbox with a
// small DOM stub and prints JSON describing what its helpers do with the
// graphs it is given. It sends nothing anywhere: fetch never resolves,
// timers and WebSocket are stubs. Used by TestGoldenUIApp:
//
//   node app_probe.js <app.js> <index.html> <cases.json>
//
// cases.json: {"graphs": {name: /api/graph data}, "connected": [{graph,
// node}], "info_panel": [{graph, node}], "ip_choice": [{graph, node}],
// "shadow_it": [graph names]}

const fs = require('fs');
const vm = require('vm');

const [appPath, indexPath, casesPath] = process.argv.slice(2);
const cases = JSON.parse(fs.readFileSync(casesPath, 'utf8'));
const indexHTML = fs.readFileSync(indexPath, 'utf8');

// Filter checkboxes as index.html declares them (all checked on load).
const legend = {};
const checkboxes = [];
for (const m of indexHTML.matchAll(/data-group="([a-z_]+)"([^>]*)>[\s\S]*?background:\s*(#[0-9A-Fa-f]{6})/g)) {
  legend[m[1]] = m[3].toUpperCase();
  checkboxes.push({ checked: /\bchecked\b/.test(m[2]), dataset: { group: m[1] } });
}

function element(id) {
  return {
    id, style: {}, dataset: {}, innerHTML: '', textContent: '', value: '', checked: true,
    clientWidth: 1200, clientHeight: 800, tagName: 'DIV',
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    addEventListener() {}, removeEventListener() {}, appendChild(c) { return c; }, removeChild() {},
    setAttribute() {}, getAttribute() { return null; }, contains() { return false; },
    querySelector() { return null; }, querySelectorAll() { return []; }, closest() { return null; },
    focus() {}, click() {}, getBoundingClientRect() { return { left: 0, top: 0, width: 1200, height: 800 }; },
  };
}
const elements = new Map();
function byId(id) {
  if (!elements.has(id)) elements.set(id, element(id));
  return elements.get(id);
}

// d3, mermaid, xterm and Chart stand-ins: every property and call gives the
// stand-in back.
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

const alerts = [];
const location = { href: '' };
const document = {
  getElementById: byId,
  querySelector() { return null; },
  querySelectorAll(sel) { return sel.includes('data-group') ? checkboxes : []; },
  addEventListener() {}, removeEventListener() {},
  createElement(tag) { return element(tag); },
  body: element('body'),
};
const sandbox = {
  document,
  window: { innerWidth: 1280, innerHeight: 800, location, document, addEventListener() {}, open() {} },
  location,
  console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
  d3: standIn(), mermaid: standIn(), Terminal: standIn(), FitAddon: standIn(), Chart: standIn(),
  fetch: () => new Promise(() => {}),
  setInterval: () => 0, clearInterval() {}, setTimeout: () => 0, clearTimeout() {},
  alert: (m) => alerts.push(String(m)), confirm: () => false, prompt: () => null,
  localStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
  navigator: { clipboard: { writeText: () => new Promise(() => {}) } },
  WebSocket: function () { throw new Error('app_probe: no WebSocket'); },
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(appPath, 'utf8'), sandbox, { filename: 'app.js' });
const run = (code) => vm.runInContext(code, sandbox);

function useGraph(name) {
  sandbox.__graph = cases.graphs[name];
  run('rawData = __graph; filterState.mode = "ALL"; filterState.selectedNodeId = null;');
}

// Text of an HTML fragment: tags removed, whitespace collapsed.
const text = (html) => html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
const matches = (html, re) => [...html.matchAll(re)].map((m) => text(m[1]));

const out = { group_colors: run('JSON.parse(JSON.stringify(groupColors))'), legend_colors: legend };

// Group filter with every checkbox on (ALL mode): nodes kept per group.
out.all_filter = {};
for (const name of Object.keys(cases.graphs).sort()) {
  useGraph(name);
  sandbox.__res = run('getFilteredData(rawData)');
  const kept = {}, total = {};
  for (const n of sandbox.__graph.nodes) total[n.group] = (total[n.group] || 0) + 1;
  for (const n of sandbox.__res.nodes) kept[n.group] = (kept[n.group] || 0) + 1;
  out.all_filter[name] = { nodes_by_group: total, kept_by_group: kept, links: sandbox.__graph.links.length, kept_links: sandbox.__res.links.length };
}

// "Show Connected Devices" (CONNECTED mode) for a node.
out.connected = [];
for (const c of cases.connected) {
  useGraph(c.graph);
  sandbox.__id = c.node;
  run('filterState.mode = "CONNECTED"; filterState.selectedNodeId = __id;');
  sandbox.__res = run('getFilteredData(rawData)');
  const neighbors = new Set();
  for (const l of sandbox.__graph.links) {
    if (l.source === c.node) neighbors.add(l.target);
    if (l.target === c.node) neighbors.add(l.source);
  }
  out.connected.push({ graph: c.graph, node: c.node, nodes: sandbox.__graph.nodes.length, neighbors: neighbors.size, kept: sandbox.__res.nodes.length });
}

// The info panel for a node.
out.info_panel = [];
for (const c of cases.info_panel) {
  useGraph(c.graph);
  sandbox.__node = sandbox.__graph.nodes.find((n) => n.id === c.node);
  run('showInfoPanel(__node)');
  const neighbors = byId('infoNeighbors').innerHTML;
  out.info_panel.push({
    graph: c.graph, node: c.node,
    title: byId('infoPanelTitle').textContent, type: byId('infoType').textContent,
    vendor: byId('infoVendor').textContent, ip: byId('infoIP').textContent,
    sys_name: byId('infoSysName').textContent, connections: byId('infoConnections').textContent,
    port_groups: matches(neighbors, /<span>🔌 ([^<]*)<\/span>\s*<span style="color:#6c8ab0">/g),
    peers: matches(neighbors, /<span>([^<]*)<\/span>\s*<span style="color:#6c8ab0;font-size:10px">/g),
  });
}

// The IP that History and Connect use for a node, next to the info panel's.
out.ip_choice = [];
for (const c of cases.ip_choice) {
  useGraph(c.graph);
  sandbox.__id = c.node;
  location.href = '';
  run('selectedNodeId = __id; viewHistory();');
  const history = location.href;
  run('selectedNodeId = __id; connectedDeviceIP = null; connectToDevice();');
  sandbox.__node = sandbox.__graph.nodes.find((n) => n.id === c.node);
  run('showInfoPanel(__node)');
  out.ip_choice.push({ graph: c.graph, node: c.node, history_url: history, connect_ip: run('connectedDeviceIP'), info_panel_ip: byId('infoIP').textContent });
}

// The Shadow-IT list.
out.shadow_it = {};
for (const name of cases.shadow_it) {
  useGraph(name);
  byId('shadowITList').innerHTML = '';
  run('showShadowIT()');
  const html = byId('shadowITList').innerHTML;
  out.shadow_it[name] = {
    headings: matches(html, /<div class="shadow-switch-name">([\s\S]*?)<\/div>/g),
    labels: matches(html, /<div class="shadow-label">([\s\S]*?)<\/div>/g),
    port_lines: matches(html, /<div class="shadow-port">([\s\S]*?)<\/div>/g),
    raw_img_tag_in_html: html.includes('<img src=x'),
  };
}
out.alerts = alerts;

process.stdout.write(JSON.stringify(out) + '\n');
