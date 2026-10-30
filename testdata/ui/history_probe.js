'use strict';
// history_probe.js tests static/history.html, the history page, as app.js
// uiHistoryURL opens it: its inline script, unmodified, in a Node vm with a
// stub DOM, Chart.js and fetch (TestUIHistoryPage):
//
//   node history_probe.js <history.html>
//
// A device on a switch port: a page of its own (its card with its facts,
// its name as text, the switch and the port it hangs on, that port's state
// now and no other port of the switch; no switch panel, no device or port
// choice), the port asked of /api/history, ↓/↑ the device's (the port's
// out/in), how many share the port, the port events of that port. A port
// the server does not find and a port the topology does not name: no
// history, never the switch's other ports. A switch's own history: one
// port of it and the whole switch again, its uplink, another device
// chosen. It sends nothing anywhere. Every failed check is printed and the
// exit code is 1.
const fs = require('fs'), vm = require('vm');
const [htmlPath] = process.argv.slice(2);
const html = fs.readFileSync(htmlPath, 'utf8');
const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].pop()[1];
// the elements the page starts hidden (style="display: none;")
const hidden = new Set([...html.matchAll(/id="([A-Za-z]+)"[^>]*style="display:\s*none;?"/g)].map(m => m[1]));
const failed = [], passed = [];
const check = (name, ok, detail) => (ok ? passed : failed).push(ok ? name : `${name}: ${JSON.stringify(detail)}`);

// makePage loads the page's script at the URL search, fetch answering from
// answers by path (a value, or a function of the URL).
function makePage(search, answers) {
  const els = new Map(), fetches = [], charts = [];
  const element = (id, tag = 'DIV') => {
    const e = { id, tagName: tag, style: hidden.has(id) ? { display: 'none' } : {}, dataset: {}, innerHTML: '', textContent: '', className: '', listeners: {}, children: [],
      classList: { add() {}, remove() {}, contains() { return false; } },
      addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
      appendChild(c) { this.children.push(c); return c; }, querySelector() { return this.q || (this.q = element('q')); }, getContext() { return {}; } };
    return e;
  };
  // a <select>: its value is one of its options' or ''
  const select = (id, options, value) => {
    const s = element(id, 'SELECT'); s.options = options.map(([v, text]) => ({ value: v, textContent: text })); s._v = value;
    Object.defineProperty(s, 'innerHTML', { get() { return ''; }, set(h) { s.options = [...h.matchAll(/<option value="([^"]*)"[^>]*>([^<]*)</g)].map(m => ({ value: m[1], textContent: m[2] })); s._v = s.options[0] ? s.options[0].value : ''; } });
    s.appendChild = (o) => { s.options.push(o); if (s.options.length === 1) s._v = o.value; return o; };
    Object.defineProperty(s, 'value', { get() { return s._v; }, set(v) { s._v = s.options.some(o => o.value === v) ? v : ''; } });
    Object.defineProperty(s, 'selectedOptions', { get() { const o = s.options.find(o => o.value === s._v); return o ? [o] : []; } });
    return s;
  };
  const selects = {
    deviceSelect: [[['', 'Select Device...']], ''], portSelect: [[['all', 'All Ports']], 'all'],
    timeframeSelect: [[['24', '24']], '24'], metricSelect: [[['traffic', 't']], 'traffic'],
  };
  const byId = (id) => {
    if (!els.has(id)) els.set(id, selects[id] ? select(id, ...selects[id]) : element(id));
    return els.get(id);
  };
  const docListeners = {};
  const location = { search, href: '' };
  const doc = { getElementById: byId, createElement: (t) => element('', t.toUpperCase()), querySelector: () => element('canvas'), querySelectorAll: () => [],
    addEventListener(t, f) { (docListeners[t] = docListeners[t] || []).push(f); }, title: '' };
  const sandbox = {
    document: doc, window: { location, innerWidth: 1280, innerHeight: 800 }, location,
    URLSearchParams, console: { log() {}, warn() {}, error(...a) { failed.push('console.error ' + a.join(' ')); } },
    Chart: function (ctx, cfg) { this.data = cfg.data; this.update = () => {}; this.getDatasetMeta = () => ({ hidden: false }); charts.push(this); },
    fetch: (url) => {
      fetches.push(url);
      const a = answers[url.split('?')[0]];
      return Promise.resolve({ json: () => Promise.resolve(typeof a === 'function' ? a(url) : (a || {})) });
    },
    alert: (m) => failed.push('alert ' + m), confirm: () => false, setTimeout: () => 0, Terminal: function () {}, FitAddon: { FitAddon: function () {} },
  };
  vm.createContext(sandbox);
  vm.runInContext(script, sandbox, { filename: 'history.html' });
  return {
    byId, fetches, charts, doc, location, run: (c) => vm.runInContext(c, sandbox),
    history: () => fetches.filter(u => u.startsWith('/api/history')),
    ready: async () => { for (const f of docListeners.DOMContentLoaded || []) await f(); await tick(); await tick(); },
  };
}
const tick = () => new Promise(r => setImmediate(r));
const shown = (el) => el.style.display !== 'none';

const pt = (t, port, inb, outb) => ({ time: t, if_name: port, in_bps: inb, out_bps: outb, in_errors: 0, out_errors: 0, in_discards: 0, out_discards: 0 });
const GE5 = '"GigabitEthernet1/0/5"', GE7 = '"GigabitEthernet1/0/7"';
const historyAnswer = (url) => url.includes('port=GE1%2F0%2F5')
  ? { device: '10.0.1.2', hours: 24, port: { name: 'GE1/0/5', if_name: GE5, if_index: 5 }, data: [pt('2026-10-30T06:00:00Z', GE5, 100, 900), pt('2026-10-30T06:01:00Z', GE5, 200, 800)] }
  : url.includes('port=') ? { device: '10.0.1.2', hours: 24, port_error: '10.0.1.2 has no port GE1/0/99', count: 0, data: [] }
  : { device: '10.0.1.2', hours: 24, data: [pt('2026-10-30T06:00:00Z', GE5, 100, 900), pt('2026-10-30T06:00:00Z', GE7, 1, 2)] };
const detail = {
  ip: '10.0.1.2', sys_name: 'dist-2',
  interfaces: [
    { if_index: 5, if_descr: GE5, if_alias: 'desk 12', if_oper_status: 1, if_admin_status: 1, if_speed: 1e9, in_bps: 1000, out_bps: 5e6, in_errors: 1, out_errors: 2, in_discards: 0, out_discards: 3 },
    { if_index: 7, if_descr: GE7, if_alias: 'printer room', if_oper_status: 2, if_admin_status: 1, if_speed: 1e8, in_bps: 0, out_bps: 0 },
  ],
  port_vlans: [{ port_index: 5, pvid: 1620, is_trunk: false }, { port_index: 7, pvid: 10, is_trunk: false }],
};
const answers = (extra) => Object.assign({
  '/api/hosts': { hosts: { '10.0.1.2': { SysName: 'dist-2' }, '10.0.1.1': { SysName: 'core-sw' } } },
  '/api/history': historyAnswer, '/api/device-detail': detail,
  '/api/port-events': { events: [{ time: '2026-10-30T06:00:00Z', type: 'port_down', port: 5, message: 'm' }] }, '/api/port-events/stats': {},
}, extra || {});
const deviceURL = (extra) => '?' + new URLSearchParams(Object.assign({
  id: '10.0.1.2', port: 'GE1/0/5', for: '<img src=x onerror=alert(1)> (10.0.2.11)', shared: '2', via: 'hub',
  type: '💻 Endpoint', vendor: 'Intel', ip: '10.0.2.11', mac: '00:1b:21:00:00:11',
}, extra || {}));

(async () => {
  // 1. a device on a hub port: a page of its own
  let P = makePage(deviceURL(), answers());
  await P.ready();
  check('device: the port is asked of /api/history', P.history()[0] === '/api/history?id=10.0.1.2&hours=24&port=GE1%2F0%2F5', P.history());
  const card = P.byId('devGrid').innerHTML;
  check('device: the page is the device\'s: its card, no switch panel, no device or port choice, no banner',
    shown(P.byId('devicePanel')) && !shown(P.byId('switchPanel')) && !shown(P.byId('deviceGroup')) && !shown(P.byId('portGroup')) &&
    !shown(P.byId('contextBanner')) && P.byId('pageTitle').textContent === '📊 Device History' &&
    P.byId('devTitle').textContent === '📍 <img src=x onerror=alert(1)> (10.0.2.11)' && P.doc.title.startsWith('<img src=x onerror=alert(1)> (10.0.2.11) - History'),
    [P.byId('devicePanel').style, P.byId('switchPanel').style, P.byId('devTitle').textContent]);
  check('device: the card has its facts and the switch port it hangs on, through the hub',
    ['💻 Endpoint', '10.0.2.11', '00:1b:21:00:00:11', 'Intel', '>dist-2 (10.0.1.2)</a> · port GE1/0/5', 'through a hub', 'href="/history.html?id=10.0.1.2"']
      .every(s => card.includes(s)) && !card.includes('<img'), card);
  check('device: the card has its port\'s state now, as the device\'s, and no other port of the switch',
    ['🟢 Up · 1 Gbps', 'Access VLAN 1620', 'desk 12', '↓ 5.0 Mbps  ↑ 1 Kbps', '3 err / 3 disc'].every(s => card.includes(s)) &&
    !card.includes('printer room') && !card.includes('VLAN 10<'), card);
  check('device: the shared port is said', P.byId('devWarn').innerHTML.includes('2 devices hang on this port'), P.byId('devWarn').innerHTML);
  check('device: online', P.byId('devStatus').textContent === '🟢 Online');
  const ds = P.charts[0].data.datasets;
  check('device: two lines, ↓ the port\'s out and ↑ its in, named as the device\'s', ds.length === 2 && ds[0].label === '↓ Download' &&
    JSON.stringify(ds[0].data.map(p => p.y)) === '[900,800]' && ds[1].label === '↑ Upload' &&
    JSON.stringify(ds[1].data.map(p => p.y)) === '[100,200]', ds.map(d => [d.label, d.data.map(p => p.y)]));
  check('device: the averages are the device\'s', P.byId('avgIn').textContent === '850 bps' && P.byId('avgOut').textContent === '150 bps',
    [P.byId('avgIn').textContent, P.byId('avgOut').textContent]);
  P.run("switchTab('events')"); await tick(); await tick();
  const ev = P.fetches.filter(u => u.startsWith('/api/port-events'));
  check('device: the port events are its port\'s (ifIndex)', ev.length === 2 && ev.every(u => u.endsWith('&port=5')), ev);
  P.run('loadHistory()'); await tick(); await tick();
  check('device: Apply asks its port again, never the whole switch', P.history().length === 2 && P.history().every(u => u.includes('&port=GE1%2F0%2F5')), P.history());

  // 2. a device whose port the server does not find
  P = makePage(deviceURL({ port: 'GE1/0/99', shared: '3' }), answers());
  await P.ready();
  check('port not found: no history, the reason in the card, no other port', P.charts[0].data.datasets.length === 0 &&
    P.byId('chartEmpty').querySelector('p').textContent === '10.0.1.2 has no port GE1/0/99: no history for this device' && P.byId('devWarn').innerHTML.includes('10.0.1.2 has no port GE1/0/99, so there is no history') &&
    !P.byId('devWarn').innerHTML.includes('devices hang') && P.byId('devGrid').innerHTML.includes('port GE1/0/99') &&
    !P.byId('devGrid').innerHTML.includes('desk 12') && !shown(P.byId('switchPanel')), [P.byId('devWarn').innerHTML, P.byId('devGrid').innerHTML]);

  // 3. a device whose port the topology does not name
  P = makePage(deviceURL({ port: '', via: 'access_point', shared: '0', type: '📶 WLAN client', client: 'on AP-1\noffice · 5G', down: '1' }), answers());
  await P.ready();
  check('a Wi-Fi client: what its controller tells, and unreachable', P.byId('devGrid').innerHTML.includes('Details</div><div class="dc-value">on AP-1\noffice · 5G</div>') &&
    P.byId('devStatus').textContent === '🔴 Unreachable' && P.byId('devStatus').className === 'dev-status-down', [P.byId('devGrid').innerHTML, P.byId('devStatus')]);
  check('port unknown: no history asked, the reason in the card', P.history().length === 0 &&
    P.byId('chartEmpty').querySelector('p').textContent.startsWith('The topology names no switch port') &&
    P.byId('devWarn').innerHTML.includes('names no switch port for this device') && P.byId('devGrid').innerHTML.includes('through an access point') &&
    !shown(P.byId('switchPanel')), [P.history(), P.byId('devWarn').innerHTML]);

  // 4. a switch's own history: one port of it, the whole switch again
  P = makePage('?id=10.0.1.2', answers({ '/api/device-detail': { error: 'x' } }));
  await P.ready();
  check('switch: the whole switch, no card, the switch\'s direction', !shown(P.byId('devicePanel')) && P.history()[0] === '/api/history?id=10.0.1.2&hours=24' &&
    P.charts[0].data.datasets.length === 2 && P.charts[0].data.datasets.every(d => !d.label.startsWith('↓')), P.charts[0].data.datasets.map(d => d.label));
  P.run("historyPort = 'GE1/0/5'; loadHistory()"); await tick(); await tick();
  const banner = P.byId('contextBanner');
  check('switch: one port of it, with the Whole switch button', banner.innerHTML.includes('Port <b>GE1/0/5</b> of <b>dist-2 (10.0.1.2)</b>') &&
    banner.innerHTML.includes('showWholeSwitch()') && P.charts[0].data.datasets[0].label === 'GigabitEthernet1/0/5 ↓ Download' &&
    JSON.stringify(P.charts[0].data.datasets[0].data.map(p => p.y)) === '[100,200]', [banner.innerHTML, P.charts[0].data.datasets.map(d => d.label)]);
  P.run('showWholeSwitch()'); await tick(); await tick();
  check('switch: the whole switch again', P.history().pop() === '/api/history?id=10.0.1.2&hours=24' && !shown(banner) &&
    P.byId('portSelect').value === 'all', [P.history(), banner.style.display]);

  // 5. a switch with its uplink
  P = makePage('?id=10.0.1.2&up=10.0.1.1&upport=GE1%2F0%2F10&upname=' + encodeURIComponent('core-sw (10.0.1.1)'), answers({ '/api/device-detail': { error: 'x' } }));
  await P.ready();
  const b5 = P.byId('contextBanner').innerHTML;
  check('uplink: the button', b5.includes('⬆ Uplink: core-sw (10.0.1.1) GE1/0/10') && !b5.includes('showWholeSwitch'), b5);
  P.run('openUplink()');
  const u = new URL(P.location.href, 'http://x');
  check('uplink: it opens the port above as this switch\'s page', u.pathname === '/history.html' && u.searchParams.get('id') === '10.0.1.1' &&
    u.searchParams.get('port') === 'GE1/0/10' && u.searchParams.get('for') === 'dist-2 (10.0.1.2)' && u.searchParams.get('ip') === '10.0.1.2', P.location.href);
  const sel = P.byId('deviceSelect'); sel.value = '10.0.1.1'; sel.listeners.change.forEach(f => f.call(sel));
  check('another device: the banner is gone', !shown(P.byId('contextBanner')));

  if (failed.length) {
    console.log(`${passed.length} passed\nFAIL\n` + failed.join('\n'));
    process.exit(1);
  }
  console.log(`${passed.length} passed`);
})().catch(err => { console.log('history_probe: ' + (err && err.stack || err)); process.exit(1); });
