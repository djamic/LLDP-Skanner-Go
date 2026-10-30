'use strict';
// history_probe.js tests static/history.html, the history page, as app.js
// uiHistoryURL opens it: its inline script, unmodified, in a Node vm with a
// stub DOM, Chart.js and fetch (TestUIHistoryPage):
//
//   node history_probe.js <history.html>
//
// A device on a switch port: the port asked of /api/history, the banner
// (the device's name as text, the switch, the port, what is in between, how
// many share the port), the port selected, ↓/↑ the device's (the port's
// out/in), the port events of that port; the whole switch again; a port the
// server does not find; a port the topology does not name; a switch with
// its uplink, and another device chosen. It sends nothing anywhere. Every
// failed check is printed and the exit code is 1.
const fs = require('fs'), vm = require('vm');
const [htmlPath] = process.argv.slice(2);
const html = fs.readFileSync(htmlPath, 'utf8');
const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].pop()[1];
const failed = [], passed = [];
const check = (name, ok, detail) => (ok ? passed : failed).push(ok ? name : `${name}: ${JSON.stringify(detail)}`);

function makePage(search, answers) {
  const els = new Map(), fetches = [], charts = [];
  const element = (id, tag = 'DIV') => {
    const e = { id, tagName: tag, style: {}, dataset: {}, innerHTML: '', textContent: '', listeners: {}, children: [],
      classList: { add() {}, remove() {}, contains() { return false; } },
      addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
      appendChild(c) { this.children.push(c); return c; }, querySelector() { return element('q'); }, getContext() { return {}; } };
    return e;
  };
  const select = (id) => {
    const s = element(id, 'SELECT'); s.options = []; s._v = '';
    Object.defineProperty(s, 'innerHTML', { get() { return ''; }, set(h) { s.options = [...h.matchAll(/<option value="([^"]*)"[^>]*>([^<]*)</g)].map(m => ({ value: m[1], textContent: m[2] })); s._v = s.options[0] ? s.options[0].value : ''; } });
    s.appendChild = (o) => { s.options.push(o); if (s.options.length === 1) s._v = o.value; return o; };
    Object.defineProperty(s, 'value', { get() { return s._v; }, set(v) { s._v = s.options.some(o => o.value === v) ? v : ''; } });
    Object.defineProperty(s, 'selectedOptions', { get() { const o = s.options.find(o => o.value === s._v); return o ? [o] : []; } });
    return s;
  };
  const byId = (id) => {
    if (!els.has(id)) {
      let e;
      if (id === 'deviceSelect') { e = select(id); e.options.push({ value: '', textContent: 'Select Device...' }); }
      else if (id === 'portSelect') { e = select(id); e.options.push({ value: 'all', textContent: 'All Ports' }); e._v = 'all'; }
      else if (id === 'timeframeSelect') { e = select(id); e.options.push({ value: '24', textContent: '24' }); e._v = '24'; }
      else if (id === 'metricSelect') { e = select(id); e.options.push({ value: 'traffic', textContent: 't' }); e._v = 'traffic'; }
      else e = element(id);
      els.set(id, e);
    }
    return els.get(id);
  };
  const docListeners = {};
  const location = { search, href: '' };
  const sandbox = {
    document: { getElementById: byId, createElement: (t) => element('', t.toUpperCase()), querySelector: () => element('canvas'), querySelectorAll: () => [],
      addEventListener(t, f) { (docListeners[t] = docListeners[t] || []).push(f); } },
    window: { location, innerWidth: 1280, innerHeight: 800 }, location,
    URLSearchParams, console: { log() {}, warn() {}, error(...a) { failed.push('console.error ' + a.join(' ')); } },
    Chart: function (ctx, cfg) { this.data = cfg.data; this.update = () => {}; this.getDatasetMeta = () => ({ hidden: false }); charts.push(this); },
    fetch: (url) => { fetches.push(url); const path = url.split('?')[0]; const a = answers[path]; return Promise.resolve({ json: () => Promise.resolve(typeof a === 'function' ? a(url) : (a || {})) }); },
    alert: (m) => failed.push('alert ' + m), confirm: () => false, setTimeout: () => 0, Terminal: function () {}, FitAddon: { FitAddon: function () {} },
  };
  vm.createContext(sandbox);
  vm.runInContext(script, sandbox, { filename: 'history.html' });
  return { byId, fetches, charts, run: (c) => vm.runInContext(c, sandbox), location, ready: async () => { for (const f of docListeners.DOMContentLoaded || []) await f(); await new Promise(r => setImmediate(r)); } };
}
const tick = () => new Promise(r => setImmediate(r));
const hosts = { hosts: { '10.0.1.2': { SysName: 'dist-2' }, '10.0.1.1': { SysName: 'core-sw' } } };
const pt = (t, port, inb, outb) => ({ time: t, if_name: port, in_bps: inb, out_bps: outb, in_errors: 0, out_errors: 0, in_discards: 0, out_discards: 0 });
const portAnswer = (url) => url.includes('port=GE1%2F0%2F5')
  ? { device: '10.0.1.2', hours: 24, port: { name: 'GE1/0/5', if_name: '"GigabitEthernet1/0/5"', if_index: 5 }, data: [pt('2026-10-30T06:00:00Z', '"GigabitEthernet1/0/5"', 100, 900), pt('2026-10-30T06:01:00Z', '"GigabitEthernet1/0/5"', 200, 800)] }
  : url.includes('port=') ? { device: '10.0.1.2', hours: 24, port_error: '10.0.1.2 has no port GE1/0/99', data: [pt('2026-10-30T06:00:00Z', '"GigabitEthernet1/0/7"', 1, 2)] }
  : { device: '10.0.1.2', hours: 24, data: [pt('2026-10-30T06:00:00Z', '"GigabitEthernet1/0/5"', 100, 900), pt('2026-10-30T06:00:00Z', '"GigabitEthernet1/0/7"', 1, 2)] };
const answers = { '/api/hosts': hosts, '/api/history': portAnswer, '/api/device-detail': { error: 'x' }, '/api/port-events': { events: [{ time: '2026-10-30T06:00:00Z', type: 'port_down', port: 5, message: 'm' }] }, '/api/port-events/stats': {} };

(async () => {
  // 1. a device on a hub port
  let P = makePage('?id=10.0.1.2&port=GE1%2F0%2F5&for=' + encodeURIComponent('<img src=x onerror=alert(1)> (10.0.2.11)') + '&shared=2&via=hub', answers);
  await P.ready();
  const hist = P.fetches.find(u => u.startsWith('/api/history'));
  check('device: the port is asked of /api/history', hist === '/api/history?id=10.0.1.2&hours=24&port=GE1%2F0%2F5', hist);
  const banner = P.byId('contextBanner');
  check('device: the banner names the device (escaped), the switch, the port, the hub and the sharing',
    banner.style.display === 'flex' && banner.innerHTML.includes('&lt;img src=x onerror=alert(1)&gt; (10.0.2.11)') && !banner.innerHTML.includes('<img') &&
    banner.innerHTML.includes('<b>dist-2 (10.0.1.2)</b> port <b>GE1/0/5</b>') && banner.innerHTML.includes('through a hub') &&
    banner.innerHTML.includes('2 devices hang on this port') && banner.innerHTML.includes('showWholeSwitch()'), banner.innerHTML);
  check('device: the port is selected', P.byId('portSelect').value === 'GigabitEthernet1/0/5', P.byId('portSelect').value);
  const ds = P.charts[0].data.datasets;
  check('device: ↓ is the port\'s out, ↑ its in', ds.length === 2 && ds[0].label === 'GigabitEthernet1/0/5 ↓ Download (port out)' &&
    JSON.stringify(ds[0].data.map(p => p.y)) === '[900,800]' && ds[1].label === 'GigabitEthernet1/0/5 ↑ Upload (port in)' &&
    JSON.stringify(ds[1].data.map(p => p.y)) === '[100,200]', ds.map(d => [d.label, d.data.map(p => p.y)]));
  check('device: the averages are the device\'s', P.byId('avgIn').textContent === '850 bps' && P.byId('avgOut').textContent === '150 bps',
    [P.byId('avgIn').textContent, P.byId('avgOut').textContent]);
  P.run("switchTab('events')"); await tick(); await tick();
  const ev = P.fetches.filter(u => u.startsWith('/api/port-events'));
  check('device: the port events are the port\'s (ifIndex)', ev.length === 2 && ev.every(u => u.endsWith('&port=5')), ev);
  P.run('showWholeSwitch()'); await tick(); await tick();
  const last = P.fetches.filter(u => u.startsWith('/api/history')).pop();
  check('whole switch: no port asked, no banner, switch view', last === '/api/history?id=10.0.1.2&hours=24' && banner.style.display === 'none' &&
    P.byId('portSelect').value === 'all', [last, banner.style.display, P.byId('portSelect').value]);

  // 2. a port the server does not find
  P = makePage('?id=10.0.1.2&port=GE1%2F0%2F99&for=dev&shared=3', answers);
  await P.ready();
  const b2 = P.byId('contextBanner').innerHTML;
  check('port not found: the warning, no Whole switch button, no device direction', b2.includes('10.0.1.2 has no port GE1/0/99: the history of the whole switch') &&
    !b2.includes('showWholeSwitch') && !b2.includes('devices hang') && P.byId('portSelect').value === 'all', b2);

  // 3. port unknown in the topology
  P = makePage('?id=10.0.1.2&for=dev&shared=0&via=access_point', answers);
  await P.ready();
  const b3 = P.byId('contextBanner').innerHTML;
  check('port unknown: the whole switch with the warning', b3.includes('names no switch port') && b3.includes('through an access point') &&
    P.fetches.find(u => u.startsWith('/api/history')) === '/api/history?id=10.0.1.2&hours=24', b3);

  // 4. a switch with its uplink
  P = makePage('?id=10.0.1.2&up=10.0.1.1&upport=GE1%2F0%2F10&upname=' + encodeURIComponent('core-sw (10.0.1.1)'), answers);
  await P.ready();
  const b4 = P.byId('contextBanner').innerHTML;
  check('switch: the uplink button', b4.includes('⬆ Uplink: core-sw (10.0.1.1) GE1/0/10') && !b4.includes('showWholeSwitch'), b4);
  check('switch: its own data, the switch\'s direction', P.charts[0].data.datasets.length === 2 && !P.charts[0].data.datasets[0].label.includes('port out'));
  P.run('openUplink()');
  const u = new URL(P.location.href, 'http://x');
  check('switch: the uplink opens the port above, for this switch', u.pathname === '/history.html' && u.searchParams.get('id') === '10.0.1.1' &&
    u.searchParams.get('port') === 'GE1/0/10' && u.searchParams.get('for') === 'dist-2 (10.0.1.2)', P.location.href);
  // another device chosen: no context left
  const sel = P.byId('deviceSelect'); sel.value = '10.0.1.1'; sel.listeners.change.forEach(f => f.call(sel));
  check('another device: the banner is gone', P.byId('contextBanner').style.display === 'none');

  console.log(passed.length + ' passed'); if (failed.length) { console.log('FAIL\n' + failed.join('\n')); process.exit(1); }
})();
