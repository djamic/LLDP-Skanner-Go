'use strict';
// tree.js: the Tree tab, the topology of /api/graph drawn as a jsTree.
//
// Part 1 is pure (no DOM, no jQuery) and runs in Node as well
// (testdata/ui/tree_probe.js): treeSpanning turns the graph into a spanning
// tree from the core, treeProject turns that tree into jsTree JSON for the
// groups the filter checkboxes show, and buildTopologyTree does both.
// Part 2, the view, needs the browser, app.js (loaded before this file),
// jQuery and jsTree. It builds and renders the tree only while the Tree tab
// is visible; while the tab is hidden a data or filter change only marks
// the tree stale.
//
// Every string in a node comes from the network (LLDP and SNMP names, port
// names, DNS names) and jsTree puts node text into the page as HTML, so the
// text is built here from escaped strings only (finding F86), and nothing
// from the server goes into a jsTree id or attribute.

// ==================== Part 1: the pure builder ====================

// Group icons, the same as the info panel's (app.js showInfoPanel).
const treeGroupIcons = {
    'switch': '🔀', 'router': '🌐', 'hub': '🔌', 'endpoint': '💻',
    'wifi_random': '🎲', 'vm': '🖥️', 'hypervisor': '🏗️', 'bmc': '🔧', 'server': '🖲️',
    'access_point': '📡', 'camera': '📹', 'printer': '🖨️', 'phone': '📱', 'iot': '🔌', 'unknown': '❓'
};

// The colour of a group without one, and of an unreachable node (as in the graph).
const treeDefaultColor = '#9E9E9E';
const treeUnreachableColor = '#ff4444';

// jsTree ids: a device's id is 'tvd-' plus its graph id with every character
// other than A-Z, a-z and 0-9 written as _<hex code>_, so it is unique and
// stable across rebuilds (jsTree keeps opened and selected nodes by id) and
// never markup. The "Not connected" folder has an id no device can have.
const treeFolderId = 'tvf-not-connected';

const treeHTMLEntities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

// treeEscapeHTML makes a value safe as HTML text or as a quoted attribute
// value (the same entities as app.js uiEscapeHTML).
function treeEscapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => treeHTMLEntities[ch]);
}

function treeSafeId(id) {
    return 'tvd-' + String(id).replace(/[^A-Za-z0-9]/g, ch => '_' + ch.charCodeAt(0).toString(16) + '_');
}

function treeIsIPv4(s) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    return !!m && m.slice(1).every(octet => Number(octet) <= 255);
}

function treeIsMAC(s) {
    return /^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$/.test(s);
}

// A link end is a node id, or the node object once d3's link force has
// resolved it (app.js renderGraph does that to the links it draws).
function treeLinkEnd(end) {
    return end !== null && typeof end === 'object' ? String(end.id) : String(end);
}

// treeLinkPort is the port of nodeId on the link, "" when the label names
// none. GetGraphData splits "<srcPort>|<dstPort>" into sourceLabel and
// targetLabel; the 'Hub' of a switch->hub link ('GE1/0/8|Hub') is a
// placeholder, not a port, and the [MAC-REF] marker and the speed and
// traffic suffix are dropped as in the info panel:
// 'TGE1/0/52 [T] 10G ↓13M ↑29M' -> 'TGE1/0/52 [T]'.
function treeLinkPort(link, nodeId) {
    const label = treeLinkEnd(link.source) === nodeId ? link.sourceLabel : link.targetLabel;
    if (!label || label === 'Hub') return '';
    return String(label).split('[MAC-REF]')[0].replace(/\s+(?:\d+[MGmg]\b|[↓↑]).*$/, '').trim();
}

// treeNodeIPs: the node's own addresses, the id when it is an IP and then
// every label line that is an IPv4 address (as app.js uiNodeIPs).
function treeNodeIPs(node) {
    const ips = node.ip ? [String(node.ip)] : [];
    String(node.sysName || node.label || '').split('\n').forEach(line => {
        const s = line.trim();
        if (treeIsIPv4(s) && !ips.includes(s)) ips.push(s);
    });
    return ips;
}

// A tag line of a label starts with its tag: '[ENDPOINT] Intel'.
const treeTagPattern = /^\[[A-Za-z-]+\]\s*/;

// treeNodeName is the name a row shows: the DNS name, else the first line
// of sysName (or label) that names the device (an SNMP sysName or an LLDP
// system name), else the text of its first tag line (the vendor of
// '[ENDPOINT] Intel', '[LLDP-EP] SNR' or '[WiFi] Apple', the OS of
// '[VM] 🐧 Linux VMware', the type of '[BMC] HPE iLO'), else its IP, else
// its id. A hub or hypervisor is named by its tag line: its other lines
// count devices and VMs ("4 devices", "6 VMs on ge1/0/24", "VMs: ...").
function treeNodeName(node) {
    if (node.hostname) return String(node.hostname);
    const id = String(node.id);
    const lines = String(node.sysName || node.label || '').split('\n').map(s => s.trim()).filter(Boolean);
    const first = lines[0] || '';
    if (first.startsWith('[HUB]') || first.startsWith('[HYPERVISOR]')) {
        const text = first.replace(treeTagPattern, '');
        if (text) return text;
    }
    const name = lines.find(l => !l.startsWith('[') && !treeIsIPv4(l) && !l.startsWith('VMs:') && l !== id);
    if (name) return name;
    for (const l of lines) {
        if (l.startsWith('[DNS]')) continue;
        const text = l.replace(treeTagPattern, '');
        if (text !== l && text) return text;
    }
    return lines.find(treeIsIPv4) || id;
}

// treeNodeAddress is the IP a row shows next to the name, or the MAC (the
// node id) when the node has no IP or the name already is the IP.
function treeNodeAddress(node, name, ips) {
    if (ips[0] && ips[0] !== name) return ips[0];
    const id = String(node.id);
    return treeIsMAC(id) && id !== name ? id : '';
}

// Child order: routers and switches, then hubs and hypervisors, then the rest.
function treeGroupRank(group) {
    if (group === 'router' || group === 'switch') return 0;
    if (group === 'hub' || group === 'hypervisor') return 1;
    return 2;
}

// Names sort naturally and the same way in every browser and Node version
// (no locale): case-insensitive, digit runs by value, so GE1/0/2 < GE1/0/10
// and sw-9 < sw-10. treeSortKey splits a text into those runs once.
function treeSortKey(text) {
    return (String(text).toLowerCase().match(/\d+|\D+/g) || []).map(run => {
        const c = run.charCodeAt(0);
        return c >= 48 && c <= 57 ? { digits: true, v: run.replace(/^0+(?=\d)/, '') } : { digits: false, v: run };
    });
}

function treeCompareKeys(a, b) {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
        const p = a[i], q = b[i];
        if (p.v === q.v && p.digits === q.digits) continue;
        if (p.digits && q.digits && p.v.length !== q.v.length) return p.v.length - q.v.length;
        return p.v < q.v ? -1 : 1;
    }
    return a.length - b.length;
}

function treeCompareIds(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
}

function treeCompareText(a, b) {
    return treeCompareKeys(treeSortKey(a), treeSortKey(b)) || treeCompareIds(a, b);
}

// treeCompareInfo is the child order of the tree: rank, name, address, id.
function treeCompareInfo(a, b) {
    return (a.rank - b.rank) || treeCompareKeys(a.nameKey, b.nameKey) || treeCompareIds(a.name, b.name) ||
        treeCompareKeys(a.addressKey, b.addressKey) || treeCompareIds(a.id, b.id);
}

// treeSpanning builds the spanning tree of the graph data (/api/graph:
// nodes, links and, when the server sends it, core). The root is the core:
// data.core when it is a node of the graph, else the first router in id
// order (the analyzer's own fallback, topologyCore: which router is the
// first gateway is not in /api/graph), else the switch with the most links,
// else the node with the most links. A breadth-first search over the links,
// in both directions, gives every node reached its parent, so each device
// appears once at its hop distance from the core. Nodes the core does not
// reach form trees of their own, rooted by the same rule; they go under the
// "Not connected" folder. Run it once per data change: treeProject reuses
// it for every filter state.
function treeSpanning(data) {
    const nodes = Array.isArray(data && data.nodes) ? data.nodes : [];
    const links = Array.isArray(data && data.links) ? data.links : [];
    const infos = new Map();
    nodes.forEach(node => {
        if (!node || node.id === undefined || node.id === null) return;
        const id = String(node.id);
        if (infos.has(id)) return;
        const group = node.group || 'endpoint';
        const name = treeNodeName(node);
        const ips = treeNodeIPs(node);
        const address = treeNodeAddress(node, name, ips);
        infos.set(id, {
            id, node, group, name, ips, address,
            rank: treeGroupRank(group),
            nameKey: treeSortKey(name),
            addressKey: treeSortKey(address),
            // how a row names this device when it holds the port of a
            // device further down: many switches are just called 'HPE'
            label: ips[0] && ips[0] !== name ? `${name} (${ips[0]})` : name,
            degree: 0,
        });
    });

    // Neighbours with the port of each end; a pair linked twice keeps the
    // ports either link names.
    const adjacency = new Map();
    const addEdge = (from, to, port, peerPort) => {
        if (!adjacency.has(from)) adjacency.set(from, new Map());
        const edges = adjacency.get(from);
        const e = edges.get(to);
        if (!e) edges.set(to, { port, peerPort });
        else {
            if (!e.port) e.port = port;
            if (!e.peerPort) e.peerPort = peerPort;
        }
    };
    links.forEach(link => {
        if (!link) return;
        const s = treeLinkEnd(link.source), t = treeLinkEnd(link.target);
        if (s === t || !infos.has(s) || !infos.has(t)) return;
        infos.get(s).degree++;
        infos.get(t).degree++;
        const sp = treeLinkPort(link, s), tp = treeLinkPort(link, t);
        addEdge(s, t, sp, tp);
        addEdge(t, s, tp, sp);
    });

    // Root preference: routers by id, then switches and then the other
    // nodes by link count (most first) and id.
    const roots = Array.from(infos.values()).sort((a, b) => {
        const ca = a.group === 'router' ? 0 : a.group === 'switch' ? 1 : 2;
        const cb = b.group === 'router' ? 0 : b.group === 'switch' ? 1 : 2;
        if (ca !== cb) return ca - cb;
        if (ca !== 0 && a.degree !== b.degree) return b.degree - a.degree;
        return treeCompareIds(a.id, b.id);
    });

    const parent = new Map(), depth = new Map(), children = new Map();
    const port = new Map(), peerPort = new Map();
    const attachDevice = new Map(), attachPort = new Map();
    const search = (root) => {
        depth.set(root, 0);
        parent.set(root, null);
        const queue = [root];
        for (let i = 0; i < queue.length; i++) {
            const u = queue[i];
            const kids = [];
            const edges = adjacency.get(u);
            const peers = edges ? Array.from(edges.keys()).map(id => infos.get(id)).sort(treeCompareInfo) : [];
            for (const peer of peers) {
                const v = peer.id;
                if (depth.has(v)) continue;
                const e = edges.get(v);
                depth.set(v, depth.get(u) + 1);
                parent.set(v, u);
                port.set(v, e.port);
                peerPort.set(v, e.peerPort);
                // Where the device is plugged in: the nearest port on its
                // path from the root (a hub member, a VM behind a vNIC and
                // the hypervisor node hang on their switch port).
                if (e.port) {
                    attachDevice.set(v, u);
                    attachPort.set(v, e.port);
                } else if (attachDevice.has(u)) {
                    attachDevice.set(v, attachDevice.get(u));
                    attachPort.set(v, attachPort.get(u));
                }
                kids.push(v);
                queue.push(v);
            }
            children.set(u, kids);
        }
    };

    const core = data && data.core !== undefined && data.core !== null && infos.has(String(data.core)) ? String(data.core) : null;
    const root = core || (roots.length ? roots[0].id : null);
    if (root !== null) search(root);
    const orphans = [];
    for (const info of roots) {
        if (depth.has(info.id)) continue;
        search(info.id);
        orphans.push(info.id);
    }
    orphans.sort((a, b) => treeCompareInfo(infos.get(a), infos.get(b)));

    const sp = { infos, root, orphans, parent, depth, children, port, peerPort, attachDevice, attachPort, coreFromServer: core !== null };
    infos.forEach(info => {
        info.title = treeTitle(sp, info);
        info.q = treeSearchText(sp, info);
    });
    return sp;
}

// treeGroupFilter is the filter of the checkboxes as a node predicate, the
// rule of app.js uiGroupShown: a node is hidden only when its group has a
// checkbox (filterable; every group when filterable is not given) and that
// checkbox is off. A node without a group counts as an endpoint.
function treeGroupFilter(enabled, filterable) {
    const on = new Set(enabled || []);
    const known = filterable ? new Set(filterable) : null;
    return node => {
        const group = node.group || 'endpoint';
        return on.has(group) || (known !== null && !known.has(group));
    };
}

// treeTitle is the tooltip of a row (plain text, escaped when the row is
// built): name, group and id, IPs, and the link to its parent in the
// spanning tree with the ports of both ends.
function treeTitle(sp, info) {
    const lines = [info.name, `${info.group} · ${info.id}`];
    if (info.ips.length) lines.push(info.ips.join(', '));
    const own = sp.port.get(info.id), peer = sp.peerPort.get(info.id), up = sp.parent.get(info.id);
    if (up !== null && up !== undefined && (own || peer)) {
        lines.push(`link: ${sp.infos.get(up).label}${own ? ' ' + own : ''} ↔ ${peer || '?'}`);
    }
    if (info.node.unreachable) lines.push('unreachable');
    return lines.join('\n');
}

// treeSearchText is what the device search matches in a row, lower case:
// id, name, addresses, the label lines (sysName holds the label's lines
// but the id), group and the port it hangs from.
function treeSearchText(sp, info) {
    const n = info.node;
    return [info.id, info.name, info.address, info.ips.join(' '), n.hostname, n.sysName || n.label,
        info.group, sp.port.get(info.id)].filter(Boolean).join('\n').toLowerCase();
}

// treeRowHTML is the text of a jsTree node: the group's colour and icon,
// the name, the IP or MAC, the port the row hangs from and the number of
// devices below it, apart by spaces (the row's plain text reads the same).
// Only escaped strings and constants go in.
function treeRowHTML(info, color, portText, count, title) {
    const unreachable = !!info.node.unreachable;
    const dot = unreachable ? treeUnreachableColor : (typeof color === 'string' && /^#[0-9A-Fa-f]{3,8}$/.test(color) ? color : treeDefaultColor);
    const icon = treeOwn(treeGroupIcons, info.group) || treeGroupIcons.unknown;
    const parts = [`<span class="tv-icon">${icon}</span>`, `<span class="tv-name">${treeEscapeHTML(info.name)}</span>`];
    if (info.address) parts.push(`<span class="tv-addr">${treeEscapeHTML(info.address)}</span>`);
    if (portText) parts.push(`<span class="tv-port">${treeEscapeHTML(portText)}</span>`);
    if (count) parts.push(treeCountHTML(count));
    return `<span class="tv-row${unreachable ? ' tv-unreachable' : ''}" title="${treeEscapeHTML(title)}">` +
        `<span class="tv-dot" style="background:${dot}"></span>${parts.join(' ')}</span>`;
}

// treeOwn is table[key] when the table has that key itself (a group named
// 'constructor' or '__proto__' finds nothing).
function treeOwn(table, key) {
    return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

function treeCountHTML(count) {
    return `<span class="tv-count" title="${count} device${count === 1 ? '' : 's'} below">${count}</span>`;
}

// treeProject turns the spanning tree into jsTree JSON (an array of top
// level nodes with nested children). shown is the filter: a node predicate
// (app.js uiGroupShown), a set or array of the groups shown, or null for
// every node. A hidden node's shown descendants move up to its nearest shown
// ancestor (to the top level when none is shown), so the tree keeps its
// shape; children are sorted again where they merge. A row shows the port it
// hangs from on its shown parent; a device whose port is on a hidden device
// in between (the hypervisor of a VM, the switch of a top-level device) shows
// that device's name with the port. Each row with shown devices below it
// counts them. The "Not connected" folder comes last, when it has shown
// devices. options.colors maps groups to colours (app.js groupColors).
function treeProject(sp, shown, options) {
    const colors = (options && options.colors) || {};
    const isShown = typeof shown === 'function' ? shown : (shown ? treeGroupFilter(shown) : () => true);

    // visit returns the rows of id's subtree that hang from visibleParent:
    // [{info, json, count}], one row when id is shown.
    const visit = (id, visibleParent) => {
        const info = sp.infos.get(id);
        const visible = isShown(info.node);
        let rows = [];
        for (const child of sp.children.get(id) || []) {
            const sub = visit(child, visible ? id : visibleParent);
            for (let i = 0; i < sub.length; i++) rows.push(sub[i]);
        }
        if (!visible) return rows;
        rows.sort((a, b) => treeCompareInfo(a.info, b.info));
        let count = 0;
        rows.forEach(r => { count += 1 + r.count; });

        // The port: on the shown parent, or on a hidden device in between,
        // named; none when it is the port of the parent's own row.
        let portText = '', title = info.title;
        const at = sp.attachDevice.get(id);
        if (at !== undefined) {
            if (at === visibleParent) portText = sp.attachPort.get(id);
            else if (visibleParent === null || sp.depth.get(at) > sp.depth.get(visibleParent)) {
                portText = `${sp.infos.get(at).label} ${sp.attachPort.get(id)}`;
                title += `\nplugged into ${portText}`;
            }
        }
        const json = {
            id: treeSafeId(id),
            text: treeRowHTML(info, treeOwn(colors, info.group), portText, count, title),
            children: rows.map(r => r.json),
            data: { node: id, q: info.q },
        };
        return [{ info, json, count }];
    };

    const top = sp.root === null ? [] : visit(sp.root, null);
    top.sort((a, b) => treeCompareInfo(a.info, b.info));
    const out = top.map(r => r.json);

    const lost = [];
    sp.orphans.forEach(id => {
        const sub = visit(id, null);
        for (let i = 0; i < sub.length; i++) lost.push(sub[i]);
    });
    if (lost.length) {
        lost.sort((a, b) => treeCompareInfo(a.info, b.info));
        let count = 0;
        lost.forEach(r => { count += 1 + r.count; });
        out.push({
            id: treeFolderId,
            text: `<span class="tv-row tv-folder" title="Devices with no link path to the core">` +
                `<span class="tv-icon">📁</span> <span class="tv-name">Not connected</span> ${treeCountHTML(count)}</span>`,
            children: lost.map(r => r.json),
            data: { folder: true, q: '' },
        });
    }
    return out;
}

// buildTopologyTree is the jsTree JSON of the graph data for a filter (see
// treeSpanning and treeProject).
function buildTopologyTree(data, shown, options) {
    return treeProject(treeSpanning(data), shown, options);
}

// ==================== Part 2: the Tree tab (browser) ====================

// jsTree's invisible root ($.jstree.root): the last of every row's parents.
const treeRootId = '#';

// The device search reaches the tree from 2 characters on, once the typing
// pauses: 1 character matches nearly every device, and each search redraws
// every row it shows (in Chrome, for the 1029 devices of the fixture, about
// 200 ms while the first characters of an IP match nearly all of them,
// 10 to 50 ms once the query picks a few).
const treeSearchMinLength = 2;
const treeSearchDelay = 400;

const treeState = {
    tab: 'graph',      // the visible tab: 'graph' or 'tree'
    stale: true,       // data or filters changed since the tree was last built
    instance: null,    // the jsTree instance, made on the first visit of the tab
    spanData: null,    // the rawData object span was built from
    span: null,        // treeSpanning(spanData)
    json: '',          // the JSON text of what jsTree shows (no refresh when unchanged)
    // The rows the user opened and selected, kept while a filter hides them,
    // so they are open and selected again when they are back.
    open: new Set(),
    selected: null,
    seeded: false,     // the first devices' top level was opened
    query: '',         // the device search applied to the tree ('' none)
    found: [],         // the rows that search found
    // The rows that search opened, which close again when it is replaced or
    // cleared (treeDropSearchRows). They are not in open, and leave this set
    // when the user closes them or opens every row.
    searchOpen: new Set(),
    searching: false,  // a jsTree search call is running (treeBySearch)
    loading: false,    // jsTree is (re)loading: the search waits for 'ready' or 'refresh'
    panelTimer: 0,     // a click's info panel waits for a possible double-click
    searchTimer: 0,
};

// selectViewTab shows the graph or the tree. The graph is only covered, never
// touched: its simulation, zoom, filters and selection stay as they are.
function selectViewTab(tab) {
    const tree = tab === 'tree';
    treeState.tab = tree ? 'tree' : 'graph';
    const stage = document.getElementById('viewStage');
    if (stage) stage.classList.toggle('tree-active', tree);
    const panel = document.getElementById('treeView');
    if (panel) panel.hidden = !tree;
    [['viewTabGraph', !tree], ['viewTabTree', tree]].forEach(([id, on]) => {
        const button = document.getElementById(id);
        if (!button) return;
        button.classList.toggle('active', on);
        button.setAttribute('aria-selected', String(on));
    });
    if (tree) {
        treeRender();
        treeApplySearch();
    } else {
        clearTimeout(treeState.panelTimer); // a click's info panel belongs to the tree
    }
}

// treeOnGraphChange runs after every /api/graph load and filter change
// (app.js uiNotifyViews). A hidden tree is only marked stale.
function treeOnGraphChange() {
    treeState.stale = true;
    if (treeState.tab === 'tree') treeRender();
}

// treeRender builds the tree when it is stale and shows it: on the first
// visit it makes the jsTree, later it refreshes it with the rows the user
// opened and selected that exist in the new tree, and its scroll position;
// nothing happens when the data jsTree would get is the same (the poll
// every 10 s mostly brings the same graph).
function treeRender() {
    const host = document.getElementById('topologyTree');
    if (!host || !treeState.stale) return;
    if (typeof jQuery === 'undefined' || !jQuery.jstree) {
        host.textContent = 'jsTree is not loaded (static/libs/jstree).';
        return;
    }
    treeState.stale = false;
    const data = rawData || { nodes: [], links: [] };
    if (treeState.spanData !== data) {
        treeState.span = treeSpanning(data);
        treeState.spanData = data;
    }
    updateFilterState(); // app.js: the checkboxes into filterState, which uiGroupShown reads
    const json = treeProject(treeState.span, uiGroupShown, { colors: groupColors });
    const text = JSON.stringify(json);
    treeShowStatus(json, rawData !== null);
    if (text === treeState.json && treeState.instance) return;
    treeState.json = text;
    // The first devices the tree gets start with their top level open (also
    // when the tab was opened before /api/graph answered).
    if (!treeState.seeded && json.length) {
        treeState.seeded = true;
        json.forEach(n => { if (n.id !== treeFolderId) treeState.open.add(n.id); });
    }

    const tree = treeState.instance;
    if (tree) {
        // A search hides and opens nodes; it is applied again on 'refresh'.
        if (treeState.query) {
            treeDropSearchRows(tree, []);
            treeBySearch(() => tree.clear_search());
        }
        treeState.query = '';
        treeState.loading = true;
        tree.settings.core.data = json;
        tree.refresh(true, state => {
            state.core.open = Array.from(new Set([...(state.core.open || []), ...treeState.open]));
            state.core.selected = treeState.selected ? [treeState.selected] : [];
            return state;
        });
        return;
    }
    json.forEach(n => { if (treeState.open.has(n.id)) n.state = { opened: true }; });
    treeState.loading = true;
    const $host = jQuery(host);
    $host.jstree({
        core: {
            data: json,
            multiple: false,
            animation: 0,
            dblclick_toggle: false, // a click toggles already
            worker: false,
            themes: { name: 'default', dots: true, icons: false },
        },
        plugins: ['search'],
        search: {
            case_sensitive: false,
            show_only_matches: true,
            show_only_matches_children: true,
            // The rows a search opened close again when it is replaced or
            // cleared, but tree.js closes them (treeDropSearchRows): jsTree
            // would close the rows above the device that stays in sight as
            // well, and after "Expand all" rows the user has open.
            close_opened_onclear: false,
            search_callback: treeSearchMatch,
        },
    });
    $host.on('activate_node.jstree', (e, d) => treeOnActivate(d.node));
    $host.on('dblclick', '.jstree-anchor', function () {
        treeShowInGraph(treeState.instance && treeState.instance.get_node(this));
    });
    $host.on('ready.jstree refresh.jstree', () => {
        treeState.loading = false;
        treeApplySearch();
    });
    // jsTree hides nothing when a search finds nothing: say so.
    $host.on('search.jstree', (e, d) => {
        treeState.found = d && Array.isArray(d.res) ? d.res.slice() : [];
        const n = treeState.found.length;
        treeShowSearchResult(n ? `${n} found` : `no device matches "${d ? d.str : ''}"`);
    });
    $host.on('clear_search.jstree', () => {
        treeState.found = [];
        treeShowSearchResult('');
    });
    // A row opened by a search is the search's, any other the user's.
    $host.on('open_node.jstree', (e, d) => (treeState.searching ? treeState.searchOpen : treeState.open).add(d.node.id));
    $host.on('close_node.jstree', (e, d) => treeForgetOpen([d.node.id]));
    $host.on('close_all.jstree', (e, d) => {
        if (!d.node || d.node.id === treeRootId) {
            treeState.open.clear();
            treeState.searchOpen.clear();
        } else {
            treeForgetOpen([d.node.id, ...(d.node.children_d || [])]);
        }
    });
    $host.on('changed.jstree', (e, d) => {
        if (d && d.event) treeState.selected = (d.selected && d.selected[0]) || null; // a user's click
        treeUpdateToolbar();
    });
    treeState.instance = $host.jstree(true);
}

// treeShowStatus writes the counts above the tree.
function treeShowStatus(json, loaded) {
    const el = document.getElementById('treeStatus');
    if (!el) return;
    if (!loaded) {
        el.textContent = 'Waiting for /api/graph ...';
        return;
    }
    let shown = 0, lost = 0;
    json.forEach(n => {
        const count = treeRowCount(n);
        shown += count;
        if (n.id === treeFolderId) lost = count;
    });
    const sp = treeState.span;
    const root = sp && sp.root !== null ? sp.infos.get(sp.root) : null;
    const total = sp ? sp.infos.size : 0;
    let text = `${shown} of ${total} devices shown`;
    if (root) text += ` · root: ${root.name}${sp.coreFromServer ? ' (core)' : ''}`;
    if (lost) text += ` · ${lost} not connected`;
    el.textContent = text;
}

// treeShowSearchResult writes the note next to the toolbar's buttons (the
// search's count, or why a device is not in the tree); a long one is cut,
// its tooltip has it all.
function treeShowSearchResult(text) {
    const el = document.getElementById('treeSearchStatus');
    if (!el) return;
    el.textContent = text;
    el.title = text;
}

// treeRowCount is the number of devices in a JSON row (the folder is none).
function treeRowCount(row) {
    let count = row.id === treeFolderId ? 0 : 1;
    (row.children || []).forEach(child => { count += treeRowCount(child); });
    return count;
}

function treeSearchMatch(str, node) {
    const q = node && node.data && node.data.q;
    return !!q && q.includes(String(str).trim().toLowerCase());
}

// treeApplySearch filters the tree by the device search box (Tree tab
// only), unless that search is already applied: a search redraws the tree.
// While jsTree loads, 'ready' or 'refresh' applies it once the rows are in.
// A search opens the rows above the devices it finds; they close again
// when the next search replaces it or the box is cleared, except that a
// cleared search leaves the selected device and the only device found in
// sight, if they are in sight then, and scrolls to the first.
function treeApplySearch() {
    const tree = treeState.instance;
    if (!tree || treeState.loading || treeState.tab !== 'tree') return;
    const input = document.getElementById('deviceSearch');
    const typed = input ? input.value.trim().toLowerCase() : '';
    const q = typed.length >= treeSearchMinLength ? typed : '';
    if (q !== treeState.query) {
        const kept = q ? [] : treeSearchKept(tree);
        treeDropSearchRows(tree, kept);
        treeState.query = q;
        treeBySearch(() => {
            if (q) tree.search(q);
            else tree.clear_search();
        });
        if (kept.length) treeScrollTo(kept[0]);
    }
    if (!q) treeShowSearchResult(typed ? `type ${treeSearchMinLength} or more characters to search the tree` : '');
}

// treeBySearch runs a jsTree search call: the rows it opens go to
// searchOpen, not to the user's open rows (the open_node handler).
function treeBySearch(call) {
    treeState.searching = true;
    try {
        call();
    } finally {
        treeState.searching = false;
    }
}

// treeDropSearchRows closes the rows the shown search opened, before it is
// replaced or cleared. The rows above a kept row stay open, as the user's.
function treeDropSearchRows(tree, kept) {
    const keep = new Set();
    kept.forEach(id => {
        const node = tree.get_node(id);
        if (node) node.parents.forEach(p => keep.add(p));
    });
    const close = [];
    treeState.searchOpen.forEach(id => {
        if (keep.has(id)) treeState.open.add(id);
        else close.push(id);
    });
    treeState.searchOpen.clear();
    if (close.length) tree.close_node(close, 0);
}

// treeForgetOpen: rows closed, by the user or by a search.
function treeForgetOpen(ids) {
    ids.forEach(id => {
        treeState.open.delete(id);
        treeState.searchOpen.delete(id);
    });
}

// treeSearchKept lists the rows that stay in sight when the search is
// cleared: the selected row and the only row the search found, each when it
// is in sight now.
function treeSearchKept(tree) {
    const ids = tree.get_selected();
    if (treeState.found.length === 1) ids.push(treeState.found[0]);
    return [...new Set(ids)].filter(id => treeInSight(tree, id));
}

// treeInSight tells whether a row is drawn: a search does not hide it and
// the rows above it are open.
function treeInSight(tree, id) {
    const node = tree.get_node(id);
    if (!node || node.state.hidden) return false;
    return node.parents.every(p => p === treeRootId || tree.is_open(p));
}

// treeScrollTo scrolls the tree to a row's own line, its anchor (the row's
// element holds the rows below it as well).
function treeScrollTo(id) {
    const el = document.getElementById(id + '_anchor') || document.getElementById(id);
    if (el && el.scrollIntoView) el.scrollIntoView({ block: 'nearest' });
}

// treeGraphNode is the /api/graph node of a jsTree node, or null.
function treeGraphNode(node) {
    const id = node && node.data ? node.data.node : undefined;
    if (id === undefined || !rawData || !Array.isArray(rawData.nodes)) return null;
    return rawData.nodes.find(n => String(n.id) === id) || null;
}

// A click on a row toggles it and selects it; the info panel opens unless
// the click turns out to be a double-click. It opens after the click has
// reached the document, where a click outside the panel closes it.
function treeOnActivate(node) {
    const tree = treeState.instance;
    if (!tree || !node) return;
    tree.toggle_node(node);
    const graphNode = treeGraphNode(node);
    clearTimeout(treeState.panelTimer);
    if (graphNode) treeState.panelTimer = setTimeout(() => showInfoPanel(graphNode), 250);
    treeUpdateToolbar();
}

// treeShowInGraph switches to the graph and focuses the node there.
function treeShowInGraph(node) {
    const graphNode = treeGraphNode(node);
    if (!graphNode) return;
    clearTimeout(treeState.panelTimer);
    closeInfoPanel(); // it would cover the node in the middle of the canvas
    selectViewTab('graph');
    treeFocusInGraph(String(graphNode.id));
}

function treeShowSelectedInGraph() {
    const tree = treeState.instance;
    if (tree) treeShowInGraph(tree.get_selected(true)[0]);
}

// treeFocusInGraph pans the graph to a drawn node and flashes it; a node the
// graph does not draw (its "Show Connected Devices" view shows other nodes)
// is shown with its neighbours, as a click in the info panel's list does.
function treeFocusInGraph(id) {
    const d = currentNodes.get(id);
    if (d && Number.isFinite(d.x) && Number.isFinite(d.y)) {
        panToDevice(d);
        if (typeof d3 !== 'undefined') {
            d3.selectAll('circle.node').filter(n => n.id === id)
                .classed('tree-focus', true)
                .transition().duration(300).attr('r', 36)
                .transition().duration(300).attr('r', 25)
                .transition().duration(300).attr('r', 36)
                .transition().duration(300).attr('r', 25)
                .on('end', function () { d3.select(this).classed('tree-focus', false); });
        }
    } else {
        highlightNodeFromPanel(id);
    }
}

// treeExpandAll opens every row. Every row is the user's then, also those
// the shown search had opened: they stay open when it is cleared.
function treeExpandAll() {
    if (!treeState.instance) return;
    treeState.instance.open_all();
    treeState.searchOpen.forEach(id => treeState.open.add(id));
    treeState.searchOpen.clear();
}

function treeCollapseAll() {
    if (treeState.instance) treeState.instance.close_all();
}

// treeUpdateToolbar enables "Show in graph" while a device is selected.
function treeUpdateToolbar() {
    const button = document.getElementById('treeShowInGraph');
    const tree = treeState.instance;
    if (button) button.disabled = !(tree && treeGraphNode(tree.get_selected(true)[0]));
}

// treeReveal selects a device in the tree and scrolls to it (a click in the
// device list, or in the info panel's list, while the Tree tab is shown):
// the rows above it open, and a search that hides it shows it. It is false
// when the tree does not have the device.
function treeReveal(id) {
    const tree = treeState.instance;
    if (!tree || id === undefined || id === null) return false;
    const tid = treeSafeId(id);
    const node = tree.get_node(tid);
    if (!node) return false;
    const hidden = [tid, ...node.parents].filter(p => p !== treeRootId && tree.is_hidden(p));
    if (hidden.length) tree.show_node(hidden);
    tree.deselect_all(true);
    tree.select_node(tid); // opens its parents
    treeState.selected = tid;
    treeScrollTo(tid);
    return true;
}

// treeOnPanelClick takes a click on a device in the info panel's "Connected
// Devices" list while the Tree tab is shown. The panel is the graph's, and
// app.js's listener on that list (uiOnNodeClick) shows the device's
// neighbourhood in the graph (highlightNodeFromPanel: "Show Connected" mode
// and a zoom), a graph the tab hides. This listener runs first (capture, on
// the same list) and stops the click: the device is selected in the tree
// instead, the graph's filter mode and zoom stay as they are, and the
// panel stays open, as on the graph. A device the tree does not have (a
// filter hides it) gets the reason in its line of the list (style.css
// tv-not-in-tree), which the panel may not leave the tree's toolbar room
// to show.
function treeOnPanelClick(event) {
    if (treeState.tab !== 'tree') return;
    const row = event.target && event.target.closest ? event.target.closest('[data-node-id]') : null;
    if (!row) return;
    event.stopPropagation();
    const id = row.getAttribute('data-node-id');
    const revealed = treeReveal(id);
    row.classList.toggle('tv-not-in-tree', !revealed);
    if (revealed) return;
    const info = treeState.span ? treeState.span.infos.get(String(id)) : undefined;
    const filtered = !!info && !uiGroupShown(info.node);
    row.setAttribute('data-tree-note', filtered ? `filtered out (${info.group})` : 'not in the tree');
    treeShowSearchResult(`${info ? info.label : id} is not in the tree` +
        (filtered ? `: its group (${info.group}) is filtered out` : ''));
}

if (typeof document !== 'undefined' && typeof window !== 'undefined') {
    if (typeof uiViewListeners !== 'undefined') uiViewListeners.push(treeOnGraphChange);
    const search = document.getElementById('deviceSearch');
    if (search) {
        search.addEventListener('input', () => {
            if (treeState.tab !== 'tree') return;
            clearTimeout(treeState.searchTimer);
            treeState.searchTimer = setTimeout(treeApplySearch, treeSearchDelay);
        });
    }
    const list = document.getElementById('deviceList');
    if (list) {
        list.addEventListener('click', event => {
            if (treeState.tab !== 'tree') return;
            const item = event.target.closest && event.target.closest('.device-item');
            if (item) treeReveal(item.dataset.deviceId);
        });
    }
    const neighbours = document.getElementById('infoNeighbors');
    if (neighbours) neighbours.addEventListener('click', treeOnPanelClick, true);
}
