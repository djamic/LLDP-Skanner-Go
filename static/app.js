let simulation = null;
let svg = null;
let g = null;
let rawData = null;
let zoom = null;

// State tracking (like reference implementation)
let currentNodes = new Map();
let currentLinks = new Map();

// Filter State
let filterState = {
    mode: 'ALL', // 'ALL' or 'CONNECTED'
    selectedNodeId: null,
    allowedGroups: new Set(), // populated from checkboxes
    checkboxGroups: new Set(), // groups that have a checkbox at all
    contextShowEndpoints: true
};

// Color scheme for the device groups the backend emits (dj_graph.go
// determineDeviceGroup); index.html has one filter checkbox with the same dot
// colour per group.
const groupColors = {
    'switch': '#4A90E2',
    'router': '#E24A4A',
    'hub': '#FF9800',
    'endpoint': '#8BC34A',
    'wifi_random': '#00BCD4',
    'vm': '#9C27B0',
    'hypervisor': '#26C6DA',  // teal-cyan
    'bmc':        '#FF6F00',  // amber — server management
    'server': '#FF5722',
    'camera': '#E91E63',
    'access_point': '#00BCD4',  // legend and report colour; not hub orange
    'printer': '#795548',
    'phone': '#3F51B5',
    'iot': '#607D8B',
    'unknown': '#9E9E9E'
};

// uiEscapeHTML makes a value safe inside innerHTML, as text or in a quoted
// attribute. Labels carry text that remote devices control (LLDP names, SNMP
// port names), so every server-provided string goes through it.
const uiHTMLEntities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function uiEscapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => uiHTMLEntities[ch]);
}

// Fetch and render network data
async function loadNetworkData() {
    try {
        const response = await fetch('/api/graph');
        const data = await response.json();

        if (data.error) {
            showError(data.error);
            return;
        }

        rawData = data;
        updateTopology(data); // Use incremental update like reference
        updateStats(data);
        updateDeviceList();
        hideLoading();

    } catch (error) {
        showError('Failed to load network data: ' + error.message);
    }
}

// Fields d3 keeps on a node object (layout and drag); the rest is /api/graph data.
const uiSimFields = new Set(['x', 'y', 'vx', 'vy', 'fx', 'fy', 'index']);

// uiNodeText is the text drawn under a node.
// E.4: hostname priority — hostname > sysName > label > id
function uiNodeText(d) {
    return d.hostname || d.sysName || d.label || d.id;
}

// uiIsIPv4 accepts a dotted quad with octets 0-255.
function uiIsIPv4(s) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    return !!m && m.slice(1).every(octet => Number(octet) <= 255);
}

// uiNodeIPs lists the node's own addresses: the id when it is an IP, then
// every label line that is exactly an IPv4 address, in label order (the
// SNMP/ARP IP comes first; enrichGraphWithIPs appends the cache IP after it).
// A "VMs: a, b" line (a hypervisor's guests) or SysDesc text is not the
// node's address. Connect, History and the info panel all use ips[0].
function uiNodeIPs(node) {
    const ips = node.ip ? [node.ip] : [];
    (node.sysName || node.label || '').split('\n').forEach(line => {
        const s = line.trim();
        if (uiIsIPv4(s) && !ips.includes(s)) ips.push(s);
    });
    return ips;
}

// uiRenderNodeLabel (re)builds the tspans of one node label when its text
// changed, so later IP/DNS/ESXi enrichment shows up on the canvas.
function uiRenderNodeLabel(el, d) {
    const displayText = uiNodeText(d);
    if (el.__uiText === displayText) return;
    el.__uiText = displayText;
    const textEl = d3.select(el);
    textEl.selectAll('tspan').remove();
    displayText.split('\n').forEach((line, i) => {
        textEl.append('tspan')
            .attr('x', 0)
            .attr('dy', i === 0 ? '1.5em' : '1.1em')
            .text(line);
    });
}

// Incremental topology update (based on reference implementation)
function updateTopology(newData) {
    const filteredData = getFilteredData(newData);
    let changed = false;

    // Track which nodes should exist after filtering
    const targetNodeIds = new Set(filteredData.nodes.map(n => n.id));

    // Add new nodes (preserve existing positions)
    filteredData.nodes.forEach(node => {
        if (!currentNodes.has(node.id)) {
            // Initialize position near center for new nodes
            node.x = window.innerWidth / 2 + (Math.random() - 0.5) * 100;
            node.y = window.innerHeight / 2 + (Math.random() - 0.5) * 100;
            currentNodes.set(node.id, node);
            changed = true;
        } else {
            // Update existing node data (but preserve x, y)
            const existing = currentNodes.get(node.id);
            // Detect property changes that require re-render (canvas text included)
            if (existing.unreachable !== node.unreachable ||
                existing.group !== node.group ||
                uiNodeText(existing) !== uiNodeText(node) ||
                JSON.stringify(existing.anomalies) !== JSON.stringify(node.anomalies)) {
                changed = true;
            }
            // Fields the server now omits (omitempty: hostname, anomalies, ...)
            // must not stay behind; only the simulation's own fields are kept.
            for (const key of Object.keys(existing)) {
                if (!(key in node) && !uiSimFields.has(key)) delete existing[key];
            }
            Object.assign(existing, node, { x: existing.x, y: existing.y });
        }
    });

    // Remove nodes that are filtered out
    for (const [id, node] of currentNodes) {
        if (!targetNodeIds.has(id)) {
            currentNodes.delete(id);
            changed = true;
        }
    }

    // Track which links should exist
    const targetLinkKeys = new Set(filteredData.links.map(l =>
        `${l.source.id || l.source}-${l.target.id || l.target}`
    ));

    // Add new links
    filteredData.links.forEach(link => {
        const key = `${link.source.id || link.source}-${link.target.id || link.target}`;
        if (!currentLinks.has(key)) {
            currentLinks.set(key, link);
            changed = true;
        } else {
            // Detect link property changes
            const existing = currentLinks.get(key);
            if (existing.unreachable !== link.unreachable ||
                existing.label !== link.label) {
                changed = true;
            }
            currentLinks.set(key, link);
        }
    });

    // Remove links that are filtered out
    for (const [key, link] of currentLinks) {
        if (!targetLinkKeys.has(key)) {
            currentLinks.delete(key);
            changed = true;
        }
    }

    // Only re-render if something changed
    if (changed) {
        renderGraph();
    }
}

// Update filter state from UI
function updateFilterState() {
    // Read all checkbox filters
    const allowed = new Set();
    const withCheckbox = new Set();
    document.querySelectorAll('.filter-cb input[data-group]').forEach(cb => {
        withCheckbox.add(cb.dataset.group);
        if (cb.checked) allowed.add(cb.dataset.group);
    });
    filterState.allowedGroups = allowed;
    filterState.checkboxGroups = withCheckbox;

    // Context menu checkbox
    filterState.contextShowEndpoints = document.getElementById('contextShowEndpoints')?.checked ?? true;
}

// uiGroupShown: a node is hidden only by an unchecked checkbox of its group;
// a group without a checkbox is always drawn instead of vanishing silently.
function uiGroupShown(n) {
    const group = n.group || 'endpoint';
    return filterState.allowedGroups.has(group) || !filterState.checkboxGroups.has(group);
}

function getFilteredData(data) {
    updateFilterState();
    let filteredNodes = data.nodes;

    const selected = filterState.selectedNodeId;
    if (filterState.mode === 'CONNECTED' && selected && data.nodes.some(n => n.id === selected)) {
        // Only the selected node and its direct neighbours; 'Show Endpoints'
        // off also drops endpoint and random-MAC neighbours.
        const connectedToSelected = new Set();
        data.links.forEach(l => {
            const s = l.source.id || l.source;
            const t = l.target.id || l.target;
            if (s === selected) connectedToSelected.add(t);
            if (t === selected) connectedToSelected.add(s);
        });

        filteredNodes = filteredNodes.filter(n => {
            if (n.id === selected) return true;
            if (!connectedToSelected.has(n.id) || !uiGroupShown(n)) return false;
            return filterState.contextShowEndpoints || (n.group !== 'endpoint' && n.group !== 'wifi_random');
        });
    } else {
        filteredNodes = filteredNodes.filter(uiGroupShown);
    }

    const nodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredLinks = data.links.filter(l =>
        nodeIds.has(l.source.id || l.source) &&
        nodeIds.has(l.target.id || l.target)
    );

    return { nodes: filteredNodes, links: filteredLinks };
}

function applyFilters() {
    if (rawData) {
        updateTopology(rawData);
        updateStats(rawData);
    }
}

// Render the network (incremental)
function renderGraph() {
    const container = document.getElementById('network');
    const width = container.clientWidth;
    const height = container.clientHeight;

    const nodes = Array.from(currentNodes.values());
    const links = Array.from(currentLinks.values());

    // Initialize SVG and zoom on first render
    if (!svg || !g) {
        svg = d3.select('#network')
            .attr('width', width)
            .attr('height', height);

        zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                g.attr('transform', event.transform);
            });

        svg.call(zoom);
        g = svg.append('g');
    }

    // Initialize or update simulation
    if (!simulation) {
        simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links)
                .id(d => d.id)
                .distance(150))
            .force('charge', d3.forceManyBody().strength(-400))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(40));
    } else {
        // Update simulation with current data
        simulation.nodes(nodes);
        simulation.force('link').links(links);
        simulation.alpha(0.3).restart(); // Gentle restart
    }

    // UPDATE LINKS
    const link = g.selectAll('line.link')
        .data(links, d => `${d.source.id || d.source}-${d.target.id || d.target}`);

    link.exit().remove();

    const linkEnter = link.enter()
        .append('line')
        .attr('class', 'link')
        .attr('stroke', '#3a5a7c')
        .attr('stroke-opacity', 0.7)
        .attr('stroke-width', 2);

    // Helper: check if link is MAC-REF (not LLDP-discovered)
    const isMacRef = d => {
        const label = (d.label || d.sourceLabel || '');
        return label.includes('MAC-REF');
    };

    const linkUpdate = linkEnter.merge(link)
        .attr('class', d => {
            if (d.unreachable) return 'link link-unreachable';
            if (isMacRef(d)) return 'link link-macref';
            return 'link';
        })
        .attr('stroke', d => {
            if (d.unreachable) return '#ff4444';
            if (isMacRef(d)) return '#FF9800';  // orange for MAC-REF
            return '#3a5a7c';
        })
        .attr('stroke-dasharray', d => {
            if (d.unreachable) return '5,5';
            if (isMacRef(d)) return '8,4';  // longer dash for MAC-REF
            return null;
        })
        .attr('stroke-opacity', d => {
            if (d.unreachable) return 0.5;
            if (isMacRef(d)) return 0.6;
            return 0.7;
        })
        .attr('stroke-width', d => isMacRef(d) ? 1.5 : 2);

    // UPDATE SOURCE LABELS
    const sourceLinkLabel = g.selectAll('text.source-label')
        .data(links, d => `${d.source.id || d.source}-${d.target.id || d.target}`);

    sourceLinkLabel.exit().remove();

    const sourceLabelEnter = sourceLinkLabel.enter()
        .append('text')
        .attr('class', 'link-label source-label')
        .attr('font-size', '11px')
        .attr('fill', '#2196F3')
        .attr('font-weight', 'bold');

    // Text on enter and update: the backend rewrites traffic labels every 30 s
    const sourceLabelUpdate = sourceLabelEnter.merge(sourceLinkLabel)
        .text(d => d.sourceLabel || '');

    // UPDATE TARGET LABELS
    const targetLinkLabel = g.selectAll('text.target-label')
        .data(links, d => `${d.source.id || d.source}-${d.target.id || d.target}`);

    targetLinkLabel.exit().remove();

    const targetLabelEnter = targetLinkLabel.enter()
        .append('text')
        .attr('class', 'link-label target-label')
        .attr('font-size', '11px')
        .attr('fill', '#F44336')
        .attr('font-weight', 'bold');

    const targetLabelUpdate = targetLabelEnter.merge(targetLinkLabel)
        .text(d => d.targetLabel || '');

    // UPDATE NODES
    const node = g.selectAll('circle.node')
        .data(nodes, d => d.id);

    node.exit().remove();

    const nodeEnter = node.enter()
        .append('circle')
        .attr('class', 'node')
        .attr('r', 25)
        .attr('stroke', '#0d1b2a')
        .attr('stroke-width', 3)
        .call(d3.drag()
            .on('start', dragstarted)
            .on('drag', dragged)
            .on('end', dragended))
        .on('click', (event, d) => {
            event.stopPropagation();
            showInfoPanel(d);
        })
        .on('contextmenu', (event, d) => {
            event.preventDefault();
            showContextMenu(event, d);
        });

    const nodeUpdate = nodeEnter.merge(node)
        .attr('fill', d => groupColors[d.group] || '#9E9E9E');

    // UPDATE NODE LABELS
    const nodeLabel = g.selectAll('text.node-label')
        .data(nodes, d => d.id);

    nodeLabel.exit().remove();

    const nodeLabelEnter = nodeLabel.enter()
        .append('text')
        .attr('class', 'node-label')
        .attr('text-anchor', 'middle')
        .attr('font-size', '12px')
        .attr('font-weight', 'bold')
        .attr('fill', '#333');

    // Multi-line labels on enter and update (rebuilt only when the text changed)
    const nodeLabelUpdate = nodeLabelEnter.merge(nodeLabel)
        .each(function (d) { uiRenderNodeLabel(this, d); });

    // E.2 + Phase 8: Apply anomaly/unreachable glow classes
    nodeUpdate
        .attr('fill', d => d.unreachable ? '#ff4444' : (groupColors[d.group] || '#9E9E9E'))
        .attr('class', d => {
            let cls = 'node';
            // Phase 8: Unreachable takes highest priority
            if (d.unreachable) cls += ' anomaly-unreachable';
            else if (d.anomalies && d.anomalies.includes('loopback')) cls += ' anomaly-loopback';
            else if (d.anomalies && (d.anomalies.includes('shadow_it') || d.anomalies.includes('congestion'))) cls += ' anomaly-shadow';
            return cls;
        });

    // Update positions on tick
    simulation.on('tick', () => {
        linkUpdate
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        sourceLabelUpdate
            .attr('x', d => d.source.x + (d.target.x - d.source.x) * 0.25)
            .attr('y', d => d.source.y + (d.target.y - d.source.y) * 0.25);

        targetLabelUpdate
            .attr('x', d => d.source.x + (d.target.x - d.source.x) * 0.75)
            .attr('y', d => d.source.y + (d.target.y - d.source.y) * 0.75);

        nodeUpdate
            .attr('cx', d => d.x)
            .attr('cy', d => d.y);

        nodeLabelUpdate
            .attr("transform", d => `translate(${d.x},${d.y})`);
    });
}

// Drag functions
function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

// Update device list
function updateDeviceList() {
    const deviceList = document.getElementById('deviceList');
    if (!deviceList) return;

    deviceList.innerHTML = '';

    const sortedDevices = Array.from(currentNodes.values()).sort((a, b) => {
        const aName = a.sysName || a.ip || a.id;
        const bName = b.sysName || b.ip || b.id;
        return aName.localeCompare(bName);
    });

    sortedDevices.forEach(device => {
        const item = document.createElement('div');
        item.className = 'device-item';
        item.dataset.deviceId = device.id;

        const name = document.createElement('div');
        name.className = 'device-name';
        name.textContent = device.sysName || device.id;

        const ip = document.createElement('div');
        ip.className = 'device-ip';
        ip.textContent = device.ip || device.id;

        item.appendChild(name);
        item.appendChild(ip);

        item.addEventListener('click', () => panToDevice(device));

        deviceList.appendChild(item);
    });

    // Setup search
    const searchInput = document.getElementById('deviceSearch');
    if (searchInput && !searchInput.dataset.initialized) {
        searchInput.dataset.initialized = 'true';
        searchInput.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            document.querySelectorAll('.device-item').forEach(item => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(query) ? 'block' : 'none';
            });
        });
    }
}

// Pan to device
function panToDevice(device) {
    if (!device.x || !device.y || !svg || !zoom) return;

    const container = document.getElementById('network');
    const width = container.clientWidth;
    const height = container.clientHeight;

    const scale = 1.5;
    const x = width / 2 - device.x * scale;
    const y = height / 2 - device.y * scale;

    svg.transition()
        .duration(750)
        .call(zoom.transform, d3.zoomIdentity.translate(x, y).scale(scale));
}

// Update statistics
function updateStats(data) {
    document.getElementById('nodeCount').textContent = `Nodes: ${data.nodes.length}`;
    document.getElementById('linkCount').textContent = `Links: ${data.links.length}`;

    // Update filter counters
    updateFilterCounts(data);

    // E.1: Update Health Score widget
    if (data.health_score !== undefined) {
        updateHealthWidget(data.health_score);
    }

    // E.5: Update Status Bar
    updateStatusBar(data);
}

// Update device type counters in filter bar
function updateFilterCounts(data) {
    const counts = {};
    (data.nodes || []).forEach(n => {
        const g = n.group || 'unknown';
        counts[g] = (counts[g] || 0) + 1;
    });
    // every group the backend emits, printer/server/unknown included
    Object.keys(groupColors).forEach(g => {
        const el = document.getElementById('fc-' + g);
        if (el) el.textContent = counts[g] || 0;
    });
}

// E.1: Health Score Widget update
function updateHealthWidget(score) {
    const scoreEl = document.getElementById('healthScoreVal');
    const barEl   = document.getElementById('healthBarFill');
    const sbEl    = document.getElementById('sbHealth');
    if (!scoreEl) return;

    const val = Math.max(0, Math.min(100, Math.round(score)));
    scoreEl.textContent = val;
    if (sbEl) sbEl.textContent = val + '/100';

    // Color class
    scoreEl.className = 'health-score';
    if (val >= 90)      scoreEl.classList.add('good');
    else if (val >= 70) scoreEl.classList.add('warning');
    else                scoreEl.classList.add('danger');

    // Progress bar: position maps score 0→100 to left edge→right edge
    if (barEl) {
        barEl.style.width = val + '%';
        // Slide gradient: low score = red (right side), high = green (left side)
        // background-position 100%=red, 0%=green
        const bgPos = (100 - val) + '% 0';
        barEl.style.backgroundPosition = bgPos;
    }

    // Update sb-health color
    const sbSpan = document.querySelector('.sb-health span');
    if (sbSpan) {
        sbSpan.style.color = val >= 90 ? '#4CAF50' : val >= 70 ? '#FF9800' : '#F44336';
    }
}

// E.5: Status Bar update
function updateStatusBar(data) {
    const sbSwitches  = document.getElementById('sbSwitches');
    const sbMACs      = document.getElementById('sbMACs');
    const sbAnomalies = document.getElementById('sbAnomalies');
    const sbLastScan  = document.getElementById('sbLastScan');

    if (sbSwitches) {
        const switchCount = (data.nodes || []).filter(n => n.group === 'switch' || n.group === 'router').length;
        sbSwitches.textContent = switchCount;
    }
    if (sbMACs) {
        sbMACs.textContent = data.total_macs !== undefined ? data.total_macs : (data.nodes || []).length;
    }
    if (sbAnomalies) {
        const anomalyCount = (data.nodes || []).filter(n => n.anomalies && n.anomalies.length > 0).length;
        sbAnomalies.textContent = anomalyCount;
        // Color: red if any anomalies
        const sbAnomalyEl = document.querySelector('.sb-anomaly span');
        if (sbAnomalyEl) sbAnomalyEl.style.color = anomalyCount > 0 ? '#F44336' : '#4CAF50';
    }
    if (sbLastScan) {
        sbLastScan.textContent = new Date().toLocaleTimeString();
    }
}

// Show error message
function showError(message) {
    const errorDiv = document.getElementById('error');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    hideLoading();
}

// Hide loading indicator
function hideLoading() {
    document.getElementById('loading').style.display = 'none';
}

// Refresh data
function refreshData() {
    loadNetworkData();
}

// Reset view to show all devices
function resetView() {
    filterState.mode = 'ALL';
    filterState.selectedNodeId = null;

    if (rawData) {
        updateTopology(rawData);
        updateStats(rawData);
    }
}

// Auto-refresh every 10 seconds
setInterval(refreshData, 10000);

// Initial load
loadNetworkData();

// ==================== Events Panel ====================

function toggleEvents() {
    const panel = document.getElementById('eventsPanel');
    const toggle = document.getElementById('eventsToggle');
    panel.classList.toggle('collapsed');
    toggle.textContent = panel.classList.contains('collapsed') ? '▶' : '▼';
}

function loadEvents() {
    fetch('/api/events')
        .then(res => res.json())
        .then(data => {
            const list = document.getElementById('eventsList');
            if (!list) return;

            const events = data.events || [];
            if (events.length === 0) {
                list.innerHTML = '<div class="event-empty">No events yet</div>';
                return;
            }

            const icons = {
                'join': '🟢',
                'leave': '🔴',
                'host_up': '🆕',
                'host_down': '❌',
                'anomaly': '⚠️',
                'fixed': '✅'
            };

            list.innerHTML = events.slice(0, 100).map(evt => {
                const icon = icons[evt.type] || '📋';
                const typeClass = evt.type === 'join' || evt.type === 'host_up' || evt.type === 'fixed'
                    ? 'event-good' : 'event-bad';
                return `<div class="event-item ${typeClass}">
                    <span class="event-icon">${icon}</span>
                    <div class="event-content">
                        <div class="event-msg">${uiEscapeHTML(evt.message)}</div>
                        <div class="event-time">${uiEscapeHTML(evt.time)}</div>
                    </div>
                </div>`;
            }).join('');
        })
        .catch(() => { });
}

// Poll events every 10 seconds
loadEvents();
setInterval(loadEvents, 10000);

// Context menu state
let selectedNodeId = null;
let contextMenuVisible = false;

// Hide context menu when clicking anywhere
document.addEventListener('click', (e) => {
    if (!e.target.closest('.context-menu') && !e.target.closest('.node')) {
        hideContextMenu();
    }
});

// Show context menu
function showContextMenu(event, node) {
    const menu = document.getElementById('contextMenu');
    selectedNodeId = node.id;

    // Position menu at mouse location (using clientX/Y for fixed positioning)
    menu.style.left = event.clientX + 'px';
    menu.style.top = event.clientY + 'px';
    menu.style.display = 'block';

    contextMenuVisible = true;
}

// Hide context menu
function hideContextMenu() {
    const menu = document.getElementById('contextMenu');
    menu.style.display = 'none';
    contextMenuVisible = false;
    selectedNodeId = null;
}

// Show connected devices for selected node
function showConnectedDevices(closeMenu = true) {
    if (!selectedNodeId || !rawData) {
        if (closeMenu) hideContextMenu();
        return;
    }

    // Set filter state
    filterState.mode = 'CONNECTED';
    filterState.selectedNodeId = selectedNodeId;

    // Update graph (logic inside getFilteredData handles the filtering)
    updateTopology(rawData);
    updateStats(rawData);

    if (closeMenu) hideContextMenu();
}

// Update filters while context menu is open
function updateContextFilters() {
    // Checkboxes are just settings - do nothing here
    // They will be applied when "Show Connected Devices" is clicked
}

// View history for selected device
function viewHistory() {
    if (!selectedNodeId || !rawData) {
        hideContextMenu();
        return;
    }

    // Find the node to get its own IP (never a VM IP from a 'VMs:' line)
    const node = rawData.nodes.find(n => n.id === selectedNodeId);
    if (node) {
        const ip = uiNodeIPs(node)[0];

        if (ip) {
            window.location.href = `/history.html?id=${encodeURIComponent(ip)}`;
        } else {
            alert('No IP address available for this device');
        }
    }
    hideContextMenu();
}

// Connect to device (SSH/Telnet) via web terminal — opens modal directly
let connectedDeviceIP = null;

function connectToDevice() {
    if (!selectedNodeId || !rawData) {
        hideContextMenu();
        return;
    }

    const node = rawData.nodes.find(n => n.id === selectedNodeId);
    if (node) {
        const ip = uiNodeIPs(node)[0];

        if (ip) {
            connectedDeviceIP = ip;
            const deviceName = node.sysName || node.label?.split('\n')[0] || ip;
            document.getElementById('connDeviceName').textContent = `${deviceName} (${ip})`;
            document.getElementById('connModal').style.display = 'flex';
            document.getElementById('portScanResults').innerHTML =
                '<div class="port-scan-item scanning">⏳ Scanning ports...</div>';
            scanDevicePorts(ip);
        } else {
            alert('No IP address available for this device');
        }
    }
    hideContextMenu();
}

function closeConnectModal() {
    document.getElementById('connModal').style.display = 'none';
}

async function scanDevicePorts(ip) {
    try {
        const res = await fetch(`/api/check-ports?id=${ip}`);
        const data = await res.json();
        const container = document.getElementById('portScanResults');
        container.innerHTML = '';

        const protocols = [
            { key: 'ssh', name: 'SSH', port: data.ssh_port || 22, open: data.ssh },
            { key: 'telnet', name: 'Telnet', port: data.telnet_port || 23, open: data.telnet },
            { key: 'http', name: 'HTTP', port: data.http_port || 80, open: data.http },
            { key: 'https', name: 'HTTPS', port: data.https_port || 443, open: data.https },
        ];

        let firstOpen = null;
        protocols.forEach(p => {
            const item = document.createElement('div');
            item.className = `port-scan-item ${p.open ? 'open' : 'closed'}`;
            item.textContent = `${p.open ? '✅' : '❌'} ${p.name} (:${p.port})`;
            item.onclick = () => {
                document.getElementById('connProto').value = p.key;
                document.getElementById('connPort').value = p.port;
                onProtoChange();
                container.querySelectorAll('.port-scan-item').forEach(el => el.classList.remove('selected'));
                item.classList.add('selected');
            };
            container.appendChild(item);
            if (p.open && !firstOpen) firstOpen = p;
        });

        if (firstOpen) {
            document.getElementById('connProto').value = firstOpen.key;
            document.getElementById('connPort').value = firstOpen.port;
            onProtoChange();
        }
    } catch (err) {
        document.getElementById('portScanResults').innerHTML =
            '<div class="port-scan-item closed">❌ Port scan failed</div>';
    }
}

function onProtoChange() {
    const proto = document.getElementById('connProto').value;
    const portMap = { ssh: 22, telnet: 23, http: 80, https: 443 };
    const credRow = document.getElementById('credentialsRow');
    credRow.style.display = (proto === 'http' || proto === 'https') ? 'none' : 'flex';
    if (proto !== 'custom' && portMap[proto]) {
        document.getElementById('connPort').value = portMap[proto];
    }
}

function doConnect() {
    const ip = connectedDeviceIP;
    const proto = document.getElementById('connProto').value;
    const port = document.getElementById('connPort').value;
    const user = document.getElementById('connUser').value;
    const pass = document.getElementById('connPass').value;
    closeConnectModal();

    if (proto === 'http') { window.open(`http://${ip}:${port}`, '_blank'); return; }
    if (proto === 'https') { window.open(`https://${ip}:${port}`, '_blank'); return; }

    openTerminal(ip, proto === 'custom' ? 'telnet' : proto, port, user, pass);
}

// ===== xterm.js Terminal =====
let term = null, termWs = null, fitAddon = null;

function openTerminal(ip, proto, port, user, pass) {
    const container = document.getElementById('terminalContainer');
    container.style.display = 'flex';
    document.getElementById('termTitle').textContent = `${ip} via ${proto.toUpperCase()}:${port}`;
    document.getElementById('termInfo').textContent = `${user}@${ip}:${port}`;

    if (term) { term.dispose(); term = null; }
    if (termWs) { termWs.close(); termWs = null; }
    document.getElementById('terminalBox').innerHTML = '';

    term = new Terminal({
        cursorBlink: true, fontSize: 14,
        fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
        theme: {
            background: '#0d1b2a', foreground: '#e0e0e0', cursor: '#4A90E2',
            selectionBackground: '#264f78',
            black: '#0d1b2a', red: '#f44336', green: '#4CAF50', yellow: '#FF9800',
            blue: '#4A90E2', magenta: '#CE93D8', cyan: '#4DD0E1', white: '#e0e0e0',
            brightBlack: '#546E7A', brightRed: '#ef9a9a', brightGreen: '#81C784',
            brightYellow: '#FFB74D', brightBlue: '#64B5F6', brightMagenta: '#F48FB1',
            brightCyan: '#80DEEA', brightWhite: '#ffffff',
        },
        scrollback: 5000, convertEol: true,
    });

    fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(document.getElementById('terminalBox'));
    setTimeout(() => fitAddon.fit(), 100);

    const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProto}//${location.host}/api/terminal?id=${encodeURIComponent(ip)}&proto=${proto}&port=${port}&user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}&cols=${term.cols}&rows=${term.rows}`;

    termWs = new WebSocket(wsUrl);
    termWs.binaryType = 'arraybuffer';
    termWs.onopen = () => term.focus();
    termWs.onmessage = (evt) => {
        term.write(evt.data instanceof ArrayBuffer ? new Uint8Array(evt.data) : evt.data);
    };
    termWs.onclose = () => term.write('\r\n\x1b[33m--- Connection closed ---\x1b[0m\r\n');
    termWs.onerror = () => term.write('\r\n\x1b[31m--- WebSocket error ---\x1b[0m\r\n');
    term.onData((data) => { if (termWs && termWs.readyState === WebSocket.OPEN) termWs.send(data); });
}

function disconnectTerminal() {
    if (termWs) { termWs.close(); termWs = null; }
    if (term) { term.dispose(); term = null; }
    document.getElementById('terminalContainer').style.display = 'none';
    document.getElementById('terminalBox').innerHTML = '';
}

// Drag, Minimize, Maximize
let isTermMaximized = false, savedTermPos = null;

(function initTermDrag() {
    let isDragging = false, offsetX, offsetY;
    document.addEventListener('mousedown', (e) => {
        const header = document.getElementById('terminalHeader');
        if (!header || !header.contains(e.target) || e.target.tagName === 'BUTTON') return;
        const c = document.getElementById('terminalContainer');
        isDragging = true;
        const rect = c.getBoundingClientRect();
        offsetX = e.clientX - rect.left; offsetY = e.clientY - rect.top;
        e.preventDefault();
    });
    document.addEventListener('mousemove', (e) => {
        if (!isDragging) return;
        const c = document.getElementById('terminalContainer');
        c.style.bottom = 'auto'; c.style.right = 'auto';
        c.style.left = (e.clientX - offsetX) + 'px'; c.style.top = (e.clientY - offsetY) + 'px';
        e.preventDefault();
    });
    document.addEventListener('mouseup', () => { isDragging = false; });
})();

function toggleTermMinimize() {
    const c = document.getElementById('terminalContainer');
    c.classList.toggle('minimized');
    if (!c.classList.contains('minimized') && fitAddon) setTimeout(() => fitAddon.fit(), 50);
}

function toggleTermMaximize() {
    const c = document.getElementById('terminalContainer');
    if (isTermMaximized) {
        if (savedTermPos) {
            c.style.top = savedTermPos.top; c.style.left = savedTermPos.left;
            c.style.bottom = savedTermPos.bottom; c.style.right = savedTermPos.right;
            c.style.width = savedTermPos.width; c.style.height = savedTermPos.height;
        }
        c.style.borderRadius = '12px'; isTermMaximized = false;
    } else {
        savedTermPos = { top: c.style.top, left: c.style.left, bottom: c.style.bottom,
            right: c.style.right, width: c.style.width, height: c.style.height };
        c.style.top = '0'; c.style.left = '0'; c.style.bottom = '0'; c.style.right = '0';
        c.style.width = '100vw'; c.style.height = '100vh'; c.style.borderRadius = '0';
        isTermMaximized = true;
    }
    c.classList.remove('minimized');
    if (fitAddon) setTimeout(() => fitAddon.fit(), 100);
}

if (typeof ResizeObserver !== 'undefined') {
    new ResizeObserver(() => {
        if (fitAddon && term) try { fitAddon.fit(); } catch(e) {}
    }).observe(document.getElementById('terminalBox') || document.body);
}

// Tag lines whose text after the tag is the vendor (label contract).
const uiVendorTags = ['[ENDPOINT]', '[LLDP-EP]', '[WiFi]'];
// "[VM] <os>[ <vendor>]": the OS label is an emoji plus one word or "<word> VM"
// ('🐧 Linux', '💻 VMware VM'); "[VM] <vendor>" has no OS label.
const uiVMOSPattern = /^([^\x00-\x7F]\S*\s+(?:\S+\s+VM(?=\s|$)|\S+))\s*(.*)$/u;

// uiParseNodeInfo reads the backend label lines for the info panel: vendor,
// detail (BMC type, VM OS, hypervisor/hub text), the DNS name and the first
// name line. It reads sysName, the full label: label drops the tag lines when
// a DNS name exists. IP lines (uiNodeIPs) and "VMs:" lines are not names.
function uiParseNodeInfo(node) {
    const out = { vendor: '', detail: '', name: '', hostname: node.hostname || '' };
    let typeText = '';    // [HYPERVISOR] text, e.g. 'VMware ESXi' or 'HPE ProLiant Server'
    let brand = '';       // vendor named by a BMC type, e.g. 'Fujitsu' in 'Fujitsu iRMC'
    let ownTag = false;   // a device tag line ([ENDPOINT], [VM], [BMC], ...) was seen
    (node.sysName || node.label || '').split('\n').forEach(raw => {
        const line = raw.trim();
        const tag = uiVendorTags.find(t => line.startsWith(t));
        if (tag) {
            ownTag = true;
            if (!out.vendor) out.vendor = line.slice(tag.length).trim();
        } else if (line.startsWith('[VM]')) {
            ownTag = true;
            const rest = line.slice('[VM]'.length).trim();
            const m = rest.match(uiVMOSPattern);
            if (!out.detail && m) out.detail = m[1];
            if (!out.vendor) out.vendor = m ? m[2] : rest;
        } else if (line.startsWith('[BMC]')) {
            ownTag = true;
            // "[BMC] <type>[ <vendor>]"; the type is 'BMC', 'IPMI' or '<brand> <product>'
            const words = line.slice('[BMC]'.length).trim().split(/\s+/).filter(Boolean);
            const typeLen = (words[0] === 'BMC' || words[0] === 'IPMI') ? 1 : Math.min(2, words.length);
            if (!out.detail) out.detail = words.slice(0, typeLen).join(' ');
            if (!out.vendor) out.vendor = words.slice(typeLen).join(' ');
            if (typeLen === 2 && !brand) brand = words[0];
        } else if (line.startsWith('[HYPERVISOR]') || line.startsWith('[HUB]')) {
            const text = line.slice(line.indexOf(']') + 1).trim();
            if (!out.detail) out.detail = text;
            if (line.startsWith('[HYPERVISOR]') && !typeText) typeText = text;
        } else if (line.startsWith('[DNS]')) {
            if (!out.hostname) out.hostname = line.slice('[DNS]'.length).trim();
        } else if (line && !line.startsWith('[') && !uiIsIPv4(line) && !line.startsWith('VMs:')) {
            if (!out.name) out.name = line;
        }
    });
    // No vendor text: fall back to what a type names — the brand of a BMC
    // type, the server vendor of '[HYPERVISOR] HPE ProLiant Server', or the
    // platform of a synthetic hypervisor node that has no tag line of its own
    // ('VMware ESXi'); a physical ESXi host keeps its unknown hardware vendor.
    if (!out.vendor) {
        if (brand) out.vendor = brand;
        else if (/\sServer$/.test(typeText)) out.vendor = typeText.replace(/\s+Server$/, '');
        else if (!ownTag) out.vendor = typeText;
    }
    return out;
}

// uiLinkPorts gives the clicked node's own port and the peer's port on one
// link. GetGraphData splits "<srcPort>|<dstPort>" into sourceLabel and
// targetLabel; 'Hub' (switch->hub links) is a placeholder, not a port.
function uiLinkPorts(link, nodeId) {
    const port = s => (s || '').split('[MAC-REF]')[0].trim();
    const src = port(link.sourceLabel);
    const dst = link.targetLabel === 'Hub' ? '' : port(link.targetLabel);
    return (link.source.id || link.source) === nodeId ? { own: src, peer: dst } : { own: dst, peer: src };
}

// uiPortKey drops the speed and traffic suffix so that links on one port
// group together: 'TGE1/0/52 [T] 10G ↓13M ↑29M' -> 'TGE1/0/52 [T]'.
function uiPortKey(label) {
    return label.replace(/\s+(?:\d+[MGmg]\b|[↓↑]).*$/, '').trim();
}

function showInfoPanel(node) {
    const panel = document.getElementById('infoPanel');
    if (!panel) return;

    // Parse node info (vendor, detail, DNS name, name line)
    const type = node.group || 'unknown';
    const info = uiParseNodeInfo(node);
    const sysName = info.hostname || info.name;
    // Same address as Connect and History; further IP lines are listed after it
    const ips = uiNodeIPs(node);

    // Get connected devices — grouped by this node's own port on each link
    const portMap = {}; // portKey → [{id, name, group}]
    if (rawData && rawData.links) {
        rawData.links.forEach(link => {
            const srcId = link.source.id || link.source;
            const tgtId = link.target.id || link.target;
            if (srcId !== node.id && tgtId !== node.id) return;
            const peerId = srcId === node.id ? tgtId : srcId;

            // On the target side the own port is targetLabel, not the peer's
            // sourceLabel. A node without a port of its own on the link
            // (endpoint, hub) is grouped under the peer's port, marked as such.
            const ports = uiLinkPorts(link, node.id);
            const own = uiPortKey(ports.own), peer = uiPortKey(ports.peer);
            const portKey = own || (peer ? `${peer} (peer)` : '—');

            const peerNode = rawData.nodes.find(n => n.id === peerId);
            const peerLabel = peerNode ? (peerNode.label?.split('\n')[0] || peerId.substring(0, 22)) : peerId.substring(0, 22);
            const peerGroup = peerNode?.group || 'endpoint';

            if (!portMap[portKey]) portMap[portKey] = [];
            portMap[portKey].push({ id: peerId, name: peerLabel, group: peerGroup });
        });
    }

    // Sort ports naturally: GE1/0/1 < GE1/0/2 etc.
    const sortedPorts = Object.keys(portMap).sort((a, b) => {
        const numA = a.match(/(\d+)/g)?.map(Number) || [];
        const numB = b.match(/(\d+)/g)?.map(Number) || [];
        for (let i = 0; i < Math.max(numA.length, numB.length); i++) {
            const diff = (numA[i] || 0) - (numB[i] || 0);
            if (diff !== 0) return diff;
        }
        return a.localeCompare(b);
    });

    const totalConnections = Object.values(portMap).reduce((s, arr) => s + arr.length, 0);

    // Format type for display ('Wi-Fi AP' is access_point everywhere; the
    // randomised-MAC group is 'Random MAC', as in the filter bar and the report)
    const typeNames = {
        'switch': '🔀 Switch', 'router': '🌐 Router', 'hub': '🔌 Hub',
        'endpoint': '💻 Endpoint', 'wifi_random': '🎲 Random MAC',
        'vm': '🖥️ VM', 'hypervisor': '🏗️ Hypervisor', 'bmc': '🔧 BMC',
        'server': '🖲️ Server', 'camera': '📹 Camera',
        'access_point': '📡 Wi-Fi AP', 'printer': '🖨️ Printer',
        'phone': '📱 Phone', 'iot': '🔌 IoT', 'unknown': '❓ Unknown'
    };
    const groupIcons = { 'switch':'🔀','router':'🌐','hub':'🔌','endpoint':'💻',
        'wifi_random':'🎲','vm':'🖥️','hypervisor':'🏗️','bmc':'🔧','server':'🖲️',
        'access_point':'📡','camera':'📹','printer':'🖨️','phone':'📱','iot':'🔌','unknown':'❓' };

    // Update panel content
    document.getElementById('infoPanelTitle').textContent = sysName || node.id;
    document.getElementById('infoType').textContent = (typeNames[type] || type) + (info.detail ? ` · ${info.detail}` : '');
    document.getElementById('infoMAC').textContent = node.id;
    document.getElementById('infoVendor').textContent = info.vendor || 'Unknown';
    document.getElementById('infoIP').textContent = ips.length === 0 ? 'Not available'
        : ips[0] + (ips.length > 1 ? ` (also ${ips.slice(1).join(', ')})` : '');
    document.getElementById('infoSysName').textContent = sysName || node.id;
    document.getElementById('infoConnections').textContent = totalConnections;

    // Phase 8: Show unreachable status
    const statusEl = document.getElementById('infoStatus');
    if (statusEl) {
        if (node.unreachable) {
            let lastSeenText = 'Unknown';
            if (node.lastSeen) {
                const diff = Math.round((Date.now() - new Date(node.lastSeen).getTime()) / 60000);
                lastSeenText = diff < 60 ? `${diff} min ago` : `${Math.round(diff/60)}h ago`;
            }
            statusEl.innerHTML = `<span style="color:#ff4444;font-weight:bold">🔴 UNREACHABLE</span> <span style="color:#888;font-size:11px">Last seen: ${uiEscapeHTML(lastSeenText)}</span>`;
            statusEl.style.display = 'block';
        } else {
            statusEl.innerHTML = '<span style="color:#4CAF50;font-weight:bold">🟢 Online</span>';
            statusEl.style.display = 'block';
        }
    }

    // Build neighbors list — grouped by port, click highlights node
    const neighborsList = document.getElementById('infoNeighbors');
    if (sortedPorts.length === 0) {
        neighborsList.innerHTML = '<div class="info-list-item" style="justify-content:center;color:#6c8ab0">No connections</div>';
    } else {
        neighborsList.innerHTML = sortedPorts.map(portKey => {
            const peers = portMap[portKey];
            const peersHTML = peers.map(peer => {
                const icon = groupIcons[peer.group] || '❓';
                const shortName = peer.name.length > 28 ? peer.name.substring(0, 26) + '…' : peer.name;
                return `<div class="info-list-item info-peer-item" data-node-id="${uiEscapeHTML(peer.id)}"
                    title="${uiEscapeHTML(peer.id)}\nClick to highlight"
                    style="cursor:pointer; padding-left:20px; font-size:12px; background:rgba(255,255,255,0.03); margin:2px 0; border-radius:4px; border-left:2px solid rgba(74,144,226,0.3);">
                    <span>${icon} ${uiEscapeHTML(shortName)}</span>
                    <span style="color:#6c8ab0;font-size:10px">${uiEscapeHTML(peer.group)}</span>
                </div>`;
            }).join('');
            return `
                <div class="info-port-group" style="margin-bottom:6px;">
                    <div style="font-size:11px; font-weight:600; color:#4A90E2; padding:3px 0 2px; 
                        border-bottom:1px solid rgba(74,144,226,0.2); display:flex; 
                        justify-content:space-between; align-items:center;">
                        <span>🔌 ${uiEscapeHTML(portKey)}</span>
                        <span style="color:#6c8ab0">${peers.length} device${peers.length>1?'s':''}</span>
                    </div>
                    ${peersHTML}
                </div>`;
        }).join('');
    }

    // Show panel
    panel.style.display = 'block';

    // Add backdrop click listener
    document.addEventListener('click', handleBackdropClick);
}

// Highlight a node from info panel click
function highlightNodeFromPanel(nodeId) {
    if (!simulation) return;
    // Select node in graph
    selectedNodeId = nodeId;
    filterState.mode = 'CONNECTED';
    filterState.selectedNodeId = nodeId;
    updateTopology(rawData);
    // Scroll/zoom to node
    const nodeData = simulation.nodes().find(n => n.id === nodeId);
    if (nodeData && svg && zoom) {
        const svgEl = svg.node().parentElement;
        const w = svgEl.clientWidth, h = svgEl.clientHeight;
        const scale = 2;
        const tx = w/2 - nodeData.x * scale;
        const ty = h/2 - nodeData.y * scale;
        svg.transition().duration(600)
            .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
    }
}

// Close info panel
function closeInfoPanel() {
    const panel = document.getElementById('infoPanel');
    if (panel) {
        panel.style.display = 'none';
    }
    document.removeEventListener('click', handleBackdropClick);
}

// Handle clicks outside panel to close it
function handleBackdropClick(event) {
    const panel = document.getElementById('infoPanel');
    if (panel && !panel.contains(event.target)) {
        closeInfoPanel();
    }
}

// Rows built with innerHTML carry the node id in an escaped data-node-id
// attribute instead of an inline onclick; one listener per list hands the id
// to the action.
function uiOnNodeClick(listId, action, stopPropagation) {
    const list = document.getElementById(listId);
    if (!list) return;
    list.addEventListener('click', event => {
        const row = event.target.closest?.('[data-node-id]');
        if (!row) return;
        if (stopPropagation) event.stopPropagation();
        action(row.getAttribute('data-node-id'));
    });
}
uiOnNodeClick('infoNeighbors', id => highlightNodeFromPanel(id), true);

// ==================== Settings Management ====================

// Open settings modal
function openSettings() {
    // Fetch current settings
    fetch('/api/settings')
        .then(res => res.json())
        .then(settings => {
            document.getElementById('settingsIPRanges').value = (settings.ipRanges || []).join('\n');
            document.getElementById('settingsCommunity').value = settings.community || 'public';
            document.getElementById('settingsTimeout').value = settings.timeout || 20;
            document.getElementById('settingsMaxWorkers').value = settings.maxWorkers || 50;
            document.getElementById('settingsUsePing').checked = settings.usePing || false;
            document.getElementById('settingsModal').style.display = 'flex';
        })
        .catch(err => {
            console.error('Failed to load settings:', err);
            document.getElementById('settingsModal').style.display = 'flex';
        });
}

// Close settings modal
function closeSettings() {
    document.getElementById('settingsModal').style.display = 'none';
}

// Save settings
function saveSettings() {
    const settings = {
        ipRanges: document.getElementById('settingsIPRanges').value
            .split('\n')
            .map(s => s.trim())
            .filter(s => s.length > 0),
        community: document.getElementById('settingsCommunity').value || 'public',
        timeout: parseInt(document.getElementById('settingsTimeout').value) || 20,
        maxWorkers: parseInt(document.getElementById('settingsMaxWorkers').value) || 50,
        usePing: document.getElementById('settingsUsePing').checked
    };

    fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'ok') {
                alert('✅ Settings saved successfully!');
                closeSettings();
            } else {
                alert('❌ Failed to save settings: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(err => {
            alert('❌ Error saving settings: ' + err.message);
        });
}

// Rescan connections
function rescanConnections() {
    if (!confirm('🔄 Start rescan of all hosts?\n\nThis will refresh connection data from all saved hosts.')) {
        return;
    }

    fetch('/api/rescan', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'ok') {
                alert('✅ Rescan started! Graph will update automatically.');
            } else {
                alert('❌ Failed to start rescan');
            }
        })
        .catch(err => {
            alert('❌ Error: ' + err.message);
        });
}

// Clean all hosts
function cleanHosts() {
    if (!confirm('🗑️ Clear all saved hosts?\n\n⚠️ This will remove all network data.\nThe application will need to rescan to discover devices.')) {
        return;
    }

    fetch('/api/hosts', { method: 'DELETE' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'ok') {
                alert('✅ All hosts cleared successfully!\n\nClick "Rescan Connections" to discover devices again.');
                // Clear local graph
                rawData = { nodes: [], links: [] };
                updateTopology(rawData);
                updateStats(rawData);
            } else {
                alert('❌ Failed to clear hosts');
            }
        })
        .catch(err => {
            alert('❌ Error: ' + err.message);
        });
}

// Close settings on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeSettings();
        closeInfoPanel();
        closeMermaid();
        closeShadowIT();
    }
});

// ==================== Capture & Analysis ====================

let activeSessionId = null;

// Start Capture
function startCapture() {
    const name = prompt("Enter session name:", "Session_" + new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-"));
    if (!name) return;

    fetch(`/api/capture/start?name=${encodeURIComponent(name)}`, { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'started') {
                activeSessionId = data.session_id;
                alert(`🔴 Capture Started!\nID: ${data.session_id}`);
                // Toggle buttons
                document.querySelector('button[onclick="startCapture()"]').style.display = 'none';
                document.querySelector('button[onclick="stopCapture()"]').style.display = 'block';
            } else {
                alert('❌ Failed to start: ' + (data.message || 'Unknown error'));
            }
        })
        .catch(err => alert('❌ Error: ' + err.message));
}

// Stop Capture
function stopCapture() {
    if (!confirm("⏹️ Stop capturing and save data?")) return;

    fetch('/api/capture/stop', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'completed') {
                activeSessionId = data.session_id; // Update just in case
                alert(`✅ Capture Saved!\nID: ${data.session_id}`);
                // Toggle buttons back
                document.querySelector('button[onclick="startCapture()"]').style.display = 'inline-block';
                document.querySelector('button[onclick="stopCapture()"]').style.display = 'none';

                // Ask to generate report
                if (confirm("📊 Do you want to generate a report now?")) {
                    generateReport(activeSessionId);
                }
            } else {
                alert('❌ Failed to stop: ' + (data.message || 'Unknown error'));
            }
        })
        .catch(err => alert('❌ Error: ' + err.message));
}

// Generate Report (Open Modal)
function generateReport() {
    openReportsModal();
}

function openReportsModal() {
    const modal = document.getElementById('reportsModal');
    const select = document.getElementById('reportSessionSelect');

    modal.style.display = 'flex';
    select.innerHTML = '<option>Loading...</option>';
    document.getElementById('reportPreview').style.display = 'none';

    fetch('/api/captures')
        .then(res => res.json())
        .then(data => {
            select.innerHTML = '';
            const sessions = data.sessions || [];

            if (sessions.length === 0) {
                select.innerHTML = '<option value="">No captures found</option>';
                return;
            }

            // Sort by time desc
            sessions.sort((a, b) => new Date(b.start_time) - new Date(a.start_time));

            sessions.forEach(s => {
                const opt = document.createElement('option');
                opt.value = s.id;
                const timeStr = new Date(s.start_time).toLocaleString();
                opt.textContent = `${s.name} (${timeStr})`;
                select.appendChild(opt);
            });
        })
        .catch(err => {
            select.innerHTML = '<option>Error loading sessions</option>';
            console.error(err);
        });
}

function closeReports() {
    document.getElementById('reportsModal').style.display = 'none';
}

function downloadWordReport() {
    const select = document.getElementById('reportSessionSelect');
    const id = select.value;
    if (!id) {
        alert("Please select a session first.");
        return;
    }
    // Trigger download
    window.location.href = `/api/report/download?id=${id}`;
}

function generateReportFromSelection() {
    const select = document.getElementById('reportSessionSelect');
    const id = select.value;

    if (!id) {
        alert("Please select a session first.");
        return;
    }

    const btn = document.querySelector('#reportsModal .btn-primary');
    const originalText = btn.textContent;
    btn.textContent = "⏳ Generating...";
    btn.disabled = true;

    fetch(`/api/report/generate?id=${id}`, { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            if (data.text_summary) {
                document.getElementById('reportPreview').style.display = 'block';
                document.getElementById('reportContent').textContent = data.text_summary;
            } else {
                alert('❌ Failed to generate report');
            }
        })
        .catch(err => alert('❌ Error: ' + err.message))
        .finally(() => {
            btn.textContent = originalText;
            btn.disabled = false;
        });
}

// Simple Report Modal (Reuse Settings Modal structure or create new on fly)
function showReportModal(text) {
    // Legacy function support - redirect to new modal logic specific for quick view?
    // Not needed if we use the main reportsModal
}

// Check for active capture on load
function checkActiveCapture() {
    fetch('/api/captures')
        .then(res => res.json())
        .then(data => {
            if (data.active) {
                activeSessionId = data.active.id;
                console.log("Found active session:", activeSessionId);
                // Update UI
                const startBtn = document.querySelector('button[onclick="startCapture()"]');
                const stopBtn = document.querySelector('button[onclick="stopCapture()"]');
                if (startBtn && stopBtn) {
                    startBtn.style.display = 'none';
                    stopBtn.style.display = 'inline-block';
                    stopBtn.title = `Stop Capture (Started: ${new Date(data.active.start_time).toLocaleTimeString()})`;
                }
            }
        })
        .catch(err => console.error("Failed to check capture status:", err));
}

// Initialize
checkActiveCapture();

// ============================================================
// G.5 — Experiments Panel
// ============================================================

let expPollInterval = null;

function openExperiments() {
    document.getElementById('experimentsModal').style.display = 'flex';
    pollExperimentStatus();
}

function closeExperiments() {
    document.getElementById('experimentsModal').style.display = 'none';
    if (expPollInterval) {
        clearInterval(expPollInterval);
        expPollInterval = null;
    }
}

function toggleDurationField() {
    const mode = document.getElementById('expMode').value;
    document.getElementById('durationGroup').style.display = mode === 'monitor24h' ? 'block' : 'none';
}

function startExperiment() {
    const mode = document.getElementById('expMode').value;
    const expID = document.getElementById('expID').value || 'exp_' + Date.now();
    const workers = parseInt(document.getElementById('expWorkers').value) || 50;
    const duration = document.getElementById('expDuration').value || '24h';

    fetch('/api/experiment/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode, exp_id: expID, workers, duration })
    })
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
                return;
            }
            document.getElementById('expStartBtn').style.display = 'none';
            document.getElementById('expStopBtn').style.display = 'inline-block';
            document.getElementById('expStatus').style.display = 'block';
            document.getElementById('expStatusText').textContent = 'Starting...';

            // Start polling
            if (expPollInterval) clearInterval(expPollInterval);
            expPollInterval = setInterval(pollExperimentStatus, 2000);
        })
        .catch(err => alert('Failed to start: ' + err));
}

function stopExperiment() {
    fetch('/api/experiment/stop', { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            document.getElementById('expStartBtn').style.display = 'inline-block';
            document.getElementById('expStopBtn').style.display = 'none';
            document.getElementById('expStatusText').textContent = 'Stopped';
            if (expPollInterval) {
                clearInterval(expPollInterval);
                expPollInterval = null;
            }
        })
        .catch(err => console.error('Stop failed:', err));
}

function pollExperimentStatus() {
    fetch('/api/experiment/status')
        .then(r => r.json())
        .then(data => {
            const statusDiv = document.getElementById('expStatus');
            const statusText = document.getElementById('expStatusText');
            const elapsedText = document.getElementById('expElapsed');

            if (data.running) {
                statusDiv.style.display = 'block';
                statusText.textContent = data.progress || 'Running...';
                elapsedText.textContent = data.elapsed || '-';
                document.getElementById('expStartBtn').style.display = 'none';
                document.getElementById('expStopBtn').style.display = 'inline-block';
            } else {
                if (data.progress === 'Completed' || data.progress === 'Cancelled') {
                    statusDiv.style.display = 'block';
                    statusText.textContent = data.progress;
                    elapsedText.textContent = '-';
                }
                document.getElementById('expStartBtn').style.display = 'inline-block';
                document.getElementById('expStopBtn').style.display = 'none';
                if (expPollInterval) {
                    clearInterval(expPollInterval);
                    expPollInterval = null;
                }
            }
        })
        .catch(() => { });
}

function loadExperimentResults() {
    const listDiv = document.getElementById('expResultsList');
    listDiv.innerHTML = '<div style="color: #888;">Loading...</div>';

    fetch('/api/experiment/results')
        .then(r => r.json())
        .then(data => {
            if (!data.files || data.files.length === 0) {
                listDiv.innerHTML = '<div style="color: #888;">No results found</div>';
                return;
            }
            listDiv.innerHTML = data.files.map(f => `
            <div style="padding: 6px 10px; border-bottom: 1px solid #1a2a3a; display: flex; justify-content: space-between; align-items: center;">
                <span style="color: #e0e0e0; font-size: 13px;">📄 ${uiEscapeHTML(f.name)}</span>
                <span style="color: #666; font-size: 11px;">${uiEscapeHTML((f.size / 1024).toFixed(1))} KB · ${uiEscapeHTML(f.modified)}</span>
            </div>
        `).join('');
        })
        .catch(err => {
            listDiv.innerHTML = '<div style="color: #E24A4A;">Error loading results</div>';
        });
}

// ============================================================
// Shadow IT Detection (Unmanaged Switches)
// ============================================================

function showShadowIT() {
    if (!rawData || !rawData.nodes || rawData.nodes.length === 0) {
        alert('❌ No network data available.');
        return;
    }

    // Find shadow IT nodes: hubs, unmanaged switches — but NOT VMware/hypervisor-related
    const shadowNodes = rawData.nodes.filter(n => {
        const label = (n.label || '').toLowerCase();
        const sysName = (n.sysName || '').toLowerCase();

        // EXCLUDE: hypervisors, VMs, ESXi hosts, BMC — these are legitimate
        if (n.group === 'hypervisor' || n.group === 'vm' || n.group === 'bmc') return false;
        if (label.includes('[hypervisor]') || label.includes('vmware esxi')) return false;
        if (label.includes('[vm]') || label.includes('vmware')) return false;

        // Hub nodes — only include if NOT a VM-related hub
        if (n.group === 'hub' || label.includes('[hub]') || label.includes('unmanaged')) {
            // Check if this hub's connected nodes are VMs/hypervisors
            const connectedNodes = rawData.links
                .filter(l => (l.source.id || l.source) === n.id || (l.target.id || l.target) === n.id)
                .map(l => {
                    const otherId = (l.source.id || l.source) === n.id
                        ? (l.target.id || l.target) : (l.source.id || l.source);
                    return rawData.nodes.find(nn => nn.id === otherId);
                })
                .filter(Boolean);

            // If any connected node is a hypervisor or VM, skip this hub
            const hasVMConnection = connectedNodes.some(cn => {
                const cl = (cn.label || '').toLowerCase();
                return cn.group === 'hypervisor' || cn.group === 'vm' ||
                    cl.includes('[hypervisor]') || cl.includes('vmware') || cl.includes('[vm]');
            });
            if (hasVMConnection) return false;

            return true; // legitimate shadow IT hub
        }

        // Other shadow-labeled nodes
        if (label.includes('shadow')) return true;

        return false;
    });

    // Group by parent switch
    const bySwitch = {};
    shadowNodes.forEach(node => {
        // Find which switch this node connects to
        const parentLink = rawData.links.find(l => {
            const tgtId = l.target.id || l.target;
            const srcId = l.source.id || l.source;
            return tgtId === node.id || srcId === node.id;
        });
        let switchName = 'Unknown';
        if (parentLink) {
            const otherId = (parentLink.source.id || parentLink.source) === node.id
                ? (parentLink.target.id || parentLink.target)
                : (parentLink.source.id || parentLink.source);
            const switchNode = rawData.nodes.find(n => n.id === otherId);
            if (switchNode) {
                switchName = (switchNode.sysName || switchNode.label || switchNode.id).split('\n')[0];
            }
        }
        if (!bySwitch[switchName]) bySwitch[switchName] = [];
        bySwitch[switchName].push(node);
    });

    const list = document.getElementById('shadowITList');

    if (shadowNodes.length === 0) {
        list.innerHTML = `<div style="text-align:center; padding:30px; color:#4CAF50;">
            <div style="font-size:48px; margin-bottom:12px;">✅</div>
            <strong>Shadow IT topilmadi!</strong><br>
            <span style="color:#888;">Barcha qurilmalar boshqariladigan switchlarga ulangan.</span>
        </div>`;
    } else {
        let html = `<div style="color:#E24A4A; margin-bottom:12px; font-weight:bold;">
            ⚠️ ${shadowNodes.length} ta boshqarilmaydigan qurilma topildi:
        </div>`;

        for (const [switchName, nodes] of Object.entries(bySwitch)) {
            html += `<div class="shadow-switch-group">
                <div class="shadow-switch-name">📡 ${uiEscapeHTML(switchName)}</div>`;

            nodes.forEach(node => {
                const label = (node.label || node.id).replace(/\n/g, ' · ');
                const port = (() => {
                    const link = rawData.links.find(l =>
                        (l.target.id || l.target) === node.id ||
                        (l.source.id || l.source) === node.id
                    );
                    return link ? (link.sourcePort || link.targetPort || '') : '';
                })();

                html += `<div class="shadow-item" data-node-id="${uiEscapeHTML(node.id)}">
                    <span class="shadow-icon">👻</span>
                    <div class="shadow-info">
                        <div class="shadow-label">${uiEscapeHTML(label)}</div>
                        ${port ? `<div class="shadow-port">Port: ${uiEscapeHTML(port)}</div>` : ''}
                    </div>
                    <span class="shadow-goto">→</span>
                </div>`;
            });

            html += '</div>';
        }
        list.innerHTML = html;
    }

    document.getElementById('shadowITModal').style.display = 'flex';
}

function focusShadowNode(nodeId) {
    closeShadowIT();
    // Find the node with x,y coordinates from the simulation
    if (!simulation) return;
    const node = simulation.nodes().find(n => n.id === nodeId);
    if (node) {
        panToDevice(node);
        // Flash the node
        d3.selectAll('.node-group')
            .filter(d => d.id === nodeId)
            .select('circle')
            .transition().duration(200).attr('r', 20).style('stroke', '#FF0')
            .transition().duration(200).attr('r', 25).style('stroke', '#FF0')
            .transition().duration(200).attr('r', 20).style('stroke', '#FF0')
            .transition().duration(500).attr('r', d => d.group === 'switch' ? 10 : 6).style('stroke', null);
    }
}

uiOnNodeClick('shadowITList', id => focusShadowNode(id));

function closeShadowIT() {
    document.getElementById('shadowITModal').style.display = 'none';
}

// ============================================================
// Mermaid Export (Switches Only)
// ============================================================

let mermaidCode = '';

async function exportMermaid() {
    if (!rawData || !rawData.nodes || rawData.nodes.length === 0) {
        alert('❌ No network data available. Please wait for scan to complete.');
        return;
    }

    // Filter: only switches and routers
    const switchNodes = rawData.nodes.filter(n =>
        n.group === 'switch' || n.group === 'router'
    );

    if (switchNodes.length === 0) {
        alert('❌ No switches found in current data.');
        return;
    }

    const switchIds = new Set(switchNodes.map(n => n.id));

    // Filter links: both ends must be switch/router
    const switchLinks = rawData.links.filter(l => {
        const srcId = l.source.id || l.source;
        const tgtId = l.target.id || l.target;
        return switchIds.has(srcId) && switchIds.has(tgtId);
    });

    // Build Mermaid code in simple format: graph TD; A-->B; C-->D;

    // Create short readable IDs from sysName or IP
    const nodeIdMap = new Map(); // original id -> short name
    const usedNames = new Set();

    switchNodes.forEach(node => {
        const label = node.label || node.sysName || node.id;
        const labelLines = label.split('\n');
        let shortName = labelLines[0] || node.id;
        // Remove brackets like [SWITCH], clean up
        shortName = shortName.replace(/\[.*?\]\s*/g, '').trim();
        // If empty or too long, try IP
        if (!shortName || shortName.length > 20) {
            shortName = node.ip || node.id;
        }
        // Sanitize for Mermaid (only alphanumeric and underscore)
        shortName = shortName.replace(/[^a-zA-Z0-9_]/g, '_').replace(/_+/g, '_');
        // Ensure unique
        let finalName = shortName;
        let counter = 2;
        while (usedNames.has(finalName)) {
            finalName = `${shortName}_${counter++}`;
        }
        usedNames.add(finalName);
        nodeIdMap.set(node.id, finalName);
    });

    let parts = ['graph TD'];

    // Add edges
    switchLinks.forEach(link => {
        const srcId = nodeIdMap.get(link.source.id || link.source);
        const tgtId = nodeIdMap.get(link.target.id || link.target);
        if (srcId && tgtId) {
            parts.push(`  ${srcId}-->${tgtId};`);
        }
    });

    // Add isolated nodes (no edges)
    const connectedIds = new Set();
    switchLinks.forEach(link => {
        connectedIds.add(link.source.id || link.source);
        connectedIds.add(link.target.id || link.target);
    });
    switchNodes.forEach(node => {
        if (!connectedIds.has(node.id)) {
            parts.push(`  ${nodeIdMap.get(node.id)};`);
        }
    });

    mermaidCode = parts.join('\n');

    // Show modal
    document.getElementById('mermaidModal').style.display = 'flex';
    document.getElementById('mermaidRawCode').textContent = mermaidCode;

    // Render Mermaid diagram
    const diagramArea = document.getElementById('mermaidDiagramArea');
    diagramArea.innerHTML = '<div style="color: #888;">Rendering diagram...</div>';

    try {
        // Initialize mermaid
        mermaid.initialize({
            startOnLoad: false,
            theme: 'default',
            securityLevel: 'loose',
            flowchart: {
                useMaxWidth: true,
                htmlLabels: true,
                curve: 'basis'
            }
        });

        const renderId = 'mermaidGraph_' + Date.now();
        const { svg } = await mermaid.render(renderId, mermaidCode);
        // Safe as markup: mermaidCode holds only node names reduced to [A-Za-z0-9_] above.
        diagramArea.innerHTML = svg;
    } catch (err) {
        console.error('Mermaid render error:', err);
        diagramArea.innerHTML = `<div style="color: #E24A4A; padding: 20px;">
            ⚠️ Render error: ${uiEscapeHTML(err.message || 'Unknown error')}
            <br><br>
            <small style="color: #888;">Raw code is available below.</small>
        </div>`;
    }
}

function closeMermaid() {
    document.getElementById('mermaidModal').style.display = 'none';
}

function copyMermaidCode() {
    if (!mermaidCode) {
        alert('No Mermaid code to copy.');
        return;
    }

    // Use textarea fallback (works on HTTP, not just HTTPS)
    const textarea = document.createElement('textarea');
    textarea.value = mermaidCode;
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    textarea.style.top = '-9999px';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();

    try {
        document.execCommand('copy');
        // Visual feedback on button
        const btn = document.querySelector('#mermaidModal .btn-primary');
        const original = btn.textContent;
        btn.textContent = '✅ Copied!';
        btn.style.background = '#4CAF50';
        setTimeout(() => {
            btn.textContent = original;
            btn.style.background = '';
        }, 2000);
    } catch (err) {
        alert('❌ Copy failed: ' + err.message);
    }

    document.body.removeChild(textarea);
}

// ============================================================
// E.6: Events Panel (Snapshot Diff — Recent Changes)
// ============================================================

function toggleEvents() {
    const panel = document.getElementById('eventsPanel');
    const toggle = document.getElementById('eventsToggle');
    if (!panel) return;
    panel.classList.toggle('collapsed');
    if (toggle) {
        toggle.textContent = panel.classList.contains('collapsed') ? '▶' : '◀';
    }
    // Fetch events when expanding
    if (!panel.classList.contains('collapsed')) {
        fetchEvents();
    }
}

let eventsLastCount = 0;

function fetchEvents() {
    fetch('/api/events')
        .then(r => r.json())
        .then(data => {
            const events = data.events || [];
            renderEvents(events);
            // Update badge if new events appeared
            if (events.length > eventsLastCount && eventsLastCount > 0) {
                const h3 = document.querySelector('#eventsPanel h3');
                if (h3 && document.getElementById('eventsPanel').classList.contains('collapsed')) {
                    h3.style.color = '#4CAF50';
                    setTimeout(() => { h3.style.color = ''; }, 3000);
                }
            }
            eventsLastCount = events.length;
        })
        .catch(() => {});
}

function renderEvents(events) {
    const list = document.getElementById('eventsList');
    if (!list) return;

    if (events.length === 0) {
        list.innerHTML = '<div class="event-empty">Waiting for events...</div>';
        return;
    }

    const iconMap = {
        'join': '🟢', 'leave': '🔴', 'host_up': '🆕', 'host_down': '❌',
        'anomaly': '⚠️', 'fixed': '✅'
    };
    const classMap = {
        'join': 'event-good', 'host_up': 'event-good', 'fixed': 'event-good',
        'leave': 'event-bad', 'host_down': 'event-bad', 'anomaly': 'event-bad'
    };

    // Show max 50 newest events
    const shown = events.slice(0, 50);
    list.innerHTML = shown.map(evt => {
        const icon = iconMap[evt.type] || '📌';
        const cls  = classMap[evt.type] || '';
        const time = evt.time || '';
        const msg  = evt.message || evt.type;
        return `<div class="event-item ${cls}">
            <span class="event-icon">${icon}</span>
            <div class="event-content">
                <div class="event-msg">${uiEscapeHTML(msg)}</div>
                <div class="event-time">${uiEscapeHTML(time)}</div>
            </div>
        </div>`;
    }).join('');
}

// Poll events every 15 seconds
setInterval(fetchEvents, 15000);

// Initial fetch
setTimeout(fetchEvents, 3000);

// ============================================================
// F.3: Download Full Audit Report (DOCX)
// ============================================================

function downloadAuditReport() {
    // Show group selection popup
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);z-index:10000;display:flex;align-items:center;justify-content:center';
    
    const groupOptions = [
        { id: 'switch', label: '🔀 Switch', checked: true },
        { id: 'router', label: '🌐 Router', checked: false },
        { id: 'hub', label: '⚠️ Hub (Shadow IT)', checked: true },
        { id: 'endpoint', label: '💻 Endpoint', checked: false },
        { id: 'access_point', label: '📡 Wi-Fi AP', checked: false },
        { id: 'vm', label: '🖥️ VM', checked: false },
        { id: 'hypervisor', label: '☁️ Hypervisor', checked: false },
        { id: 'bmc', label: '🔧 BMC/iLO', checked: false },
        { id: 'camera', label: '📷 Camera', checked: false },
        { id: 'phone', label: '📞 Phone', checked: false },
        { id: 'iot', label: '🌡️ IoT', checked: false },
        { id: 'wifi_random', label: '🎲 Random MAC', checked: false },
    ];

    let checkboxesHTML = groupOptions.map(g => 
        `<label style="display:flex;align-items:center;gap:8px;padding:6px 0;cursor:pointer;font-size:14px">
            <input type="checkbox" name="exportGroup" value="${g.id}" ${g.checked ? 'checked' : ''} style="width:18px;height:18px;cursor:pointer">
            ${g.label}
        </label>`
    ).join('');

    overlay.innerHTML = `
        <div style="background:#1e1e2e;border-radius:12px;padding:24px;min-width:300px;color:#fff;box-shadow:0 8px 32px rgba(0,0,0,0.5)">
            <h3 style="margin:0 0 16px;font-size:16px;color:#60a5fa">📋 Topologiya eksporti</h3>
            <p style="margin:0 0 12px;font-size:12px;color:#aaa">Qaysi qurilma turlarini diagrammaga kiritish?</p>
            <div style="border:1px solid #333;border-radius:8px;padding:8px 12px;margin-bottom:16px">${checkboxesHTML}</div>
            <div style="display:flex;gap:8px;justify-content:flex-end">
                <button id="exportCancel" style="padding:8px 16px;border:1px solid #555;border-radius:6px;background:transparent;color:#ccc;cursor:pointer;font-size:13px">Bekor</button>
                <button id="exportSvg" style="padding:8px 16px;border:none;border-radius:6px;background:#E65100;color:#fff;cursor:pointer;font-size:13px;font-weight:600">🖼️ SVG</button>
                <button id="exportDocx" style="padding:8px 16px;border:none;border-radius:6px;background:#2E74B5;color:#fff;cursor:pointer;font-size:13px;font-weight:600">📋 DOCX</button>
                <button id="exportMd" style="padding:8px 16px;border:none;border-radius:6px;background:#7B1FA2;color:#fff;cursor:pointer;font-size:13px;font-weight:600">📝 MD</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);

    overlay.querySelector('#exportCancel').onclick = () => overlay.remove();
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

    function getSelectedGroups() {
        return [...overlay.querySelectorAll('input[name=exportGroup]:checked')].map(c => c.value).join(',');
    }

    overlay.querySelector('#exportDocx').onclick = () => {
        const groups = getSelectedGroups();
        if (!groups) { alert('Kamida bitta turni tanlang!'); return; }
        overlay.remove();
        doDownload(`/api/report/audit-docx?groups=${groups}`, 'Network_Audit', '.docx', '#2E74B5');
    };

    overlay.querySelector('#exportMd').onclick = () => {
        const groups = getSelectedGroups();
        if (!groups) { alert('Kamida bitta turni tanlang!'); return; }
        overlay.remove();
        doDownload(`/api/report/audit-md?groups=${groups}`, 'Network_Audit', '.md', '#7B1FA2');
    };

    overlay.querySelector('#exportSvg').onclick = () => {
        const groups = getSelectedGroups();
        if (!groups) { alert('Kamida bitta turni tanlang!'); return; }
        overlay.remove();
        doDownload(`/api/report/audit-svg?groups=${groups}`, 'Network_Topology', '.svg', '#E65100');
    };
}

function doDownload(url, filePrefix, ext, btnColor) {
    const btn = document.querySelector('.audit-btn');
    const original = btn.textContent;
    btn.textContent = '⏳ Yuklanmoqda...';
    btn.disabled = true;

    fetch(url)
        .then(r => {
            if (!r.ok) throw new Error('Server xatosi: ' + r.status);
            return r.blob();
        })
        .then(blob => {
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `${filePrefix}_${new Date().toISOString().slice(0,10)}${ext}`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(a.href);

            btn.textContent = '✅ Yuklandi!';
            btn.style.background = '#4CAF50';
            setTimeout(() => {
                btn.textContent = original;
                btn.style.background = btnColor;
                btn.disabled = false;
            }, 2000);
        })
        .catch(err => {
            alert('❌ Hisobot yuklab olinmadi: ' + err.message);
            btn.textContent = original;
            btn.disabled = false;
        });
}

function downloadAuditMD() {
    const btn = event.target.closest('.menu-btn');
    const original = btn.textContent;
    btn.textContent = '⏳ MD...';
    btn.disabled = true;

    fetch('/api/report/audit-md')
        .then(r => {
            if (!r.ok) throw new Error('Server xatosi: ' + r.status);
            return r.blob();
        })
        .then(blob => {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            const date = new Date().toISOString().slice(0, 10);
            a.download = `Network_Audit_${date}.md`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            btn.textContent = '✅ Yuklandi!';
            btn.style.background = '#4CAF50';
            setTimeout(() => {
                btn.textContent = original;
                btn.style.background = '#7B1FA2';
                btn.disabled = false;
            }, 2000);
        })
        .catch(err => {
            alert('❌ MD hisobot yuklab olinmadi: ' + err.message);
            btn.textContent = original;
            btn.disabled = false;
        });
}
