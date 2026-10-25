// modules.js: the device modules of the device in the info panel (the
// Graph's and the Tree's): which modules serve it, how many logins the
// Credentials window has for it, its last action, and a button per action.
// An action that changes the device asks first; its result opens in the
// module window. Every text from the server is put in with textContent.

let modulesShownIP = '';

const modEl = id => document.getElementById(id);

function modNode(tag, cls, text) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text !== undefined) el.textContent = text;
    return el;
}

// modulesShowFor lists the modules of the device at ip in the info panel
// (app.js showInfoPanel calls it); a device without modules hides the
// section. An answer for a device the panel no longer shows is dropped.
async function modulesShowFor(ip) {
    const section = modEl('infoModules');
    if (!section) return;
    modulesShownIP = ip;
    section.hidden = true;
    if (!ip) return;
    let v;
    try {
        const res = await fetch('/api/modules?ip=' + encodeURIComponent(ip));
        v = await res.json();
    } catch (err) {
        return;
    }
    if (modulesShownIP !== ip || !v.modules || !v.modules.length) return;
    const list = modEl('infoModulesList');
    list.replaceChildren(...v.modules.map(m => modCard(ip, m)));
    section.hidden = false;
}

function modCard(ip, m) {
    const card = modNode('div', 'mod-card');
    const head = modNode('div', 'mod-head');
    head.append(modNode('span', 'mod-name', '🧩 ' + m.label),
        modNode('span', m.logins ? 'mod-logins' : 'mod-logins mod-none',
            m.logins ? `${m.logins} login${m.logins > 1 ? 's' : ''}` : 'no login in 🔑 Credentials'));
    card.appendChild(head);
    if (m.last) {
        const when = new Date(m.last.time).toLocaleString();
        card.appendChild(modNode('div', m.last.ok ? 'mod-last' : 'mod-last mod-failed',
            `${m.last.ok ? '✅' : '❌'} ${m.last.action} · ${when}: ${m.last.summary}`));
    }
    const buttons = modNode('div', 'mod-actions');
    m.actions.forEach(a => {
        const b = modNode('button', a.changes ? 'mod-btn mod-change' : 'mod-btn', a.label);
        b.type = 'button';
        b.disabled = !m.logins;
        b.title = m.logins ? (a.changes ? a.confirm : 'Read only') : `Add a ${m.protocol} login for this device in 🔑 Credentials`;
        b.addEventListener('click', event => {
            event.stopPropagation();
            modRun(ip, m, a, b);
        });
        buttons.appendChild(b);
    });
    card.appendChild(buttons);
    return card;
}

async function modRun(ip, m, a, button) {
    if (a.changes && !confirm(`${m.label} ${ip}\n\n${a.confirm}`)) return;
    button.disabled = true;
    modOpen(`🧩 ${m.label} · ${a.label} · ${ip}`, [modNode('p', 'mod-running', '⏳ Logging in with the logins of 🔑 Credentials, in their order…')]);
    let v = {};
    try {
        const res = await fetch('/api/modules/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ module: m.id, action: a.id, ip, confirmed: a.changes }),
        });
        v = await res.json().catch(() => ({}));
        if (!res.ok && !v.error) v.error = `HTTP ${res.status}`;
    } catch (err) {
        v = { error: 'The server does not answer: ' + err.message };
    }
    button.disabled = false;
    modOpen(`🧩 ${m.label} · ${a.label} · ${ip}`, modResultNodes(v));
    if (modulesShownIP === ip) modulesShowFor(ip);
}

function modResultNodes(v) {
    const out = [];
    out.push(modNode('p', v.ok ? 'mod-status mod-ok' : 'mod-status mod-failed',
        v.ok ? '✅ ' + ((v.result && v.result.summary) || 'Done') : '❌ ' + (v.error || 'Failed')));
    if (v.login) out.push(modNode('p', 'mod-meta', `Login: ${v.login.username || '(API key)'} · #${v.login.id} · ${v.tried} tried`));
    if (v.snmp) out.push(modNode('p', 'mod-meta', '📡 ' + v.snmp));
    const r = v.result || {};
    if (r.changes && r.changes.length) {
        out.push(modNode('h3', '', 'Changes'));
        const ul = modNode('ul', 'mod-changes');
        r.changes.forEach(c => ul.appendChild(modNode('li', '', c)));
        out.push(ul);
    }
    if (r.facts && r.facts.length) {
        const t = modNode('table', 'cred-table mod-facts');
        r.facts.forEach(f => {
            const tr = modNode('tr');
            tr.append(modNode('th', '', f.label), modNode('td', '', f.value));
            t.appendChild(tr);
        });
        out.push(t);
    }
    (r.tables || []).forEach(tb => {
        out.push(modNode('h3', '', `${tb.title} (${(tb.rows || []).length})`));
        const wrap = modNode('div', 'cred-table-wrap');
        const t = modNode('table', 'cred-table');
        const head = modNode('tr');
        tb.columns.forEach(c => head.appendChild(modNode('th', '', c)));
        const thead = modNode('thead');
        thead.appendChild(head);
        const tbody = modNode('tbody');
        (tb.rows || []).forEach(row => {
            const tr = modNode('tr');
            row.forEach(cell => tr.appendChild(modNode('td', '', cell)));
            tbody.appendChild(tr);
        });
        t.append(thead, tbody);
        wrap.appendChild(t);
        out.push(wrap);
    });
    return out;
}

function modOpen(title, nodes) {
    modEl('moduleModalTitle').textContent = title;
    modEl('moduleModalBody').replaceChildren(...nodes);
    modEl('moduleModal').style.display = 'flex';
}

function closeModuleResult() {
    modEl('moduleModal').style.display = 'none';
}

// A click in the module window is not a click outside the info panel
// (app.js handleBackdropClick would close the panel)
document.addEventListener('DOMContentLoaded', () => {
    const modal = modEl('moduleModal');
    if (modal) modal.addEventListener('click', event => event.stopPropagation());
});
