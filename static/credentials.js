// credentials.js: the page's login (who is logged in, log out, back to
// the login page once the session ends) and the Credentials window: the
// logins the scanner uses on devices, behind the window's own password.
// A password only goes to the server, which never sends one back. Every
// text from the server is put in with textContent.

// A 401 means the session ended: back to the login page, then here. The
// Credentials password's own 401 (a wrong password) is not one.
(function () {
    const fetchFirst = window.fetch.bind(window);
    window.fetch = async (...args) => {
        const res = await fetchFirst(...args);
        const url = String(args[0] && args[0].url || args[0]);
        if (res.status === 401 && !url.startsWith('/api/login') && !url.startsWith('/api/credentials/unlock')) {
            location.href = '/login.html?next=' + encodeURIComponent(location.pathname + location.search);
        }
        return res;
    };
})();

// The user's name in the header
fetch('/api/me').then(res => res.json()).then(me => {
    const el = document.getElementById('userName');
    if (el && me.user) el.textContent = '👤 ' + me.user;
}).catch(() => { });

async function logout() {
    await fetch('/api/logout', { method: 'POST' }).catch(() => { });
    location.href = '/login.html';
}

// ==================== Credentials window ====================

const credState = { protocols: [], types: [], entries: [] };

const credEl = id => document.getElementById(id);

async function credApi(method, path, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
    }
    try {
        const res = await fetch(path, opts);
        return { ok: res.ok, status: res.status, v: await res.json().catch(() => ({})) };
    } catch (err) {
        return { ok: false, status: 0, v: { error: 'The server does not answer: ' + err.message } };
    }
}

// credShow shows one of the window's views: 'novault' (no Credentials
// password set), 'locked' (its password asked) or 'open' (the logins).
function credShow(view) {
    credEl('credNoVault').hidden = view !== 'novault';
    credEl('credLocked').hidden = view !== 'locked';
    credEl('credOpen').hidden = view !== 'open';
    credEl('credLockBtn').hidden = view !== 'open';
    credEl('credUnlockError').hidden = true;
    if (view === 'locked') credEl('credUnlockPassword').focus();
}

async function openCredentials() {
    credEl('credentialsModal').style.display = 'flex';
    const me = await credApi('GET', '/api/me');
    if (!me.v.vaultConfigured) credShow('novault');
    else if (!me.v.vaultUnlocked) credShow('locked');
    else {
        credShow('open');
        credLoad();
    }
}

function closeCredentials() {
    credEl('credentialsModal').style.display = 'none';
    credEl('credUnlockPassword').value = '';
    credResetForm();
}

async function lockCredentials() {
    await credApi('POST', '/api/credentials/lock');
    credState.entries = [];
    credRender();
    credResetForm();
    credShow('locked');
}

async function credUnlock(event) {
    event.preventDefault();
    const input = credEl('credUnlockPassword');
    const r = await credApi('POST', '/api/credentials/unlock', { password: input.value });
    input.value = '';
    if (!r.ok) {
        credEl('credUnlockError').textContent = r.v.error || `HTTP ${r.status}`;
        credEl('credUnlockError').hidden = false;
        input.focus();
        return;
    }
    credShow('open');
    credLoad();
}

async function credLoad() {
    const r = await credApi('GET', '/api/credentials');
    if (r.status === 403) {
        credShow('locked');
        return;
    }
    if (!r.ok) {
        credFormError(r.v.error || `HTTP ${r.status}`);
        return;
    }
    credState.protocols = r.v.protocols || [];
    credState.types = r.v.types || [];
    credState.entries = r.v.entries || [];
    credFillSelect(credEl('credProtocol'), credState.protocols);
    credFillSelect(credEl('credTypeValue'), credState.types);
    credFillSelect(credEl('credDeviceType'), [{ id: '', label: '— the scanner finds out —' },
        ...credState.types.filter(t => t.id !== 'any')]);
    if (!credEl('credId').value) credTypeChanged();
    credRender();
}

function credFillSelect(select, options) {
    const keep = select.value;
    select.replaceChildren(...options.map(o => {
        const opt = document.createElement('option');
        opt.value = o.id;
        opt.textContent = o.label;
        return opt;
    }));
    if (options.some(o => o.id === keep)) select.value = keep;
}

const credLabel = (options, id) => (options.find(o => o.id === id) || { label: id }).label;

function credTargetText(target, deviceType) {
    if (target.kind === 'type') return credLabel(credState.types, target.value);
    return deviceType ? `${target.value} · ${credLabel(credState.types, deviceType)}` : target.value;
}

function credButton(text, title, onClick, disabled, cls) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'cred-action' + (cls ? ' ' + cls : '');
    b.textContent = text;
    b.title = title;
    b.disabled = !!disabled;
    b.addEventListener('click', onClick);
    return b;
}

function credRender() {
    const rows = credState.entries.map((e, i) => {
        const tr = document.createElement('tr');
        const cell = (text, cls) => {
            const td = document.createElement('td');
            td.textContent = text;
            if (cls) td.className = cls;
            tr.appendChild(td);
        };
        cell(String(i + 1), 'cred-num');
        cell(credTargetText(e.target, e.deviceType), 'cred-target cred-kind-' + e.target.kind);
        cell(credLabel(credState.protocols, e.protocol));
        cell(e.username || '—', 'cred-user');
        cell(e.hasPassword ? '••••••' : '—');
        cell(e.note || '', 'cred-note-cell');
        const actions = document.createElement('td');
        actions.className = 'cred-actions';
        if (e.target.kind === 'ip' && e.deviceType && typeof modulesOpenFor === 'function') {
            actions.append(credButton('🧩 Modules', 'Modules of this device', () => modulesOpenFor(e.target.value)));
        }
        actions.append(
            credButton('↑', 'Try earlier', () => credMove(e, -1), i === 0),
            credButton('↓', 'Try later', () => credMove(e, 1), i === credState.entries.length - 1),
            credButton('Edit', 'Change this login', () => credEdit(e)),
            credButton('Delete', 'Delete this login', () => credDelete(e), false, 'cred-delete'));
        tr.appendChild(actions);
        return tr;
    });
    if (!rows.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 7;
        td.className = 'cred-empty';
        td.textContent = 'No logins yet.';
        tr.appendChild(td);
        rows.push(tr);
    }
    credEl('credRows').replaceChildren(...rows);
}

// credTypeProtocol is the protocol a device type's logins usually are for:
// picking the type picks it (the first protocol, vSphere, is no switch's).
const credTypeProtocol = {
    'esxi': 'vsphere', 'vcenter': 'vsphere', 'bmc': 'redfish', 'ilo': 'redfish', 'idrac': 'redfish',
    'fortigate': 'https', 'unifi-controller': 'https',
};

function credTypeChanged() {
    const kind = credEl('credKind').value;
    const type = kind === 'type' ? credEl('credTypeValue').value : credEl('credDeviceType').value;
    if (kind !== 'type' && !type) return;
    const protocol = credTypeProtocol[type] || 'ssh';
    if ([...credEl('credProtocol').options].some(o => o.value === protocol)) credEl('credProtocol').value = protocol;
}

// credKindChanged shows the device type list or the IP field.
function credKindChanged() {
    const kind = credEl('credKind').value;
    credEl('credTypeValue').hidden = kind !== 'type';
    credEl('credIPValue').hidden = kind === 'type';
    credEl('credDeviceTypeGroup').hidden = kind === 'type';
    credEl('credIPValue').placeholder = kind === 'cidr' ? '172.20.0.0/24' : '172.20.0.3';
}

function credFormError(msg) {
    credEl('credError').textContent = msg;
    credEl('credError').hidden = !msg;
}

function credResetForm() {
    credEl('credId').value = '';
    credEl('credKind').value = 'type';
    credEl('credIPValue').value = '';
    credEl('credUser').value = '';
    credEl('credPassword').value = '';
    credEl('credPassword').placeholder = '';
    credEl('credNote').value = '';
    credEl('credDeviceType').value = '';
    credEl('credFormTitle').textContent = 'Add a login';
    credEl('credSave').textContent = '➕ Add';
    credEl('credCancel').hidden = true;
    credFormError('');
    credKindChanged();
    credTypeChanged();
}

function credEdit(e) {
    credEl('credId').value = e.id;
    credEl('credKind').value = e.target.kind;
    credKindChanged();
    if (e.target.kind === 'type') credEl('credTypeValue').value = e.target.value;
    else credEl('credIPValue').value = e.target.value;
    credEl('credProtocol').value = e.protocol;
    credEl('credUser').value = e.username;
    credEl('credPassword').value = '';
    credEl('credPassword').placeholder = 'unchanged';
    credEl('credNote').value = e.note || '';
    credEl('credDeviceType').value = e.deviceType || '';
    credEl('credFormTitle').textContent = 'Change login #' + (credState.entries.indexOf(e) + 1);
    credEl('credSave').textContent = '💾 Save';
    credEl('credCancel').hidden = false;
    credFormError('');
    credEl('credUser').focus();
}

async function credSubmit(event) {
    event.preventDefault();
    const id = credEl('credId').value;
    const kind = credEl('credKind').value;
    const body = {
        id,
        target: { kind, value: kind === 'type' ? credEl('credTypeValue').value : credEl('credIPValue').value.trim() },
        protocol: credEl('credProtocol').value,
        username: credEl('credUser').value.trim(),
        password: credEl('credPassword').value,
        note: credEl('credNote').value.trim(),
        deviceType: kind === 'type' ? '' : credEl('credDeviceType').value,
    };
    const r = await credApi(id ? 'PUT' : 'POST', '/api/credentials', body);
    credEl('credPassword').value = '';
    if (r.status === 403) {
        credShow('locked');
        return;
    }
    if (!r.ok) {
        credFormError(r.v.error || `HTTP ${r.status}`);
        return;
    }
    credResetForm();
    credLoad();
}

async function credDelete(e) {
    const what = `${credLabel(credState.protocols, e.protocol)} login of ${credTargetText(e.target, e.deviceType)}`;
    if (!confirm(`Delete the ${what}?`)) return;
    const r = await credApi('DELETE', '/api/credentials?id=' + encodeURIComponent(e.id));
    if (!r.ok) credFormError(r.v.error || `HTTP ${r.status}`);
    if (credEl('credId').value === e.id) credResetForm();
    credLoad();
}

async function credMove(e, move) {
    const r = await credApi('PATCH', '/api/credentials', { id: e.id, move });
    if (!r.ok) credFormError(r.v.error || `HTTP ${r.status}`);
    credLoad();
}

document.addEventListener('DOMContentLoaded', () => {
    if (!credEl('credentialsModal')) return;
    credEl('credUnlockForm').addEventListener('submit', credUnlock);
    credEl('credForm').addEventListener('submit', credSubmit);
    credEl('credKind').addEventListener('change', credKindChanged);
    credEl('credTypeValue').addEventListener('change', credTypeChanged);
    credEl('credDeviceType').addEventListener('change', credTypeChanged);
    credEl('credCancel').addEventListener('click', credResetForm);
    credKindChanged();
});
