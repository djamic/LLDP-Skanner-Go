// login.js: the login page. A good login goes to the page the user came
// from (?next=, a path of this server only), else to the topology.
(function () {
    const form = document.getElementById('loginForm');
    const error = document.getElementById('loginError');
    const button = document.getElementById('loginSubmit');

    const show = msg => {
        error.textContent = msg;
        error.hidden = !msg;
    };

    // "/x" of this server, never "//host" or "/\host" (another site)
    const nextPath = () => {
        const next = new URLSearchParams(location.search).get('next') || '/';
        return /^\/(?![\/\\])/.test(next) ? next : '/';
    };

    fetch('/api/login').then(res => res.json()).then(v => {
        if (!v.users) {
            form.hidden = true;
            document.getElementById('loginNoUser').hidden = false;
        }
    }).catch(() => { });

    form.addEventListener('submit', async event => {
        event.preventDefault();
        show('');
        button.disabled = true;
        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user: form.username.value.trim(), password: form.password.value }),
            });
            if (res.ok) {
                location.replace(nextPath());
                return;
            }
            const v = await res.json().catch(() => ({}));
            show(v.error || `Login failed (HTTP ${res.status})`);
            form.password.value = '';
            form.password.focus();
        } catch (err) {
            show('The server does not answer: ' + err.message);
        } finally {
            button.disabled = false;
        }
    });
})();
