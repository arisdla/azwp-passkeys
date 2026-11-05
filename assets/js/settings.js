(function () {
    'use strict';
    const client = window.azwpPasskeys;
    const { __, _n, sprintf } = wp.i18n;
    document.querySelectorAll('[data-passkey-only-readiness]').forEach(notice => {
        const form = notice.closest('form');
        const field = form?.querySelector('input[type="hidden"][name="passkey_only_confirmed"]');
        if (!field) return;
        form.addEventListener('submit', event => {
            if (!form.querySelector('input[name="passkey_only"][value="1"]')?.checked) return;
            const total = Number(notice.dataset.passkeyOnlyReadiness);
            if (window.confirm(sprintf(_n('%d account has no working passkey and will not be able to sign in. Turn on Passkey only mode anyway?', '%d accounts have no working passkey and will not be able to sign in. Turn on Passkey only mode anyway?', total, 'azwp-passkeys'), total))) field.value = notice.dataset.passkeyOnlyToken;
            else event.preventDefault();
        });
    });
    const root = document.querySelector('[data-azwp-passkeys="diagnostics"]');
    if (!root) return;
    const viewer = root.querySelector('[data-log-view]');
    const count = root.querySelector('[data-log-count]');
    const clear = root.querySelector('[data-action="clear-logs"]');
    async function load() {
        try {
            const data = await client.requestAction('log_read', {}, root.dataset.nonce);
            const text = data.entries.length ? data.entries.map(entry => typeof entry === 'string' ? entry : JSON.stringify(entry)).join('\n') : __('No log entries.', 'azwp-passkeys');
            if (viewer.textContent !== text) { viewer.textContent = text; viewer.scrollTop = viewer.scrollHeight; }
            count.textContent = String(data.count); clear.disabled = data.count === 0;
        } catch (_) { viewer.textContent = __('Could not load logs.', 'azwp-passkeys'); }
    }
    clear.addEventListener('click', async () => {
        clear.disabled = true;
        try { await client.requestAction('log_clear', {}, root.dataset.nonce, true); client.status(root, __('Logs cleared.', 'azwp-passkeys')); }
        catch (error) { client.status(root, error.message, true); }
        await load();
    });
    load();
    if (root.dataset.logging === '1') window.setInterval(load, client.config.log_poll_interval_ms);
}());
