(function () {
    'use strict';
    const client = window.azwpPasskeys;
    const { __ } = wp.i18n;
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
