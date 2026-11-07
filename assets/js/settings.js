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
    const root = document.querySelector('[data-azwp-passkeys="logs"]');
    if (!root) return;
    const rows = root.querySelector('[data-log-rows]');
    const navs = [...root.querySelectorAll('[data-log-pages]')];
    const categorySelect = root.querySelector('[data-log-filter="category"]');
    const resultSelect = root.querySelector('[data-log-filter="result"]');
    const clear = root.querySelector('[data-action="clear-logs"]');
    const query = new URLSearchParams(location.search);
    const state = {
        paged: Math.max(1, parseInt(query.get('paged'), 10) || 1),
        category: query.get('category') || '',
        result: ['ok', 'failed'].includes(query.get('result')) ? query.get('result') : '',
    };
    let shown = null, sequence = 0, inFlight = 0;
    const element = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; };
    function pageUrl(paged) {
        const url = new URL(location.href);
        for (const key of ['paged', 'category', 'result']) url.searchParams.delete(key);
        if (paged > 1) url.searchParams.set('paged', String(paged));
        if (state.category) url.searchParams.set('category', state.category);
        if (state.result) url.searchParams.set('result', state.result);
        return url.toString();
    }
    const remember = () => history.replaceState(null, '', pageUrl(state.paged));
    function entryRow(entry) {
        const row = element('tr');
        row.title = entry.correlation_id;
        row.dataset.id = String(entry.id);
        const event = element('td', 'azwp-passkeys-log-event');
        if (entry.category && entry.action !== null) event.append(element('span', 'azwp-passkeys-muted', entry.category + __(': ', 'azwp-passkeys')), entry.action);
        else event.textContent = entry.category || entry.action;
        const result = element('td', 'azwp-passkeys-log-result ' + (entry.ok ? 'azwp-passkeys-ok' : 'azwp-passkeys-failed'));
        const mark = element('span', '', entry.ok ? '✓' : '✗');
        mark.setAttribute('aria-hidden', 'true');
        result.append(mark, element('span', 'screen-reader-text', entry.ok ? __('Succeeded', 'azwp-passkeys') : __('Failed', 'azwp-passkeys')));
        row.append(element('td', 'azwp-passkeys-log-id', String(entry.id)), event, element('td', 'azwp-passkeys-log-user', entry.user), result, element('td', '', entry.details), element('td', 'azwp-passkeys-log-time', entry.time), element('td', 'azwp-passkeys-log-ip', entry.ip));
        return row;
    }
    function pageLink(paged, className, label, symbol, enabled) {
        if (!enabled) { const span = element('span', 'tablenav-pages-navspan button disabled', symbol); span.setAttribute('aria-hidden', 'true'); return span; }
        const link = element('a', className + ' button');
        link.href = pageUrl(paged);
        link.dataset.paged = String(paged);
        const glyph = element('span', '', symbol);
        glyph.setAttribute('aria-hidden', 'true');
        link.append(element('span', 'screen-reader-text', label), glyph);
        return link;
    }
    function renderPages(nav, data, top) {
        nav.replaceChildren(element('span', 'displaying-num', sprintf(_n('%s item', '%s items', data.matched, 'azwp-passkeys'), data.matched.toLocaleString())));
        nav.classList.toggle('one-page', data.total_pages < 2);
        if (data.total_pages < 2) return;
        const first = data.paged === 1, last = data.paged === data.total_pages;
        const position = element('span', 'paging-input');
        if (top) {
            const [before, after] = sprintf(__('%1$s of %2$s', 'azwp-passkeys'), '\u0000', data.total_pages.toLocaleString()).split('\u0000');
            const input = element('input', 'current-page');
            Object.assign(input, { id: 'azwp-passkeys-current-page', type: 'text', name: 'paged', size: String(data.total_pages).length, value: String(data.paged) });
            const label = element('label', 'screen-reader-text', __('Current page', 'azwp-passkeys'));
            label.htmlFor = input.id;
            input.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); go(parseInt(input.value, 10) || 1); } });
            input.addEventListener('change', () => go(parseInt(input.value, 10) || 1));
            position.append(label, before, input, element('span', 'tablenav-paging-text', after));
        } else position.append(element('span', 'tablenav-paging-text', sprintf(__('%1$s of %2$s', 'azwp-passkeys'), data.paged.toLocaleString(), data.total_pages.toLocaleString())));
        const links = element('span', 'pagination-links');
        links.append(
            pageLink(1, 'first-page', __('First page', 'azwp-passkeys'), '«', !first), ' ',
            pageLink(data.paged - 1, 'prev-page', __('Previous page', 'azwp-passkeys'), '‹', !first), ' ',
            position, ' ',
            pageLink(data.paged + 1, 'next-page', __('Next page', 'azwp-passkeys'), '›', !last), ' ',
            pageLink(data.total_pages, 'last-page', __('Last page', 'azwp-passkeys'), '»', !last));
        nav.append(links);
    }
    function render(data) {
        shown = { newest: data.entries[0]?.id ?? 0, matched: data.matched, total: data.total };
        categorySelect.value = state.category;
        resultSelect.value = state.result;
        const empty = element('tr', 'azwp-passkeys-log-empty');
        const message = element('td', '', data.total === 0 ? __('No log entries.', 'azwp-passkeys') : __('No log entries match these filters.', 'azwp-passkeys'));
        message.colSpan = 7;
        empty.append(message);
        rows.replaceChildren(...(data.entries.length ? data.entries.map(entryRow) : [empty]));
        navs.forEach((nav, index) => renderPages(nav, data, index === 0));
        clear.disabled = data.total === 0;
    }
    async function load(poll = false) {
        const ticket = ++sequence, requested = state.paged;
        const payload = { paged: requested, ...(state.category ? { category: state.category } : {}), ...(state.result ? { ok: state.result === 'ok' } : {}) };
        inFlight++;
        let data;
        try { data = await client.requestAction('log_read', payload, root.dataset.nonce); }
        catch (_) {
            if (ticket === sequence) client.status(root, __('Could not load logs.', 'azwp-passkeys'), true);
            return;
        } finally { inFlight--; }
        if (ticket !== sequence) return;
        if (poll && shown && shown.newest === (data.entries[0]?.id ?? 0) && shown.matched === data.matched) return;
        render(data);
        if (data.paged !== requested) { state.paged = data.paged; remember(); }
    }
    function go(paged) {
        state.paged = Math.max(1, paged);
        remember();
        load();
    }
    root.addEventListener('click', event => {
        const link = event.target.closest('a[data-paged]');
        if (!link || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        go(Number(link.dataset.paged));
    });
    for (const [select, key] of [[categorySelect, 'category'], [resultSelect, 'result']]) {
        select.addEventListener('change', () => { state[key] = select.value; go(1); });
    }
    clear.addEventListener('click', async () => {
        const total = shown?.total ?? 0;
        if (!window.confirm(sprintf(_n('Delete %s log entry for this site? This cannot be undone.', 'Delete all %s log entries for this site? This cannot be undone.', total, 'azwp-passkeys'), total.toLocaleString()))) return;
        clear.disabled = true;
        try { await client.requestAction('log_clear', {}, root.dataset.nonce, true); client.status(root, __('Logs cleared.', 'azwp-passkeys')); }
        catch (error) { client.status(root, error.message, true); }
        go(1);
    });
    if (![...categorySelect.options].some(option => option.value === state.category)) { state.category = ''; remember(); }
    load();
    // Polling would shift rows under a reader on later pages, so only page 1 refreshes.
    if (root.dataset.logging === '1') window.setInterval(() => { if (state.paged === 1 && !inFlight) load(true); }, client.config.log_poll_interval_ms);
}());
