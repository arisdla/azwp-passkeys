(function () {
    'use strict';
    if (window.azwpPasskeys) return;
    const { __, sprintf } = wp.i18n;
    const config = window.azwpPasskeysConfig;
    let pending = false;
    const originalDisabled = new WeakMap();
    const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
    const encode = value => { let text = ''; for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte); return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
    const status = (root, text, error = false) => {
        const node = root.querySelector('[data-azwp-passkeys="status"]');
        if (!node) return;
        node.setAttribute('role', error ? 'alert' : 'status');
        node.textContent = text;
        node.classList.toggle('azwp-passkeys-error', error);
    };
    function setPagePending(value) {
        pending = value;
        const buttons = [...document.querySelectorAll('.azwp-passkeys [data-action="register"],.azwp-passkeys [data-action="setup"],.azwp-passkeys [data-action="send-setup"],.azwp-passkeys [data-action="login"],.azwp-passkeys [data-action^="test"],.azwp-passkeys [data-action="rename"],.azwp-passkeys [data-action="remove"]')];
        const passwordSubmit = document.querySelector('[data-password-form] input[type="submit"]');
        if (passwordSubmit) buttons.push(passwordSubmit);
        buttons.forEach(button => { if (value) { originalDisabled.set(button, button.disabled); button.disabled = true; } else if (originalDisabled.has(button)) { button.disabled = originalDisabled.get(button); originalDisabled.delete(button); } });
    }
    async function requestAction(action, payload = {}, nonce = '', completion = false) {
        let response;
        try {
            response = await fetch(config.ajax_url, { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' }, body: new URLSearchParams({ action: 'azwp_passkeys_' + action, payload: JSON.stringify(payload), ...(nonce ? { _ajax_nonce: nonce } : {}) }) });
            const result = await response.json();
            if (!result || typeof result.success !== 'boolean' || !result.data) throw new Error('invalid-envelope');
            if (!result.success) throw Object.assign(new Error(result.data.message || __('The operation could not be completed.', 'azwp-passkeys')), { code: result.data.code, retry: result.data.retry, server: true });
            return result.data;
        } catch (error) {
            if (error.server) throw error;
            throw Object.assign(new Error(completion ? __('The result could not be confirmed. Refresh to check.', 'azwp-passkeys') : __('Could not connect. Check your connection and try again.', 'azwp-passkeys')), { code: 'network_error', retry: completion ? 'uncertain' : 'fresh_attempt' });
        }
    }
    function publicOptions(options) {
        const result = { ...options, challenge: decode(options.challenge), userVerification: 'required' };
        if (options.user) result.user = { ...options.user, id: decode(options.user.id) };
        for (const key of ['allowCredentials', 'excludeCredentials']) if (Array.isArray(options[key])) result[key] = options[key].map(item => ({ ...item, id: decode(item.id) }));
        return result;
    }
    function serialize(credential) {
        const response = { clientDataJSON: encode(credential.response.clientDataJSON) };
        if (credential.response.attestationObject) {
            response.attestationObject = encode(credential.response.attestationObject);
            if (typeof credential.response.getTransports === 'function') response.transports = credential.response.getTransports();
        } else {
            response.authenticatorData = encode(credential.response.authenticatorData);
            response.signature = encode(credential.response.signature);
            response.userHandle = credential.response.userHandle === null ? null : encode(credential.response.userHandle);
        }
        return { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response, clientExtensionResults: credential.getClientExtensionResults() };
    }
    const supported = () => !!(window.isSecureContext && window.PublicKeyCredential && navigator.credentials && config.server_ready);
    const createCredential = async options => serialize(await navigator.credentials.create({ publicKey: publicOptions(options) }));
    const getAssertion = async options => serialize(await navigator.credentials.get({ publicKey: publicOptions(options) }));
    const rootFor = node => node.closest('[data-azwp-passkeys="register"],[data-azwp-passkeys="test"],[data-azwp-passkeys="login"],[data-azwp-passkeys="list"],[data-azwp-passkeys="setup"]');
    // Themes can print an invalid lang attribute, such as en_US, which Intl rejects.
    function relativeTimeFormat() {
        try { return new Intl.RelativeTimeFormat(document.documentElement.lang || undefined, { numeric: 'auto' }); }
        catch { return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }); }
    }
    function appendTime(cell, timestamp, label) {
        if (!label) { cell.textContent = '—'; return; }
        const time = document.createElement('time'); time.textContent = label; time.title = label; time.dateTime = new Date(timestamp * 1000).toISOString();
        const age = Math.max(0, Date.now() / 1000 - timestamp);
        if (age < 7 * 86400) {
            const [value, unit] = age < 60 ? [0, 'second'] : age < 3600 ? [Math.floor(age / 60), 'minute'] : age < 86400 ? [Math.floor(age / 3600), 'hour'] : [Math.floor(age / 86400), 'day'];
            time.textContent = relativeTimeFormat().format(-value, unit);
        }
        cell.append(time);
    }
    function element(tag, className = '', text = '') {
        const node = document.createElement(tag); if (className) node.className = className; if (text) node.textContent = text; return node;
    }
    function messageRow(body, text) {
        const tr = body.insertRow(); tr.className = 'no-items'; const td = tr.insertCell(); td.className = 'colspanchange'; td.colSpan = 4; td.textContent = text;
    }
    function rowAction(row, action, label, className, allowed) {
        const button = element('button', className, label); button.type = 'button'; button.dataset.action = action; button.dataset.record = String(row.record_id); button.dataset.name = row.name;
        button.disabled = pending || !allowed;
        if (pending) originalDisabled.set(button, !allowed);
        return button;
    }
    async function refreshCredentialList(root, tested = null) {
        if (root.dataset.canManage !== '1') return;
        const body = root.querySelector('table').tBodies[0];
        try {
            const data = await requestAction('list', { target_id: root.dataset.target }, root.dataset.nonce);
            const [nameLabel, authenticatorLabel, addedLabel, lastUsedLabel] = [__('Name', 'azwp-passkeys'), __('Authenticator', 'azwp-passkeys'), __('Added', 'azwp-passkeys'), __('Last used', 'azwp-passkeys')];
            body.replaceChildren();
            if (!data.credentials.length) messageRow(body, root.dataset.own === '1' ? __('No passkeys yet. Add one to sign in with your fingerprint, face, or device PIN.', 'azwp-passkeys') : __('This account has no passkeys yet.', 'azwp-passkeys'));
            data.credentials.forEach(row => {
                const tr = body.insertRow(); if (tested === String(row.record_id)) tr.className = 'azwp-passkeys-tested';
                const name = tr.insertCell(); name.className = 'column-name has-row-actions column-primary'; name.dataset.colname = nameLabel;
                name.append(element('strong', '', row.name));
                if (!row.available && row.unavailable_reason) name.append(element('p', 'description', row.unavailable_reason));
                const rename = element('span', 'rename'); rename.append(rowAction(row, 'rename', __('Rename', 'azwp-passkeys'), 'button-link', row.can_rename), ' | ');
                const remove = element('span', 'delete'); remove.append(rowAction(row, 'remove', __('Remove', 'azwp-passkeys'), 'button-link button-link-delete', row.can_remove));
                const actions = element('div', 'row-actions'); actions.append(rename, remove);
                const toggle = element('button', 'toggle-row'); toggle.type = 'button'; toggle.append(element('span', 'screen-reader-text', __('Show more details', 'azwp-passkeys')));
                name.append(actions, toggle);
                const model = tr.insertCell(); model.className = 'column-model'; model.dataset.colname = authenticatorLabel; model.append(document.createTextNode(row.authenticator || '—'));
                if (row.synced) { const badgeLine = element('div'); badgeLine.append(element('span', 'azwp-passkeys-badge', __('Synced', 'azwp-passkeys'))); model.append(badgeLine); }
                const added = tr.insertCell(); added.className = 'column-added'; added.dataset.colname = addedLabel; appendTime(added, row.created_ts, row.created_local);
                const lastUsed = tr.insertCell(); lastUsed.className = 'column-last-used'; lastUsed.dataset.colname = lastUsedLabel; appendTime(lastUsed, row.last_used_ts, row.last_used_local);
            });
            // The server refuses Passkey only mode without a usable passkey, so the profile says so before saving.
            const section = document.querySelector('[data-requires-passkey]')?.closest('#azwp-passkeys');
            if (section?.contains(root)) {
                const policy = section.querySelector('[data-requires-passkey]');
                policy.disabled = !policy.checked && !data.credentials.some(row => row.available);
                section.querySelector('[data-passkey-required]').hidden = !policy.disabled;
            }
        } catch (error) {
            body.replaceChildren(); messageRow(body, __('Could not load passkeys. Refresh the page.', 'azwp-passkeys'));
        }
    }
    const refreshLists = (target, tested = null) => Promise.all([...document.querySelectorAll('[data-azwp-passkeys="list"]')].filter(root => root.dataset.target === String(target)).map(root => refreshCredentialList(root, tested)));
    // With a password form on the page, its own Remember Me box applies to passkey sign-in too.
    function rememberLogin(root) {
        const own = root.querySelector('[data-field="remember"]');
        if (own) return own.checked;
        if (!config.policy.remember_login) return false;
        const scope = root.closest('form') || root.closest('.azwp-passkeys-login-wrapper');
        return !!scope?.querySelector('input[name="rememberme"]')?.checked;
    }
    async function ceremony(root, action) {
        if (pending) return;
        if (!supported()) { status(root, __('Passkeys are unavailable. Use a supported browser and a secure connection.', 'azwp-passkeys'), true); return; }
        const isLogin = action === 'login'; const setup = action === 'setup'; const register = action === 'register' || setup;
        const prefix = setup ? 'setup' : register ? 'register' : isLogin ? 'login' : 'test';
        const nonce = register && !setup ? root.dataset.nonce : '';
        const payload = setup ? { user_id: root.dataset.user, token: root.dataset.token } : register ? { target_id: root.dataset.target } : isLogin ? { remember: rememberLogin(root), redirect_to: root.querySelector('[data-field="redirect_to"]')?.value || '', surface: root.dataset.surface } : { target_id: root.dataset.target };
        setPagePending(true); status(root, __('Preparing…', 'azwp-passkeys'));
        let stage = 'options';
        try {
            const issued = await requestAction(prefix + '_options', payload, nonce);
            if (!issued.attempt_id || !issued.publicKey) throw new Error('invalid options');
            stage = 'browser';
            status(root, __("Follow your browser's instructions", 'azwp-passkeys'));
            const credential = register ? await createCredential(issued.publicKey) : await getAssertion(issued.publicKey);
            status(root, register ? __('Saving…', 'azwp-passkeys') : __('Verifying…', 'azwp-passkeys'));
            stage = 'completion';
            const result = await requestAction(prefix + '_complete', { attempt_id: issued.attempt_id, credential, ...(setup ? { token: root.dataset.token } : {}) }, nonce, true);
            status(root, register ? __('Passkey added.', 'azwp-passkeys') : isLogin ? __('Passkey verified.', 'azwp-passkeys') : sprintf(__('Passkey test passed for “%s”.', 'azwp-passkeys'), result.name));
            if (!isLogin && !setup) await refreshLists(root.dataset.target, prefix === 'test' ? result.record_id : null);
            if ((isLogin || setup) && typeof result.redirect_to === 'string') window.setTimeout(() => window.location.assign(result.redirect_to), 200);
        } catch (error) {
            const cancelled = error.name === 'NotAllowedError' || error.name === 'AbortError';
            // A cancelled sign-in picker usually means no passkey on this device, so point to the password when policy allows one.
            let message = cancelled ? (isLogin && !config.policy.passkey_only ? __('Passkey prompt cancelled. Try again or use a password.', 'azwp-passkeys') : __('Passkey prompt cancelled. Try again.', 'azwp-passkeys')) : (error.server || error.code === 'network_error') ? error.message : __('The passkey could not be verified. Try again.', 'azwp-passkeys');
            if (stage === 'options' && !error.server && error.code !== 'network_error') message = __('The passkey request could not be started. Try again.', 'azwp-passkeys');
            status(root, message, true);
            if (register && !setup) await refreshLists(root.dataset.target);
        } finally {
            setPagePending(false);
        }
    }
    async function sendSetup(root) {
        if (pending) return;
        setPagePending(true);
        try { await requestAction('send_setup', { target_id: root.dataset.target }, root.dataset.nonce, true); status(root, __('Setup link sent to the account email address. It expires in one hour.', 'azwp-passkeys')); }
        catch (error) { status(root, error.message, true); }
        finally { setPagePending(false); }
    }
    // Mirrors WordPress Quick Edit: the row is hidden and an edit row follows it, after a hidden spacer that keeps the stripes aligned.
    function startRename(root, button) {
        const row = button.closest('tr'); const spacer = element('tr'); spacer.hidden = true;
        const editor = element('tr', 'inline-edit-row quick-edit-row quick-edit-row-post'); const cell = editor.insertCell(); cell.className = 'colspanchange'; cell.colSpan = row.cells.length;
        const legend = element('legend', 'inline-edit-legend', __('Rename passkey', 'azwp-passkeys')); legend.id = root.id + '-rename-' + button.dataset.record;
        const input = element('input'); input.type = 'text'; input.dataset.field = 'name'; input.value = button.dataset.name;
        const label = element('label'); const field = element('span', 'input-text-wrap'); field.append(input); label.append(element('span', 'title', __('Name', 'azwp-passkeys')), field);
        const column = element('div', 'inline-edit-col'); column.append(label);
        const fieldset = element('fieldset', 'inline-edit-col-left'); fieldset.append(legend, column);
        const save = element('button', 'button button-primary save', __('Update', 'azwp-passkeys')); save.type = 'button';
        const cancel = element('button', 'button cancel', __('Cancel', 'azwp-passkeys')); cancel.type = 'button';
        const spinner = element('span', 'spinner');
        const submitRow = element('div', 'submit inline-edit-save'); submitRow.append(save, cancel, spinner);
        const wrapper = element('div', 'inline-edit-wrapper'); wrapper.setAttribute('role', 'region'); wrapper.setAttribute('aria-labelledby', legend.id); wrapper.append(fieldset, submitRow);
        cell.append(wrapper);
        const restore = () => { spacer.remove(); editor.remove(); row.hidden = false; button.focus(); };
        async function submit() {
            if (pending) return;
            const name = input.value;
            if (name === button.dataset.name) { restore(); return; }
            if (name === '') { status(root, __('Enter a name for this passkey.', 'azwp-passkeys'), true); input.focus(); return; }
            setPagePending(true); spinner.classList.add('is-active');
            try { await requestAction('rename', { target_id: root.dataset.target, record_id: button.dataset.record, name }, root.dataset.nonce, true); status(root, __('Passkey renamed.', 'azwp-passkeys')); }
            catch (error) { status(root, error.message, true); }
            finally { setPagePending(false); await refreshCredentialList(root); root.querySelector(`[data-action="rename"][data-record="${button.dataset.record}"]`)?.focus(); }
        }
        // The list sits inside the profile form, so Enter must not submit it.
        editor.addEventListener('keydown', event => { if (event.key === 'Escape') { event.preventDefault(); restore(); } else if (event.key === 'Enter' && event.target === input) { event.preventDefault(); submit(); } });
        save.addEventListener('click', submit); cancel.addEventListener('click', restore);
        row.hidden = true; row.after(spacer, editor); input.focus(); input.select();
    }
    async function remove(root, button) {
        if (pending) return;
        const position = [...root.querySelectorAll('[data-action="remove"]')].indexOf(button);
        if (!window.confirm(sprintf(__('Remove “%s”? This removes the passkey from this website. It does not delete it from your device or password manager.', 'azwp-passkeys'), button.dataset.name))) return;
        setPagePending(true);
        try { const result = await requestAction('remove', { target_id: root.dataset.target, record_id: button.dataset.record }, root.dataset.nonce, true); status(root, result.already_absent ? __('Passkey already removed. List refreshed.', 'azwp-passkeys') : __('Passkey removed.', 'azwp-passkeys')); }
        catch (error) { status(root, error.message, true); }
        finally {
            setPagePending(false); await refreshCredentialList(root);
            const remaining = root.querySelectorAll('[data-action="rename"]');
            remaining[Math.min(position, remaining.length - 1)]?.focus();
        }
    }
    document.addEventListener('click', event => { const button = event.target.closest('[data-action]'); if (!button || button.disabled) return; const root = rootFor(button); if (!root) return; const action = button.dataset.action; if (['register','login','test','setup'].includes(action)) { event.preventDefault(); ceremony(root, action); } if (action === 'send-setup') { event.preventDefault(); sendSetup(root); } if (action === 'rename') { event.preventDefault(); startRename(root, button); } if (action === 'remove') { event.preventDefault(); remove(root, button); } });
    function initialize() {
        document.querySelectorAll('[data-azwp-passkeys="list"]').forEach(root => refreshCredentialList(root));
        if (!supported()) document.querySelectorAll('[data-azwp-passkeys="register"],[data-azwp-passkeys="test"],[data-azwp-passkeys="login"],[data-azwp-passkeys="setup"]').forEach(root => {
            root.querySelectorAll('[data-action="register"],[data-action="setup"],[data-action="login"],[data-action^="test"]').forEach(button => { button.disabled = true; });
            if (root.querySelector('[data-action]')) status(root, __('Passkeys are unavailable. Use a supported browser and a secure connection.', 'azwp-passkeys'), true);
        });
    }
    window.azwpPasskeys = { requestAction, createCredential, getAssertion, refreshCredentialList, setPagePending, ceremony, supported, status, config };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize); else initialize();
}());
