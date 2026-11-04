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
        const buttons = [...document.querySelectorAll('.azwp-passkeys [data-action="register"],.azwp-passkeys [data-action="login"],.azwp-passkeys [data-action^="test"],.azwp-passkeys [data-action="rename"],.azwp-passkeys [data-action="remove"]')];
        const passwordSubmit = document.querySelector('[data-password-form] input[type="submit"]');
        if (passwordSubmit) buttons.push(passwordSubmit);
        buttons.forEach(button => { if (value) { originalDisabled.set(button, button.disabled); button.disabled = true; } else { button.disabled = originalDisabled.get(button) || false; originalDisabled.delete(button); } });
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
    const rootFor = node => node.closest('[data-azwp-passkeys="register"],[data-azwp-passkeys="test"],[data-azwp-passkeys="login"],[data-azwp-passkeys="list"]');
    async function refreshCredentialList(root) {
        if (root.dataset.canManage !== '1') return;
        const table = root.querySelector('table');
        try {
            const data = await requestAction('list', { target_id: root.dataset.target }, root.dataset.nonce);
            const rows = data.credentials;
            const headings = [__('Name', 'azwp-passkeys'), __('Authenticator', 'azwp-passkeys'), __('Added', 'azwp-passkeys'), __('Last used', 'azwp-passkeys'), __('Actions', 'azwp-passkeys')];
            for (const section of [table.tHead, table.tFoot]) {
                section.replaceChildren(); const tr = document.createElement('tr');
                headings.forEach(text => { const th = document.createElement('th'); th.scope = 'col'; th.textContent = text; tr.append(th); }); section.append(tr);
            }
            const body = table.tBodies[0]; body.replaceChildren();
            if (!rows.length) { const cell = body.insertRow().insertCell(); cell.colSpan = headings.length; cell.textContent = __('No passkeys added.', 'azwp-passkeys'); }
            rows.forEach(row => {
                const tr = body.insertRow(); const name = tr.insertCell(); name.append(document.createTextNode(row.name));
                const rename = document.createElement('button'); rename.type = 'button'; rename.className = 'button-link'; rename.dataset.action = 'rename'; rename.dataset.record = String(row.record_id); rename.dataset.name = row.name; rename.textContent = __('Rename', 'azwp-passkeys');
                rename.disabled = pending || !row.can_rename;
                const renameLine = document.createElement('div'); renameLine.append(rename); name.append(renameLine);
                if (!row.available && row.unavailable_reason) { const help = document.createElement('p'); help.className = 'description'; help.textContent = row.unavailable_reason; name.append(help); }
                const model = tr.insertCell(); model.append(document.createTextNode(row.authenticator || '—'));
                if (row.synced) { const badge = document.createElement('span'); badge.className = 'azwp-passkeys-badge'; badge.textContent = __('Synced', 'azwp-passkeys'); const badgeLine = document.createElement('div'); badgeLine.append(badge); model.append(badgeLine); }
                tr.insertCell().textContent = row.created_local; tr.insertCell().textContent = row.last_used_local || '—';
                const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button'; remove.dataset.action = 'remove'; remove.dataset.record = String(row.record_id); remove.dataset.name = row.name; remove.textContent = __('Remove', 'azwp-passkeys');
                remove.disabled = pending;
                tr.insertCell().append(remove);
            });
        } catch (error) {
            const body = table.tBodies[0]; body.replaceChildren(); const td = body.insertRow().insertCell(); td.colSpan = table.tHead.rows[0].cells.length; td.textContent = __('Could not load passkeys. Refresh the page.', 'azwp-passkeys');
        }
    }
    const refreshLists = target => Promise.all([...document.querySelectorAll('[data-azwp-passkeys="list"]')].filter(root => root.dataset.target === String(target)).map(refreshCredentialList));
    async function ceremony(root, action) {
        if (pending) return;
        if (!supported()) { status(root, __('Passkeys are unavailable. Use a supported browser and a secure connection.', 'azwp-passkeys'), true); return; }
        const isLogin = action === 'login'; const register = action === 'register';
        const prefix = register ? 'register' : isLogin ? 'login' : 'test';
        const nonce = register ? root.dataset.nonce : '';
        const payload = register ? { target_id: root.dataset.target } : isLogin ? { remember: !!root.querySelector('[data-field="remember"]')?.checked, redirect_to: (root.dataset.surface === 'frontend' ? document.querySelector('[data-field="redirect_to"]') : root.querySelector('[data-field="redirect_to"]'))?.value || '', surface: root.dataset.surface } : { target_id: root.dataset.target };
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
            const result = await requestAction(prefix + '_complete', { attempt_id: issued.attempt_id, credential }, nonce, true);
            status(root, register ? __('Passkey added.', 'azwp-passkeys') : isLogin ? __('Passkey verified.', 'azwp-passkeys') : sprintf(__('Passkey test passed for “%s”.', 'azwp-passkeys'), result.name));
            if (!isLogin) await refreshLists(root.dataset.target);
            if (isLogin && typeof result.redirect_to === 'string') window.setTimeout(() => window.location.assign(result.redirect_to), 200);
        } catch (error) {
            const cancelled = error.name === 'NotAllowedError' || error.name === 'AbortError';
            // A cancelled sign-in picker usually means no passkey on this device, so point to the password when policy allows one.
            let message = cancelled ? (isLogin && config.policy.preferred_login !== 'only' ? __('Passkey prompt cancelled. Try again or use a password.', 'azwp-passkeys') : __('Passkey prompt cancelled. Try again.', 'azwp-passkeys')) : (error.server || error.code === 'network_error') ? error.message : __('The passkey could not be verified. Try again.', 'azwp-passkeys');
            if (stage === 'options' && !error.server && error.code !== 'network_error') message = __('The passkey request could not be started. Try again.', 'azwp-passkeys');
            status(root, message, true);
            if (register) await refreshLists(root.dataset.target);
        } finally {
            setPagePending(false);
        }
    }
    async function manage(root, button) {
        if (pending) return;
        const action = button.dataset.action;
        let name;
        if (action === 'rename') { name = window.prompt(__('Rename passkey', 'azwp-passkeys'), button.dataset.name); if (name === null || name === button.dataset.name) return; if (name === '') { status(root, __('Enter a name for this passkey.', 'azwp-passkeys'), true); return; } }
        else if (!window.confirm(sprintf(__('Remove “%s”? This removes the passkey from this website. It does not delete it from your device or password manager.', 'azwp-passkeys'), button.dataset.name))) return;
        setPagePending(true);
        try { const result = await requestAction(action, { target_id: root.dataset.target, record_id: button.dataset.record, ...(action === 'rename' ? { name } : {}) }, root.dataset.nonce, true); status(root, action === 'rename' ? __('Passkey renamed.', 'azwp-passkeys') : result.already_absent ? __('Passkey already removed. List refreshed.', 'azwp-passkeys') : __('Passkey removed.', 'azwp-passkeys')); }
        catch (error) { status(root, error.message, true); }
        finally { setPagePending(false); await refreshCredentialList(root); }
    }
    document.addEventListener('click', event => { const button = event.target.closest('[data-action]'); if (!button || button.disabled) return; const root = rootFor(button); if (!root) return; const action = button.dataset.action; if (['register','login','test'].includes(action)) { event.preventDefault(); ceremony(root, action); } if (['rename','remove'].includes(action)) { event.preventDefault(); manage(root, button); } });
    function initialize() {
        document.querySelectorAll('[data-azwp-passkeys="list"]').forEach(refreshCredentialList);
        if (!supported()) document.querySelectorAll('[data-azwp-passkeys="register"],[data-azwp-passkeys="test"],[data-azwp-passkeys="login"]').forEach(root => {
            root.querySelectorAll('[data-action="register"],[data-action="login"],[data-action^="test"]').forEach(button => { button.disabled = true; });
            if (root.querySelector('[data-action]')) status(root, __('Passkeys are unavailable. Use a supported browser and a secure connection.', 'azwp-passkeys'), true);
        });
    }
    window.azwpPasskeys = { requestAction, createCredential, getAssertion, refreshCredentialList, setPagePending, ceremony, supported, status, config };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize); else initialize();
}());
