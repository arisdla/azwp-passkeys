(function () {
    'use strict';
    const client = window.azwpPasskeys;
    const { __ } = wp.i18n;
    const root = document.querySelector('[data-azwp-passkeys="login"][data-surface="native"]'); if (!root) return;
    const form = root.closest('form');
    const passkeyOnly = !!client.config.policy.passkey_only;
    // login_form prints inside the form before Remember Me and Log In, so move the passkey button after them.
    if (!passkeyOnly) form.append(root);
    if (!client.supported()) {
        root.querySelector('[data-passkey-form]').hidden = true;
        client.status(root, __('Passkeys are unavailable. Use a supported browser and a secure connection.', 'azwp-passkeys'), true);
        return;
    }
    if (passkeyOnly) {
        root.querySelector('[data-action="login"]').focus();
        form.addEventListener('submit', event => { event.preventDefault(); client.ceremony(root, 'login'); });
    }
}());
