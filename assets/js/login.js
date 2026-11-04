(function () {
    'use strict';
    const client = window.azwpPasskeys;
    const { __ } = wp.i18n;
    const root = document.querySelector('[data-azwp-passkeys="login"][data-surface="native"]'); if (!root) return;
    const form = root.closest('form');
    const passwordNodes = [...form.children].filter(node => node !== root);
    const passkeyForm = root.querySelector('[data-passkey-form]');
    let passwordMode = client.config.policy.preferred_login === 'password';
    function renderMode() {
        passwordNodes.forEach(node => {
            node.hidden = !passwordMode;
            // Core user-profile.js disables password inputs that are hidden on load; restore them when shown.
            if (passwordMode) node.querySelectorAll('input:disabled').forEach(input => { input.disabled = false; });
        });
        passkeyForm.hidden = passwordMode;
        const button = root.querySelector('[data-action="switch-login"]');
        if (button) button.textContent = passwordMode ? __('Use a passkey instead', 'azwp-passkeys') : __('Use a password instead', 'azwp-passkeys');
        (passwordMode ? form.querySelector('#user_login') : root.querySelector('[data-action="login"]'))?.focus();
    }
    if (!client.supported()) {
        passwordMode = client.config.policy.preferred_login !== 'only';
        client.status(root, __('Passkeys are unavailable. Use a supported browser and a secure connection.', 'azwp-passkeys'), true);
    }
    renderMode();
    root.querySelector('[data-action="switch-login"]')?.addEventListener('click', () => { passwordMode = !passwordMode; renderMode(); });
    form.addEventListener('submit', event => { if (!passwordMode) { event.preventDefault(); client.ceremony(root, 'login'); } });
}());
