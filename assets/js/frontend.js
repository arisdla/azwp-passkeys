(function () {
    'use strict';
    const { __ } = wp.i18n;
    function showMode(root, password) {
        const wrapper = root.closest('.azwp-passkeys-login-wrapper');
        const passwordForm = wrapper.querySelector('[data-password-form]');
        root.querySelector('[data-passkey-form]').hidden = password;
        if (passwordForm) passwordForm.hidden = !password;
        const switchButton = root.querySelector('[data-action="switch-login"]');
        if (switchButton) switchButton.textContent = password ? __('Use a passkey instead', 'azwp-passkeys') : __('Use a password instead', 'azwp-passkeys');
        (password ? passwordForm?.querySelector('input[type="text"]') : root.querySelector('[data-action="login"]'))?.focus();
    }
    document.addEventListener('click', event => {
        if (!event.target.closest('[data-action="switch-login"]')) return;
        const root = document.querySelector('[data-azwp-passkeys="login"][data-surface="frontend"]'); if (!root) return;
        showMode(root, !root.querySelector('[data-passkey-form]').hidden);
    });
    document.querySelectorAll('[data-azwp-passkeys="login"][data-surface="frontend"]').forEach(root => {
        if (!window.azwpPasskeys.supported()) {
            const password = root.closest('.azwp-passkeys-login-wrapper').querySelector('[data-password-form]');
            if (password) showMode(root, true);
            else window.azwpPasskeys.status(root, __('Passkeys are unavailable. Use a supported browser and a secure connection.', 'azwp-passkeys'), true);
        }
    });
}());
