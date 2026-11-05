(function () {
    'use strict';
    const { __ } = wp.i18n;
    if (window.azwpPasskeys.supported()) return;
    document.querySelectorAll('[data-azwp-passkeys="login"][data-surface="frontend"]').forEach(root => {
        root.querySelector('[data-passkey-form]').hidden = true;
        window.azwpPasskeys.status(root, __('Passkeys are unavailable. Use a supported browser and a secure connection.', 'azwp-passkeys'), true);
    });
}());
