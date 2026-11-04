(function () {
    'use strict';
    // After the registration continuation, adding a passkey is the next step.
    const section = document.getElementById('azwp-passkeys');
    if (section && section.dataset.open === 'add') section.querySelector('[data-action="register"]')?.focus();
}());
