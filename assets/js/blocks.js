(function () {
    'use strict';
    const { __ } = wp.i18n;
    const { createElement: el, Fragment } = wp.element;
    const { InspectorControls, useBlockProps } = wp.blockEditor;
    const { PanelBody, CheckboxControl, TextControl } = wp.components;
    const labels = { login: __('Passkey sign-in', 'azwp-passkeys'), register: __('Add passkey', 'azwp-passkeys'), test: __('Test passkey', 'azwp-passkeys'), list: __('Passkey list', 'azwp-passkeys') };
    const icons = { login: 'admin-network', register: 'plus-alt', test: 'sos', list: 'menu' };
    const encode = value => String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/\[/g, '&#91;').replace(/\]/g, '&#93;');
    Object.keys(labels).forEach(kind => {
        const schema = kind === 'login' ? { traditional: { type: 'boolean', default: true }, username: { type: 'string', default: '' }, auto_hide: { type: 'boolean', default: true }, to: { type: 'string', default: '' } } : { display: { type: 'boolean', default: true } };
        wp.blocks.registerBlockType('azwp-passkeys/' + kind, {
            apiVersion: 3, title: labels[kind], icon: icons[kind], category: 'widgets', keywords: [__('passkey', 'azwp-passkeys')], attributes: schema,
            edit: ({ attributes, setAttributes }) => {
                const checkbox = (key, label) => el(CheckboxControl, { key, label, checked: attributes[key], onChange: value => setAttributes({ [key]: value }) });
                const text = (key, label) => el(TextControl, { key, label, value: attributes[key], onChange: value => setAttributes({ [key]: value }) });
                const controls = kind === 'login' ? [checkbox('traditional', __('Include password sign-in form', 'azwp-passkeys')), text('username', __('Prefilled username or email', 'azwp-passkeys')), checkbox('auto_hide', __('Hide when signed in', 'azwp-passkeys')), text('to', __('After sign-in, go to', 'azwp-passkeys'))] : [checkbox('display', __('Show a message when signed out', 'azwp-passkeys'))];
                return el(Fragment, null, el(InspectorControls, null, el(PanelBody, { title: labels[kind] }, controls)), el('div', useBlockProps(), el('strong', null, labels[kind]), el('p', null, __('Passkey actions are unavailable in the editor.', 'azwp-passkeys'))));
            },
            save: ({ attributes }) => el(wp.element.RawHTML, null, '[azwp_pk_' + kind + ' ' + Object.keys(schema).map(key => key + '="' + encode(attributes[key]) + '"').join(' ') + ']'),
        });
    });
}());
