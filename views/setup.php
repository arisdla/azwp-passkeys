<?php defined('ABSPATH') || exit; ?>
<div class="azwp-passkeys" id="<?php echo esc_attr($instance); ?>" data-azwp-passkeys="setup" data-user="<?php echo esc_attr((string) $user_id); ?>" data-token="<?php echo esc_attr($token); ?>">
<?php if (!$valid): ?><p class="message"><?php esc_html_e('This passkey setup link has expired or was already used. Ask a site administrator for a new one.','azwp-passkeys'); ?></p>
<?php else: ?><p><?php printf(esc_html__('Add a passkey for %s. Confirm with your fingerprint, face, or device PIN.','azwp-passkeys'),esc_html($user->user_login)); ?></p>
<button type="button" class="button button-primary" data-action="setup"><?php esc_html_e('Add passkey','azwp-passkeys'); ?></button>
<?php endif; ?><div data-azwp-passkeys="status" role="status" aria-live="polite"></div></div>
