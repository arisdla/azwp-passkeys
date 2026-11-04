<?php defined('ABSPATH') || exit; ?>
<div class="azwp-passkeys" id="<?php echo esc_attr($instance); ?>" data-azwp-passkeys="test" data-target="<?php echo esc_attr($target_id); ?>">
<?php if (!$can_manage): ?><p><?php echo esc_html(is_user_logged_in()?__('You do not have permission to manage these passkeys.','azwp-passkeys'):__('Sign in to manage your passkeys.','azwp-passkeys')); ?></p><?php else: ?>
<p><?php esc_html_e('Confirm with your fingerprint, face, or device PIN. This is required to continue.','azwp-passkeys'); ?></p><button type="button" class="button" data-action="test"><?php esc_html_e('Test passkey','azwp-passkeys'); ?></button>
<?php endif; ?><div data-azwp-passkeys="status" role="status" aria-live="polite"></div></div>
