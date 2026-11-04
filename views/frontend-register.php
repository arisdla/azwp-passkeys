<?php defined('ABSPATH') || exit; ?>
<div class="azwp-passkeys" id="<?php echo esc_attr($instance); ?>" data-azwp-passkeys="register" data-target="<?php echo esc_attr($target_id); ?>" data-nonce="<?php echo esc_attr($nonce); ?>">
<?php if (!$can_manage): ?><p><?php echo esc_html(is_user_logged_in()?__('You do not have permission to manage these passkeys.','azwp-passkeys'):__('Sign in to manage your passkeys.','azwp-passkeys')); ?></p><?php else: ?>
<p><?php printf(esc_html__('Add a passkey for %s. You can add more than one and rename them later.','azwp-passkeys'),esc_html(get_userdata($target_id)->display_name)); ?></p>
<p><?php esc_html_e('Confirm with your fingerprint, face, or device PIN. This is required to continue.','azwp-passkeys'); ?></p><button type="button" class="button button-primary" data-action="register" <?php disabled(!$ready); ?>><?php esc_html_e('Add passkey','azwp-passkeys'); ?></button>
<?php endif; ?><div data-azwp-passkeys="status" role="status" aria-live="polite"></div></div>
