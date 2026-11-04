<?php defined('ABSPATH') || exit; ?>
<div class="azwp-passkeys" id="<?php echo esc_attr($instance); ?>" data-azwp-passkeys="login" data-surface="<?php echo $native?'native':'frontend'; ?>">
<div data-passkey-form><input type="hidden" data-field="redirect_to" value="<?php echo esc_attr($redirect_to); ?>">
<p><?php esc_html_e('Confirm with your fingerprint, face, or device PIN. This is required to continue.','azwp-passkeys'); ?></p>
<?php if ($policy['remember_login']): ?><label><input type="checkbox" data-field="remember"> <?php esc_html_e('Remember me','azwp-passkeys'); ?></label><?php endif; ?>
<button type="button" class="button button-primary" data-action="login"><?php esc_html_e('Sign in with a passkey','azwp-passkeys'); ?></button></div>
<?php if ($policy['preferred_login']!=='only'&&($native||!empty($traditional))): ?><button type="button" class="button-link" data-action="switch-login"><?php esc_html_e('Use a password instead','azwp-passkeys'); ?></button><?php endif; ?>
<div data-azwp-passkeys="status" role="status" aria-live="polite"></div></div>
