<?php defined('ABSPATH') || exit; $password_form=empty($policy['passkey_only'])&&($native||!empty($traditional)); ?>
<div class="azwp-passkeys" id="<?php echo esc_attr($instance); ?>" data-azwp-passkeys="login" data-surface="<?php echo $native?'native':'frontend'; ?>">
<div data-passkey-form><input type="hidden" data-field="redirect_to" value="<?php echo esc_attr($redirect_to); ?>">
<?php if ($password_form): ?><p class="azwp-passkeys-or"><?php esc_html_e('or','azwp-passkeys'); ?></p>
<?php else: ?><p><?php esc_html_e('Confirm with your fingerprint, face, or device PIN. This is required to continue.','azwp-passkeys'); ?></p>
<?php if ($policy['remember_login']): ?><label><input type="checkbox" data-field="remember"> <?php esc_html_e('Remember me','azwp-passkeys'); ?></label><?php endif; endif; ?>
<button type="button" class="button button-primary" data-action="login"><?php esc_html_e('Sign in with a passkey','azwp-passkeys'); ?></button></div>
<div data-azwp-passkeys="status" role="status" aria-live="polite"></div></div>
