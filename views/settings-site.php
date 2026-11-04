<?php defined('ABSPATH') || exit; ?>
<div class="wrap azwp-passkeys"><h1><?php echo esc_html__("AZ's WP Passkeys",'azwp-passkeys'); ?></h1>
<?php $this->status_notice(); ?>
<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
<input type="hidden" name="action" value="azwp_passkeys_save_site">
<?php wp_nonce_field('azwp_passkeys_save_site_'.get_current_blog_id()); ?>
<h2><?php esc_html_e('Website','azwp-passkeys'); ?></h2><table class="form-table"><tbody>
<?php foreach (['rp_name'=>__('Website name','azwp-passkeys'),'rp_id'=>__('Passkey domain','azwp-passkeys')] as $key=>$label): ?>
<tr><th scope="row"><label for="azwp-passkeys-<?php echo esc_attr($key); ?>"><?php echo esc_html($label); ?></label></th><td><input class="regular-text" required id="azwp-passkeys-<?php echo esc_attr($key); ?>" name="<?php echo esc_attr($key); ?>" value="<?php echo esc_attr($values[$key]); ?>"><p class="description"><?php echo esc_html($key==='rp_name'?__('The name shown when you use a passkey.','azwp-passkeys'):__("Use the site's domain or a valid parent domain, without https://, a path or a port.",'azwp-passkeys')); ?></p><?php $this->invalid_field_notice($key); if (!$values[$key]): ?><p><?php esc_html_e('Enter the website name and passkey domain before adding passkeys.','azwp-passkeys'); ?></p><?php endif; ?></td></tr>
<?php endforeach; ?></tbody></table><h2><?php esc_html_e('Sign-in','azwp-passkeys'); ?></h2><table class="form-table"><tbody>
<?php foreach (array_merge(['preferred_login','remember_login','reset_restriction'],is_multisite()?[]:['after_registration']) as $key) $this->setting_control($key,$values,false,$ready); ?>
</tbody></table><?php do_action('azwp_passkeys_settings_extra'); submit_button(__('Save changes','azwp-passkeys')); ?></form>
<p><a href="<?php echo esc_url(admin_url('profile.php#azwp-passkeys')); ?>"><?php esc_html_e('Manage your passkeys','azwp-passkeys'); ?></a> | <a href="<?php echo esc_url(admin_url('tools.php?page=azwp-passkeys-diagnostics')); ?>"><?php esc_html_e('Passkey diagnostics','azwp-passkeys'); ?></a></p></div>
