<?php defined('ABSPATH') || exit; ?>
<div class="wrap azwp-passkeys"><h1><?php echo esc_html__("AZ's WP Passkeys",'azwp-passkeys'); ?></h1><?php $this->status_notice(); ?>
<form method="post" action="<?php echo esc_url(network_admin_url('edit.php?action=azwp_passkeys_save_network')); ?>"><?php wp_nonce_field('azwp_passkeys_save_network_'.get_current_network_id()); ?>
<h2><?php esc_html_e('Sign-in','azwp-passkeys'); ?></h2><table class="form-table"><tbody><?php foreach (['passkey_only'] as $key) $this->setting_control($key,$values,true,$ready); ?></tbody></table><?php submit_button(__('Save changes','azwp-passkeys')); ?></form></div>
