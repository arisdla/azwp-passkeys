<?php
/**
 * Plugin Name: AZ's WP Passkeys Watchdog
 * Description: Reactivates AZ's WP Passkeys after a silent deactivation and blocks password sign-in for passkey-only accounts while the plugin cannot run. Installed and removed by the plugin.
 * Author: Arthur Z.
 * License: GPL-3.0-or-later
 * Text Domain: azwp-passkeys
 */
// Self-contained and PHP 7.2 syntax: the plugin may be missing or broken, and a fatal in a must-use plugin takes the whole site down.
if (!defined('ABSPATH')) { exit; }

call_user_func(static function () {
    $network = is_multisite();
    $guard = get_site_option('azwp_passkeys_watchdog');
    $plugin = is_array($guard) && isset($guard['plugin']) && is_string($guard['plugin']) && validate_file($guard['plugin']) === 0 && substr($guard['plugin'], -4) === '.php' ? $guard['plugin'] : null;
    // Raw reads the stored list, because filters such as WP-CLI's --skip-plugins hide entries until plugins_loaded and writing a filtered list back would deactivate them.
    $active_list = static function ($raw) use ($network) {
        global $wpdb;
        if (!$raw) { $list = $network ? get_site_option('active_sitewide_plugins', []) : get_option('active_plugins', []); }
        elseif ($network) { $list = maybe_unserialize($wpdb->get_var($wpdb->prepare("SELECT meta_value FROM {$wpdb->sitemeta} WHERE site_id = %d AND meta_key = %s ORDER BY meta_id LIMIT 1", get_current_network_id(), 'active_sitewide_plugins'))); }
        else { $list = maybe_unserialize($wpdb->get_var($wpdb->prepare("SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", 'active_plugins'))); }
        return is_array($list) ? $list : [];
    };
    $listed = static function (array $list) use ($plugin, $network) { return $network ? isset($list[$plugin]) : in_array($plugin, $list, true); };
    $facts = static function () use ($plugin, $active_list, $listed) {
        if ($plugin === null) { return ['armed' => false]; }
        return ['armed' => true, 'loaded' => defined('AZWP_PASSKEYS_VERSION'), 'present' => is_file(WP_PLUGIN_DIR . '/' . $plugin), 'listed' => $listed($active_list(false)) || $listed($active_list(true))];
    };
    $state = static function (array $facts) {
        if (!$facts['armed']) { return 'disarmed'; }
        if ($facts['loaded']) { return 'running'; }
        return $facts['present'] && !$facts['listed'] ? 'reactivate' : 'fail_closed';
    };

    try { $now = $state($facts()); } catch (\Throwable $error) { $now = 'fail_closed'; }
    if ($now === 'disarmed') { return; }
    if ($now === 'reactivate') {
        try {
            $list = $active_list(true);
            if ($network) { $list[$plugin] = time(); update_site_option('active_sitewide_plugins', $list); }
            else { $list[] = $plugin; sort($list); update_option('active_plugins', $list); }
        } catch (\Throwable $error) { /* Fails closed on plugins_loaded. */ }
    }
    // Intentional deactivation is never silent; it works even while the plugin's own code is paused.
    add_action('deactivated_plugin', static function ($deactivated) use ($plugin) {
        if ($deactivated === $plugin) { delete_site_option('azwp_passkeys_watchdog'); }
    });
    add_action('plugins_loaded', static function () use ($state, $facts, $network) {
        if ($state($facts()) === 'running') { return; }
        $passkey_only = static function () use ($network) {
            $settings = $network ? get_site_option('azwp_passkeys_network_settings') : get_option('azwp_passkeys_settings');
            return is_array($settings) && !empty($settings['passkey_only']);
        };
        $application_users = [];
        add_action('application_password_did_authenticate', static function ($user) use (&$application_users) {
            if ($user instanceof \WP_User) { $application_users[(int) $user->ID] = true; }
        });
        add_filter('authenticate', static function ($user) use (&$application_users, $passkey_only) {
            if (!$user instanceof \WP_User) { return $user; }
            $id = (int) $user->ID;
            if (isset($application_users[$id])) { unset($application_users[$id]); return $user; }
            return $passkey_only() || get_user_meta($id, 'azwp_passkeys_password_disabled', true) ? new \WP_Error('authentication_failed', __('Sign-in failed. Please try again.', 'azwp-passkeys')) : $user;
        }, PHP_INT_MAX);
        add_filter('allow_password_reset', static function ($allowed) use ($passkey_only) {
            if (is_wp_error($allowed) || !$allowed) { return $allowed; }
            $settings = get_option('azwp_passkeys_settings');
            $mode = $passkey_only() ? 'everyone' : (is_array($settings) && isset($settings['reset_restriction']) ? $settings['reset_restriction'] : 'off');
            return $mode === 'off' || ($mode === 'except_admin' && current_user_can('edit_users'));
        }, PHP_INT_MAX);
        $notice = static function () use ($network) {
            if (!current_user_can($network ? 'manage_network_plugins' : 'activate_plugins')) { return; }
            echo '<div class="notice notice-error"><p>' . esc_html__('AZ\'s WP Passkeys is not running, so password sign-in stays blocked for accounts that use passkeys only. Restore the plugin, or delete wp-content/mu-plugins/azwp-passkeys-watchdog.php to lift the block.', 'azwp-passkeys') . '</p></div>';
        };
        add_action('admin_notices', $notice);
        add_action('network_admin_notices', $notice);
    }, 0);
});
