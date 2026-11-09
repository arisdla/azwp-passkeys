<?php
/**
 * Plugin Name: AZ's WP Passkeys
 * Description: Passkey sign-in and management for WordPress.
 * Version: 0.4.1
 * Author: Arthur Z.
 * Requires at least: 6.9
 * Requires PHP: 8.3
 * Tested up to: 7.1
 * License: GPL-3.0-or-later
 * Text Domain: azwp-passkeys
 * Domain Path: /languages
 * Network: true
 */
declare(strict_types=1);
if (!defined('ABSPATH')) { exit; }
define('AZWP_PASSKEYS_VERSION', '0.4.1');
define('AZWP_PASSKEYS_FILE', __FILE__);
define('AZWP_PASSKEYS_DIR', __DIR__ . '/');
define('AZWP_PASSKEYS_URL', plugin_dir_url(__FILE__));
require_once __DIR__ . '/autoload.php';
$azwp_passkeys_plugin = new AZWP\Passkeys\Plugin($GLOBALS['wpdb']);
$azwp_passkeys_plugin->register_hooks();
unset($azwp_passkeys_plugin);
// Updates come from GitHub releases, not WordPress.org.
YahnisElsts\PluginUpdateChecker\v6\PucFactory::buildUpdateChecker(
    'https://github.com/arisdla/azwp-passkeys/releases/download/latest/azwp-passkeys.json',
    AZWP_PASSKEYS_FILE,
    'azwp-passkeys'
);
