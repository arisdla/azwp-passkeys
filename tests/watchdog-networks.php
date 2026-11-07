<?php
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true || !defined('AZWP_PASSKEYS_FILE')) {
    throw new RuntimeException('A disposable WordPress test bootstrap with the plugin loaded is required.');
}
if (!is_multisite()) {
    echo "Skipped watchdog-networks.php: requires multisite.\n";
    return;
}
require_once ABSPATH . 'wp-admin/includes/ms.php';
require_once ABSPATH . 'wp-admin/includes/schema.php';

use AZWP\Passkeys\{Lifecycle, Storage};

$checks = 0;
$assert = static function (bool $condition, string $label) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($label); }
    ++$checks;
};
$cli = static function (string $url, string $args): array {
    $base = 'wp --path=' . escapeshellarg(ABSPATH) . ' --url=' . escapeshellarg($url);
    exec("$base $args 2>&1", $output, $status);
    if ($status !== 0) { throw new RuntimeException("wp $args failed: " . implode("\n", $output)); }
    return $output;
};
$wp = static function (string $url, string $code, string $flags = '') use ($cli): mixed {
    $marker = 'AZWP_WATCHDOG_RESULT:';
    $script = 'require_once ABSPATH . "wp-admin/includes/plugin.php"; echo "\n' . $marker . '", wp_json_encode((static function () { ' . $code . ' })());';
    $output = $cli($url, "$flags eval " . escapeshellarg($script));
    foreach ($output as $line) {
        if (str_starts_with($line, $marker)) { return json_decode(substr($line, strlen($marker)), true, 512, JSON_THROW_ON_ERROR); }
    }
    throw new RuntimeException("Missing watchdog result: " . implode("\n", $output));
};
$plugin = plugin_basename(AZWP_PASSKEYS_FILE);
$plugin_code = var_export($plugin, true);
$guard = ['plugin' => $plugin, 'version' => AZWP_PASSKEYS_VERSION];
$probe = static fn(string $url): array => $wp($url, 'return [
    "network" => get_current_network_id(),
    "active" => is_plugin_active_for_network(' . $plugin_code . '),
    "loaded" => defined("AZWP_PASSKEYS_VERSION"),
    "guard" => get_site_option("azwp_passkeys_watchdog"),
    "file" => is_file(WPMU_PLUGIN_DIR . "/azwp-passkeys-watchdog.php"),
    "retry" => (bool) get_site_transient("azwp_passkeys_watchdog_retry"),
];');

$db = $GLOBALS['wpdb'];
$suffix = bin2hex(random_bytes(4));
$domain = "azwp-watchdog-$suffix.example.test";
$url_a = get_site_url();
$url_b = 'http://' . $domain;
$network_a = get_current_network_id();
$assert($db->insert($db->site, ['domain' => $domain, 'path' => '/']) === 1, 'Created a second network');
$network_b = (int) $db->insert_id;
$site_b = null;
$user = null;
try {
    clean_network_cache($network_b);
    $admin = get_user_by('login', get_super_admins()[0]);
    $assert($admin instanceof WP_User, 'Found the test installation administrator');
    populate_network_meta($network_b, [
        'admin_email' => $admin->user_email,
        'site_admins' => [$admin->user_login],
        'site_name' => 'Watchdog fixture network',
        'subdomain_install' => false,
    ]);
    $site_b = wp_insert_site([
        'domain' => $domain, 'path' => '/', 'network_id' => $network_b,
        'user_id' => $admin->ID, 'title' => 'Watchdog fixture network',
        'options' => ['siteurl' => $url_b, 'home' => $url_b],
    ]);
    $assert(is_int($site_b), 'Created the second network’s main site');
    $assert($probe($url_a)['network'] === $network_a && $probe($url_b)['network'] === $network_b, 'Fresh requests select distinct networks');

    $cli($url_b, 'plugin activate azwp-passkeys --network');
    $a = $probe($url_a);
    $b = $probe($url_b);
    $assert($a['active'] && $a['guard'] === $guard && $b['active'] && $b['guard'] === $guard && $b['file'], 'Both active networks are armed');

    foreach ([$url_a, $url_b] as $url) {
        $wp($url, 'return set_site_transient("azwp_passkeys_watchdog_retry", 1, 300);');
    }
    $cli($url_a, 'plugin deactivate azwp-passkeys --network');
    clearstatcache();
    $assert(is_file(Lifecycle::watchdog_file()), 'Deactivating network A leaves the shared watchdog installed');
    $a = $probe($url_a);
    $assert(!$a['active'] && !$a['loaded'] && $a['guard'] === false && !$a['retry'], 'A fresh request leaves the deliberately deactivated network A dormant');
    $assert($wp($url_b, 'deactivate_plugins(' . $plugin_code . ', true, true); return !is_plugin_active_for_network(' . $plugin_code . ');'), 'Network B is inactive immediately after silent deactivation');
    $b = $probe($url_b);
    $assert($b['active'] && $b['loaded'] && $b['guard'] === $guard && $b['retry'], 'The shared watchdog recovers network B after silent deactivation');

    $password = wp_generate_password(24);
    $login = 'azwp_watchdog_network_' . $suffix;
    $user = wp_insert_user(['user_login' => $login, 'user_pass' => $password, 'role' => 'subscriber']);
    $assert(is_int($user) && add_user_to_blog($site_b, $user, 'subscriber') === true, 'Created a password-disabled fixture account on network B');
    $storage = new Storage($db);
    $assert($storage->save_password_policy($user, true)['ok'], 'Saved the fixture account’s password policy');
    $sign_in = 'if (defined("AZWP_PASSKEYS_VERSION")) { throw new RuntimeException("Expected a bootstrap without the main plugin"); }
        $user = wp_authenticate(' . var_export($login, true) . ', ' . var_export($password, true) . ');
        return is_wp_error($user) ? $user->get_error_code() : "signed_in";';
    $assert($wp($url_b, $sign_in, '--skip-plugins=azwp-passkeys') === 'authentication_failed', 'Network B blocks password sign-in when the main plugin cannot load');
    $assert($wp($url_a, $sign_in) === 'signed_in', 'The dormant watchdog imposes no password restrictions on network A');

    $cli($url_b, 'plugin deactivate azwp-passkeys --network');
    $b = $probe($url_b);
    $assert(!$b['active'] && !$b['loaded'] && $b['guard'] === false && !$b['retry'] && $b['file'], 'Deactivating the last armed network leaves a dormant watchdog file');

    $networks = var_export([$network_a, $network_b], true);
    $retries = var_export([Lifecycle::WATCHDOG_RETRY, Lifecycle::UPGRADE_RETRY], true);
    $wp($url_a, '
        foreach (' . $networks . ' as $network) {
            update_network_option($network, "azwp_passkeys_watchdog", ' . var_export($guard, true) . ');
            foreach (' . $retries . ' as $retry) {
                update_network_option($network, "_site_transient_" . $retry, 1);
                update_network_option($network, "_site_transient_timeout_" . $retry, time() + 300);
            }
        }
        uninstall_plugin(' . $plugin_code . ');
        return true;
    ');
    foreach ([$url_a, $url_b] as $url) {
        $state = $probe($url);
        $assert(!$state['active'] && !$state['file'] && $state['guard'] === false, "Uninstall removes the watchdog file and clears the guard on $url");
        $assert($wp($url, 'foreach (' . $retries . ' as $retry) {
            if (get_site_transient($retry) !== false || get_site_option("_site_transient_timeout_" . $retry) !== false) { return false; }
        }
        return true;'), "Uninstall removes both retry transients and their timeouts on $url");
    }
    echo "Watchdog multi-network integration: $checks checks passed.\n";
} finally {
    wp_cache_flush();
    if (!$probe($url_a)['active']) { $cli($url_a, 'plugin activate azwp-passkeys --network'); }
    wp_cache_flush();
    if (is_int($site_b)) { wp_delete_site($site_b); }
    $db->delete($db->sitemeta, ['site_id' => $network_b]);
    $db->delete($db->site, ['id' => $network_b]);
    clean_network_cache($network_b);
    if (is_int($user)) { wpmu_delete_user($user); }
}
