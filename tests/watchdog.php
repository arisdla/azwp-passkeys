<?php
/** Watchdog behavior across real bootstraps: every check runs in a fresh wp process against the disposable test site. */
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true || !defined('AZWP_PASSKEYS_FILE')) {
    throw new RuntimeException('A disposable WordPress test bootstrap with the plugin loaded is required.');
}
require_once dirname(__DIR__) . '/autoload.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
if (is_multisite()) { require_once ABSPATH . 'wp-admin/includes/ms.php'; }

use AZWP\Passkeys\Storage;
use AZWP\Passkeys\Lifecycle;

$checks = 0;
$assert = static function (bool $condition, string $label) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($label); }
    ++$checks;
};
$network = is_multisite();
$plugin = plugin_basename(AZWP_PASSKEYS_FILE);
$guard = ['plugin' => $plugin, 'version' => AZWP_PASSKEYS_VERSION];
$base = 'wp --url=http://localhost:8090 --path=' . escapeshellarg(ABSPATH);
$cli = static function (string $args) use ($base): void {
    exec("$base $args 2>&1", $output, $status);
    if ($status !== 0) { throw new RuntimeException("wp $args failed: " . implode("\n", $output)); }
};
$wp = static function (string $code, string $flags = '') use ($base): mixed {
    $marker = 'AZWP_WATCHDOG_RESULT:';
    $script = 'require_once ABSPATH . "wp-admin/includes/plugin.php"; echo "\n' . $marker . '", wp_json_encode((static function () { ' . $code . ' })());';
    exec("$base $flags eval " . escapeshellarg($script) . ' 2>&1', $output, $status);
    foreach ($output as $line) { if (str_starts_with($line, $marker)) { return json_decode(substr($line, strlen($marker)), true); } }
    throw new RuntimeException("wp $flags eval failed: " . implode("\n", $output));
};
$probe = static fn(string $flags = ''): array => $wp('$plugin = ' . var_export($plugin, true) . '; return ["active" => ' . ($network ? 'is_plugin_active_for_network($plugin)' : 'is_plugin_active($plugin)') . ', "loaded" => defined("AZWP_PASSKEYS_VERSION"), "guard" => get_site_option("azwp_passkeys_watchdog"), "file" => is_file(WPMU_PLUGIN_DIR . "/azwp-passkeys-watchdog.php"), "retry" => (bool) get_site_transient("azwp_passkeys_watchdog_retry")];', $flags);
$admin_notices = static fn(string $flags = ''): string => $wp('$admin = ' . ($network ? 'get_user_by("login", get_super_admins()[0])' : 'get_users(["role" => "administrator", "number" => 1])[0]') . '; wp_set_current_user($admin->ID); ob_start(); do_action("admin_notices"); return ob_get_clean();', $flags);
$network_flag = $network ? ' --network' : '';
$skip = '--skip-plugins=azwp-passkeys';
$installed = Lifecycle::watchdog_file();
$source = dirname(__DIR__) . '/watchdog/azwp-passkeys-watchdog.php';

$storage = new Storage($GLOBALS['wpdb']);
$policy_scope = $network ? ['network', (int) get_current_network_id()] : ['site', get_current_blog_id()];
$options_before = ['azwp_passkeys_settings' => get_option('azwp_passkeys_settings', null)];
$network_before = $network ? get_site_option('azwp_passkeys_network_settings', null) : null;
$hello_before = $wp('return is_plugin_active("hello.php");');
$blocker = tempnam(sys_get_temp_dir(), 'azwp-watchdog');
$require = $blocker . '.php';
file_put_contents($require, "<?php define('WPMU_PLUGIN_DIR', " . var_export($blocker . '/mu-plugins', true) . ');');
$users = [];
try {
    $cli("plugin deactivate azwp-passkeys$network_flag");
    $state = $probe();
    $assert(!$state['active'] && $state['guard'] === false && !$state['file'], 'Intentional deactivation removes the watchdog and its guard');
    $state = $probe();
    $assert(!$state['active'] && !$state['loaded'], 'After intentional deactivation the plugin stays inactive');
    $cli("plugin activate azwp-passkeys$network_flag");
    $state = $probe();
    $assert($state['active'] && $state['loaded'] && $state['guard'] === $guard && $state['file'] && hash_file('sha256', $installed) === hash_file('sha256', $source), 'Activation installs the watchdog and arms the guard');

    $wp('deactivate_plugins(' . var_export($plugin, true) . ', true); return true;');
    $state = $probe();
    $assert($state['active'] && $state['loaded'] && $state['guard'] === $guard, 'The next request reactivates a silently deactivated plugin');

    $wp('deactivate_plugins(' . var_export($plugin, true) . '); return true;', $skip);
    $state = $probe();
    $assert(!$state['active'] && !$state['loaded'] && $state['guard'] === false, 'Intentional deactivation while the plugin is not loaded disarms the watchdog');
    $cli("plugin activate azwp-passkeys$network_flag");

    if (!$hello_before) { $cli("plugin activate hello$network_flag"); }
    $stored = static fn(): array => $wp('return ' . ($network ? 'get_site_option("active_sitewide_plugins")' : 'get_option("active_plugins")') . ';');
    $before = $stored();
    $wp('return true;', '--skip-plugins');
    $assert($stored() === $before, 'A request that hides an active plugin leaves the stored plugin list unchanged');
    $wp('deactivate_plugins(' . var_export($plugin, true) . ', true); return true;');
    $wp('return true;', '--skip-plugins');
    $active = $wp('return [is_plugin_active("hello.php"), is_plugin_active(' . var_export($plugin, true) . ')];');
    $assert($active === [true, true], 'Reactivating from a request that hides every plugin keeps the other plugins active');
    if (!$hello_before) { $cli("plugin deactivate hello$network_flag"); }

    $password = wp_generate_password(24);
    foreach (['disabled', 'normal'] as $name) {
        $id = wp_insert_user(['user_login' => 'azwp_watchdog_' . $name . '_' . bin2hex(random_bytes(4)), 'user_pass' => $password, 'role' => 'subscriber']);
        if (is_wp_error($id)) { throw new RuntimeException('Could not create test user'); }
        $users[$name] = (int) $id;
    }
    $assert($storage->save_password_policy($users['disabled'], true)['ok'], 'The password-disabled fixture is saved');
    $sign_in = static fn(string $flags = ''): array => $wp('$result = []; foreach (' . var_export(array_map(static fn(int $id): string => get_userdata($id)->user_login, $users), true) . ' as $name => $login) { $user = wp_authenticate($login, ' . var_export($password, true) . '); $result[$name] = is_wp_error($user) ? $user->get_error_code() : "signed_in"; } $result["reset"] = wp_is_password_reset_allowed_for_user(' . $users['normal'] . ') === true; $result["loaded"] = defined("AZWP_PASSKEYS_VERSION"); return $result;', $flags);
    $result = $sign_in($skip);
    $assert(!$result['loaded'] && $result['disabled'] === 'authentication_failed' && $result['normal'] === 'signed_in' && $result['reset'], 'While the plugin is not loaded, a password-disabled account cannot sign in with a password and others can');
    $assert(str_contains($admin_notices($skip), 'is not running'), 'While the plugin is not loaded, administrators see the fail-closed notice');
    $storage->save_settings($policy_scope[0], $policy_scope[1], ['passkey_only' => true]);
    $result = $sign_in($skip);
    $assert($result['disabled'] === 'authentication_failed' && $result['normal'] === 'authentication_failed' && !$result['reset'], 'While the plugin is not loaded, Passkey only mode blocks password sign-in and resets for everyone');
    $storage->save_settings($policy_scope[0], $policy_scope[1], ['passkey_only' => false]);
    $storage->save_settings('site', get_current_blog_id(), ['reset_restriction' => 'everyone']);
    $result = $sign_in($skip);
    $assert($result['normal'] === 'signed_in' && !$result['reset'], 'While the plugin is not loaded, the reset restriction still blocks resets');
    $storage->save_settings('site', get_current_blog_id(), ['reset_restriction' => 'off']);
    $result = $sign_in();
    $assert($result['loaded'] && $result['disabled'] === 'authentication_failed' && $result['normal'] === 'signed_in' && $result['reset'], 'With the plugin loaded, the plugin enforces the same policy');

    unlink($installed);
    $state = $probe();
    $assert($state['file'] && hash_file('sha256', $installed) === hash_file('sha256', $source), 'A loaded plugin reinstalls a deleted watchdog');
    $wp('update_site_option("azwp_passkeys_watchdog", ["plugin" => ' . var_export($plugin, true) . ', "version" => "0.0.1"]); return true;', $skip);
    $state = $probe();
    $assert($state['guard'] === $guard, 'A loaded plugin rearms a guard left by another version');

    $cli("plugin deactivate azwp-passkeys$network_flag");
    $cli("--require=" . escapeshellarg($require) . " plugin activate azwp-passkeys$network_flag");
    $state = $probe('--require=' . escapeshellarg($require));
    $assert($state['active'] && $state['loaded'] && !$state['file'] && $state['guard'] === false && $state['retry'], 'A failed watchdog install does not block activation and sets the retry delay');
    $assert(str_contains($admin_notices('--require=' . escapeshellarg($require)), 'Deactivation protection'), 'Administrators see that deactivation protection is off');
    $state = $probe();
    $assert(!$state['file'] && $state['guard'] === false, 'The install waits for the retry delay');
    $wp('delete_site_transient("azwp_passkeys_watchdog_retry"); return true;', $skip);
    $state = $probe();
    $assert($state['file'] && $state['guard'] === $guard && !$state['retry'], 'The install succeeds after the retry delay');
    $assert(!str_contains($admin_notices(), 'Deactivation protection'), 'The deactivation protection notice clears once the watchdog is installed');

    $cli("plugin deactivate azwp-passkeys$network_flag");
    $wp('update_site_option("azwp_passkeys_watchdog", ' . var_export($guard, true) . '); copy(' . var_export($source, true) . ', WPMU_PLUGIN_DIR . "/azwp-passkeys-watchdog.php"); uninstall_plugin(' . var_export($plugin, true) . '); return true;');
    $state = $probe();
    $assert(!$state['active'] && $state['guard'] === false && !$state['file'], 'Uninstall removes the watchdog and its guard');
    echo "Watchdog integration: $checks checks passed.\n";
} finally {
    if (!$wp('return is_plugin_active(' . var_export($plugin, true) . ');')) { $cli("plugin activate azwp-passkeys$network_flag"); }
    if (!$hello_before && $wp('return is_plugin_active("hello.php");')) { $cli("plugin deactivate hello$network_flag"); }
    wp_cache_flush();
    foreach ($users as $id) {
        if (get_userdata($id)) { if ($network) { wpmu_delete_user($id); } else { wp_delete_user($id); } }
        $storage->cleanup_user($id, null, true);
    }
    foreach ($options_before as $option => $value) { if ($value === null) { delete_option($option); } else { update_option($option, $value); } }
    if ($network) { if ($network_before === null) { delete_site_option('azwp_passkeys_network_settings'); } else { update_site_option('azwp_passkeys_network_settings', $network_before); } }
    @unlink($require);
    @unlink($blocker);
}
