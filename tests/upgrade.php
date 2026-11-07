<?php
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true || !defined('AZWP_PASSKEYS_FILE')) {
    throw new RuntimeException('A disposable WordPress test bootstrap with the plugin loaded is required.');
}
require_once ABSPATH . 'wp-admin/includes/user.php';
if (is_multisite()) { require_once ABSPATH . 'wp-admin/includes/ms.php'; }

use AZWP\Passkeys\{Lifecycle, Logs, Settings, Storage};

$checks = 0;
$assert = static function (bool $condition, string $label) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($label); }
    ++$checks;
};
$db = $GLOBALS['wpdb'];
$site = get_current_blog_id();
$network = get_current_network_id();
$main_network = get_main_network_id();
$storage = new Storage($db);
$schemas = require __DIR__ . '/fixtures/schema-030.php';
$suffix = bin2hex(random_bytes(4));
$prefix = $db->base_prefix . 'azwp_passkeys_';
$tables = [];
foreach ([...array_keys($schemas), 'events'] as $name) { $tables[$name] = $prefix . $name; }
$exists = static fn(string $table): bool => $db->get_var($db->prepare('SHOW TABLES LIKE %s', $db->esc_like($table))) === $table;
$backups = [];
foreach ($tables as $table) {
    if ($exists($table)) { $backups[$table] = $table . '_' . $suffix; }
}
$rename = static function (array $from_to) use ($db, $assert): void {
    if (!$from_to) { return; }
    $pairs = [];
    foreach ($from_to as $from => $to) { $pairs[] = "`$from` TO `$to`"; }
    $assert($db->query('RENAME TABLE ' . implode(', ', $pairs)) !== false, 'Could not swap test tables');
};
$option = 'azwp_passkeys_settings';
$network_option = 'azwp_passkeys_network_settings';
$site_before = get_option($option, null);
$network_before = get_network_option($network, $network_option, null);
$version_before = get_network_option($main_network, Lifecycle::SCHEMA_OPTION, null);
$retry = Lifecycle::UPGRADE_RETRY;
$retry_before = get_site_transient($retry);
$retry_timeout = (int) get_site_option('_site_transient_timeout_' . $retry);
$user = null;

$rename($backups);
try {
    $user = wp_insert_user(['user_login' => 'azwp_upgrade_' . $suffix, 'user_pass' => wp_generate_password(), 'role' => 'subscriber']);
    $assert(!is_wp_error($user), 'Fixture owner exists');
    foreach ($schemas as $name => $schema) {
        $assert($db->query("CREATE TABLE `{$tables[$name]}` $schema " . $db->get_charset_collate()) !== false, "Created the v0.3.0 $name table");
    }
    $now = time();
    $local = current_time('mysql');
    $credential = "\0%\xff" . random_bytes(64);
    $attempt = random_bytes(32);
    $browser = random_bytes(32);
    $rows = [
        'identities' => ['user_id' => $user, 'handle' => random_bytes(64), 'enrollment_initialized' => 1, 'created_at' => $now],
        'credentials' => [
            'id' => 12, 'user_id' => $user, 'site_id' => $site,
            'credential_hash' => hash('sha256', $credential, true), 'credential_id' => $credential,
            'rp_id' => 'localhost', 'public_key_pem' => 'fixture PEM', 'public_key_cose' => "\xa1\x01\x02",
            'credential_type' => 'public-key', 'attestation_type' => 'none', 'trust_path' => '[]',
            'aaguid' => random_bytes(16), 'other_ui' => null, 'algorithm' => -7, 'sign_count' => 17,
            'backup_eligible' => 1, 'backed_up' => 1, 'transports' => '["internal"]',
            'name' => 'Clé ancienne 🔑', 'created_at' => $now, 'created_local' => $local, 'last_used_local' => $local,
        ],
        'attempts' => [
            'id' => $attempt, 'site_id' => $site, 'purpose' => 'login', 'actor_id' => null, 'target_id' => $user,
            'browser_hash' => $browser, 'session_hash' => null, 'challenge' => random_bytes(32),
            'issued' => '{"mode":"named"}', 'status' => 'pending', 'created_at' => $now, 'expires_at' => $now + 300,
        ],
        'logs' => [
            'id' => 1, 'site_id' => $site, 'occurred_at' => $now, 'event' => 'credential_test',
            'actor_id' => $user, 'target_id' => $user, 'result' => 'ok', 'correlation_id' => $suffix . str_repeat('0', 24),
            'detail' => '{"name":"v0.3.0 fixture"}',
        ],
    ];
    foreach ($rows as $name => $row) {
        $assert($db->insert($tables[$name], $row) === 1, "Seeded v0.3.0 $name data");
    }
    $site_settings = ['rp_name' => 'Upgrade fixture', 'rp_id' => 'localhost', 'logging' => false, 'remember_login' => true, 'reset_restriction' => 'except_admin'];
    $network_settings = ['passkey_only' => false, 'related_origins' => ['https://example.test']];
    update_option($option, is_multisite() ? $site_settings : $site_settings + $network_settings);
    if (is_multisite()) { update_network_option($network, $network_option, $network_settings); }
    update_user_meta($user, 'azwp_passkeys_password_disabled', '1');

    $snapshot = static function () use ($db, $tables, $option, $network, $network_option, $user): array {
        return [
            'identity' => $db->get_row("SELECT * FROM `{$tables['identities']}`", ARRAY_A),
            'credential' => $db->get_row("SELECT * FROM `{$tables['credentials']}`", ARRAY_A),
            'attempt' => $db->get_row("SELECT * FROM `{$tables['attempts']}`", ARRAY_A),
            'site' => get_option($option),
            'network' => get_network_option($network, $network_option),
            'policy' => get_user_meta($user, 'azwp_passkeys_password_disabled', true),
        ];
    };
    $before = $snapshot();
    $legacy_log = $db->get_row("SELECT * FROM `{$tables['logs']}`", ARRAY_A);
    $version = static fn(): int => (int) get_network_option($main_network, Lifecycle::SCHEMA_OPTION, 1);
    delete_network_option($main_network, Lifecycle::SCHEMA_OPTION);
    delete_site_transient($retry);

    $deny_drop = static fn(string $sql): string => $sql === "DROP TABLE IF EXISTS `{$tables['logs']}`" ? "DROP TABLE `{$prefix}missing_$suffix`" : $sql;
    $suppressed = $db->suppress_errors(true);
    add_filter('query', $deny_drop);
    try { do_action('plugins_loaded'); }
    finally { remove_filter('query', $deny_drop); $db->suppress_errors($suppressed); }
    $assert($version() === 1 && (bool) get_site_transient($retry) && $exists($tables['events']), 'Failed legacy DROP leaves the schema version pending and schedules retry');
    $assert($snapshot() === $before && $db->get_row("SELECT * FROM `{$tables['logs']}`", ARRAY_A) === $legacy_log, 'Partial upgrade preserves account data and legacy logs');
    do_action('plugins_loaded');
    $assert($version() === 1 && $exists($tables['logs']), 'The retry delay prevents another upgrade attempt');

    delete_site_transient($retry);
    do_action('plugins_loaded');
    $assert($version() === 2 && !$exists($tables['logs']), 'Successful retry records schema version 2 and removes old diagnostic history');
    $assert($snapshot() === $before, 'Upgrade preserves account data and settings byte for byte');
    $settings = (new Settings($storage, new Logs($storage)))->get_effective($site);
    $assert(!$settings['logging'] && $settings['remember_login'] && $settings['related_origins'] === ['https://example.test'] && $storage->password_disabled($user), 'Saved settings and password policy remain effective');

    delete_network_option($main_network, Lifecycle::SCHEMA_OPTION);
    do_action('plugins_loaded');
    $assert($version() === 2 && $snapshot() === $before && !$exists($tables['logs']), 'Repeating the upgrade preserves account data and settings');
    $renamed = $storage->with_owner_lock($user, static fn(Storage $store): array => $store->update_credential(12, ['name' => 'Renamed after upgrade']));
    $assert($renamed['ok'] && $db->get_var("SELECT name FROM `{$tables['credentials']}` WHERE id=12") === 'Renamed after upgrade', 'The upgraded credential remains writable');
    $binding = ['site_id' => $site, 'purpose' => 'login', 'actor_id' => 0, 'target_id' => $user, 'browser_hash' => $browser, 'session_hash' => null];
    $attempt_id = rtrim(strtr(base64_encode($attempt), '+/', '-_'), '=');
    $assert($storage->claim_attempt($attempt_id, $binding)['ok'], 'The pending v0.3.0 attempt remains claimable');
    (new Logs($storage))->record('passkey.tested', ['enabled' => true, 'target_id' => $user]);
    $assert($db->get_var("SELECT event FROM `{$tables['events']}`") === 'passkey.tested', 'The new event log accepts writes');
    echo "Historical upgrade integration: $checks checks passed.\n";
} finally {
    if (is_int($user)) {
        if (is_multisite()) { wpmu_delete_user($user); } else { wp_delete_user($user); }
    }
    if ($site_before === null) { delete_option($option); } else { update_option($option, $site_before); }
    if (is_multisite()) {
        if ($network_before === null) { delete_network_option($network, $network_option); } else { update_network_option($network, $network_option, $network_before); }
    }
    if ($version_before === null) { delete_network_option($main_network, Lifecycle::SCHEMA_OPTION); }
    else { update_network_option($main_network, Lifecycle::SCHEMA_OPTION, $version_before); }
    delete_site_transient($retry);
    if ($retry_before !== false) { set_site_transient($retry, $retry_before, $retry_timeout ? max(1, $retry_timeout - time()) : 0); }
    $assert($db->query('DROP TABLE IF EXISTS `' . implode('`, `', $tables) . '`') !== false, 'Removed the upgrade fixture tables');
    $rename(array_flip($backups));
}
