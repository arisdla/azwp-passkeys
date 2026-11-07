<?php
/** Lifecycle behavior in a disposable WordPress installation. */
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true) {
    throw new RuntimeException('A disposable WordPress test bootstrap is required.');
}
require_once dirname(__DIR__) . '/autoload.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
if (is_multisite()) { require_once ABSPATH . 'wp-admin/includes/ms.php'; }

use AZWP\Passkeys\Storage;
use AZWP\Passkeys\Settings;
use AZWP\Passkeys\Lifecycle;

$checks = 0;
$assert = static function (bool $condition, string $label) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($label); }
    ++$checks;
};
$storage = new Storage($GLOBALS['wpdb']);
$logs = new \AZWP\Passkeys\Logs($storage);
$settings = new Settings($storage, $logs);
$lifecycle = new Lifecycle($settings, $storage, $logs);
$lifecycle->activate(is_multisite());
$assert(wp_next_scheduled('azwp_passkeys_cleanup') !== false, 'Activation schedules cleanup');
$assert(!array_key_exists('username_free', $settings->get_effective(get_current_blog_id())), 'Settings have no usernameless switch');
$assert($settings->get_effective(get_current_blog_id())['passkey_only'] === false, 'Passkey only mode is off after activation');
$user_id = wp_insert_user(['user_login'=>'azwp_lifecycle_'.bin2hex(random_bytes(5)), 'user_pass'=>wp_generate_password(), 'role'=>'subscriber']);
if (is_wp_error($user_id)) { throw new RuntimeException('Could not create test user'); }
try {
    $storage->save_password_policy($user_id, true);
    $identity_before = $storage->get_identity($user_id)['data']['identity'];
    $row = ['user_id'=>$user_id,'site_id'=>get_current_blog_id(),'credential_id'=>random_bytes(64),'rp_id'=>'example.test','public_key_pem'=>'validated fixture','public_key_cose'=>"\xa1\x01\x02",'credential_type'=>'public-key','attestation_type'=>'none','trust_path'=>[],'aaguid'=>random_bytes(16),'other_ui'=>null,'algorithm'=>-7,'sign_count'=>0,'backup_eligible'=>false,'backed_up'=>false,'transports'=>[],'name'=>'Lifecycle fixture','created_at'=>time(),'created_local'=>current_time('mysql'),'last_used_local'=>null];
    $inserted = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->insert_credential($row));
    $assert($inserted['ok'], 'Lifecycle credential fixture saved');
    // A membership-only deleted_user notification must not erase an existing account.
    $lifecycle->delete_account($user_id);
    $assert(count($storage->get_credentials($user_id)['data']['credentials']) === 1, 'Existing account survives deleted_user notification');
    $lifecycle->remove_membership($user_id, get_current_blog_id());
    $assert($storage->get_credentials($user_id)['data']['credentials'] === [], 'Membership removal deletes site credentials');
    $assert($storage->password_disabled($user_id), 'Membership cleanup retains global account password flag');
    $assert($storage->get_identity($user_id)['data']['identity']['handle'] === $identity_before['handle'], 'Membership cleanup retains stable handle');
    $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->insert_credential($row));
    $lifecycle->deactivate(is_multisite());
    $assert(wp_next_scheduled('azwp_passkeys_cleanup') === false, 'Deactivation unschedules cleanup');
    $assert(count($storage->get_credentials($user_id)['data']['credentials']) === 1, 'Deactivation retains credentials');
    if (is_multisite()) { wpmu_delete_user($user_id); } else { wp_delete_user($user_id); }
    $lifecycle->delete_account($user_id);
    $assert($storage->get_credentials($user_id)['data']['credentials'] === [], 'Final account cleanup deletes credentials');
    $assert($storage->get_identity($user_id)['data']['identity'] === null, 'Final account cleanup deletes identity');
    $assert(!$storage->password_disabled($user_id), 'Final account cleanup deletes flag');
    $recreate = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->insert_credential($row));
    $assert(!$recreate['ok'] && $storage->get_identity($user_id)['data']['identity'] === null, 'Deleted account cannot recreate credential or handle');
    $wpdb = $GLOBALS['wpdb'];
    $events = $wpdb->base_prefix . 'azwp_passkeys_events';
    $legacy = $wpdb->base_prefix . 'azwp_passkeys_logs';
    $table_exists = static fn(string $name): bool => $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $name)) === $name;
    $version = static fn(): int => (int) get_network_option(get_main_network_id(), Lifecycle::SCHEMA_OPTION, 1);
    $as_030 = static function () use ($wpdb, $events, $legacy): void {
        delete_network_option(get_main_network_id(), Lifecycle::SCHEMA_OPTION);
        delete_site_transient(Lifecycle::UPGRADE_RETRY);
        $wpdb->query("DROP TABLE IF EXISTS `$events`");
        $wpdb->query("CREATE TABLE IF NOT EXISTS `$legacy` (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, PRIMARY KEY (id)) ENGINE=InnoDB");
    };
    $assert($version() === 2 && !$table_exists($legacy), 'Activation stores schema version 2 and leaves no legacy logs table');
    $as_030();
    $owner = (int) wp_insert_user(['user_login'=>'azwp_upgrade_'.bin2hex(random_bytes(4)), 'user_pass'=>wp_generate_password(), 'role'=>'subscriber']);
    try {
        $saved = $storage->with_owner_lock($owner, static fn(Storage $store): array => $store->insert_credential(['user_id'=>$owner,'credential_id'=>random_bytes(64),'name'=>'Before upgrade'] + $row));
        $renamed = $saved['ok'] ? $storage->with_owner_lock($owner, static fn(Storage $store): array => $store->update_credential((int) $saved['data']['credential']['id'], ['name'=>'Renamed before upgrade'])) : $saved;
        $assert($renamed['ok'], 'Before the upgrade runs, a passkey rename still succeeds');
    } finally { $storage->cleanup_user($owner); wp_delete_user($owner); }
    $break = static fn(string $query): string => str_starts_with($query, 'CREATE TABLE') ? 'CREATE TABLE broken' : $query;
    add_filter('query', $break);
    try { $lifecycle->upgrade(); } finally { remove_filter('query', $break); }
    $assert($version() === 1 && get_site_transient(Lifecycle::UPGRADE_RETRY) && $table_exists($legacy), 'A failed upgrade leaves the version unchanged and sets the retry delay');
    $lifecycle->upgrade();
    $assert($version() === 1 && !$table_exists($events), 'The upgrade skips during the retry delay');
    delete_site_transient(Lifecycle::UPGRADE_RETRY);
    $other = new wpdb(DB_USER, DB_PASSWORD, DB_NAME, DB_HOST);
    $lock = 'azwp-passkeys:' . substr(hash('sha256', DB_NAME . ':' . $wpdb->base_prefix), 0, 32) . ':upgrade';
    $assert((string) $other->get_var($other->prepare('SELECT GET_LOCK(%s,0)', $lock)) === '1', 'Another connection holds the upgrade lock');
    try { $lifecycle->upgrade(); } finally { $other->get_var($other->prepare('SELECT RELEASE_LOCK(%s)', $lock)); $other->close(); }
    $assert($version() === 1 && !$table_exists($events), 'The upgrade skips while another request holds the lock');
    do_action('plugins_loaded');
    $assert($version() === 2 && $table_exists($events) && !$table_exists($legacy), 'A 0.3.0 install upgrades on plugins_loaded');
    $logs->record('passkey.tested', ['enabled'=>true, 'correlation_id'=>$probe = bin2hex(random_bytes(16))]);
    $assert((int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `$events` WHERE correlation_id=%s", $probe)) === 1, 'A log write succeeds after the upgrade');
    $wpdb->delete($events, ['correlation_id'=>$probe]);
    $as_030();
    $lifecycle->activate(is_multisite());
    $assert($version() === 2 && $table_exists($events) && !$table_exists($legacy), 'Reactivating a 0.3.0 install drops the legacy logs table');

    $logging_before = $settings->get_site(get_current_blog_id())['logging'];
    $storage->save_settings('site', get_current_blog_id(), ['logging'=>true]);
    $rows_for = static fn(int $id): array => $wpdb->get_results($wpdb->prepare("SELECT * FROM `$events` WHERE target_id=%d", $id), ARRAY_A);
    $deleted = [];
    try {
        foreach (['two', 'none', 'member', 'failed'] as $name) {
            $id = wp_insert_user(['user_login'=>'azwp_cleanup_'.$name.'_'.bin2hex(random_bytes(4)), 'user_pass'=>wp_generate_password(), 'role'=>'subscriber']);
            if (is_wp_error($id)) { throw new RuntimeException('Could not create cleanup user'); }
            $deleted[$name] = (int) $id;
        }
        foreach (['two', 'two', 'member', 'failed'] as $name) {
            $storage->with_owner_lock($deleted[$name], static fn(Storage $store): array => $store->insert_credential(['user_id'=>$deleted[$name],'credential_id'=>random_bytes(64)] + $row));
        }
        $login = get_userdata($deleted['two'])->user_login;
        if (is_multisite()) { wpmu_delete_user($deleted['two']); } else { wp_delete_user($deleted['two']); }
        $rows = $rows_for($deleted['two']);
        $assert(count($rows) === 1 && $rows[0]['event'] === 'passkey.account_deleted' && $rows[0]['ok'] === '1' && json_decode($rows[0]['data'], true) === ['count'=>2] && $rows[0]['target_login'] === $login && (int) $rows[0]['site_id'] === get_current_blog_id(), 'Deleting a user with two passkeys writes one row with the count and the saved login');
        if (is_multisite()) { wpmu_delete_user($deleted['none']); } else { wp_delete_user($deleted['none']); }
        $assert($rows_for($deleted['none']) === [], 'Deleting a user with no passkeys writes no row');
        $lifecycle->remove_membership($deleted['member'], get_current_blog_id());
        $assert($storage->get_credentials($deleted['member'])['data']['credentials'] === [] && $rows_for($deleted['member']) === [], 'Removing a membership deletes the passkeys and writes no row');
        $break = static fn(string $query): string => str_starts_with($query, "DELETE FROM `{$wpdb->base_prefix}azwp_passkeys_credentials`") ? 'DELETE broken' : $query;
        add_filter('query', $break);
        try { $lifecycle->early_delete_account($deleted['failed'], get_userdata($deleted['failed'])); } finally { remove_filter('query', $break); }
        $rows = $rows_for($deleted['failed']);
        $assert(count($rows) === 1 && $rows[0]['ok'] === '0' && $rows[0]['code'] === 'storage_failed' && $rows[0]['data'] === null && count($storage->get_credentials($deleted['failed'])['data']['credentials']) === 1, 'A failed cleanup writes one failure row and keeps the passkeys');
    } finally {
        foreach ($deleted as $id) {
            if (get_userdata($id)) { if (is_multisite()) { wpmu_delete_user($id); } else { wp_delete_user($id); } }
            $storage->cleanup_user($id, null, true);
            $wpdb->delete($events, ['target_id'=>$id]);
        }
        $storage->save_settings('site', get_current_blog_id(), ['logging'=>$logging_before]);
    }
    $gone = 990000 + random_int(1, 9999);
    $kept = $gone + 1;
    try {
        foreach ([$gone, $gone, $kept] as $site) {
            $storage->insert_event(['site_id'=>$site,'occurred_at'=>time(),'event'=>'passkey.tested','ok'=>1,'code'=>'ok','correlation_id'=>bin2hex(random_bytes(16)),'actor_id'=>1,'actor_login'=>'admin','ip'=>'192.0.2.1']);
        }
        require_once ABSPATH . WPINC . '/class-wp-site.php';
        do_action('wp_delete_site', new WP_Site((object) ['blog_id'=>$gone]));
        $count = static fn(int $site): int => (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `$events` WHERE site_id=%d", $site));
        $assert($count($gone) === 0, "Deleting a site deletes that site's log entries");
        $assert($count($kept) === 1, "Deleting a site keeps other sites' log entries");
    } finally {
        $wpdb->query($wpdb->prepare("DELETE FROM `$events` WHERE site_id IN (%d,%d)", $gone, $kept));
    }
    echo "Lifecycle integration: $checks checks passed.\n";
} finally {
    if (get_userdata($user_id)) { if (is_multisite()) { wpmu_delete_user($user_id); } else { wp_delete_user($user_id); } }
    $storage->cleanup_user($user_id, null, true);
    $lifecycle->deactivate(is_multisite());
}
