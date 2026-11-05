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
$settings = new Settings($storage);
$lifecycle = new Lifecycle($settings, $storage);
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
    echo "Lifecycle integration: $checks checks passed.\n";
} finally {
    if (get_userdata($user_id)) { if (is_multisite()) { wpmu_delete_user($user_id); } else { wp_delete_user($user_id); } }
    $storage->cleanup_user($user_id, null, true);
    $lifecycle->deactivate(is_multisite());
}
