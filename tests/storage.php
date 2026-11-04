<?php
/** Integration checks. Run only in a disposable WordPress database. */
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true) {
    throw new RuntimeException('A disposable WordPress test bootstrap is required.');
}
require_once dirname(__DIR__) . '/autoload.php';
require_once ABSPATH . 'wp-admin/includes/user.php';

use AZWP\Passkeys\Storage;
use AZWP\Passkeys\Settings;

$checks = 0;
$assert = static function (bool $condition, string $label) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($label); }
    ++$checks;
};
$storage = new Storage($GLOBALS['wpdb']);
$settings = new Settings($storage);
$assert($storage->install_schema()['ok'], 'Transactional schema installs');
$assert($storage->install_schema()['ok'], 'Schema installation is idempotent');
$user_id = wp_insert_user(['user_login' => 'azwp_storage_' . bin2hex(random_bytes(6)), 'user_pass' => wp_generate_password(), 'role' => 'subscriber']);
if (is_wp_error($user_id)) { throw new RuntimeException('Test user creation failed'); }
$original_settings = get_option('azwp_passkeys_settings', null);
$site_id = get_current_blog_id();
try {
    $identity = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->get_identity($user_id));
    $assert($identity['ok'] && strlen($identity['data']['identity']['handle']) === 32 && (int) $identity['data']['identity']['enrollment_initialized'] === 0, 'Lock provisioning does not initialize enrollment');
    $initialized = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->initialize_identity($user_id));
    $assert($initialized['ok'] && $initialized['data']['identity']['handle'] === $identity['data']['identity']['handle'], 'Enrollment retains stable handle');
    $row = ['user_id'=>$user_id,'site_id'=>$site_id,'credential_id'=>"\0".random_bytes(64),'rp_id'=>'example.test','public_key_pem'=>'validated PEM fixture','public_key_cose'=>"\xa1\x01\x02",'credential_type'=>'public-key','attestation_type'=>'none','trust_path'=>[],'aaguid'=>str_repeat("\0",16),'other_ui'=>null,'algorithm'=>-7,'sign_count'=>0,'backup_eligible'=>false,'backed_up'=>false,'transports'=>['internal'],'name'=>'Test passkey','created_at'=>time(),'created_local'=>current_time('mysql'),'last_used_local'=>null];
    $saved = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->insert_credential($row));
    $assert($saved['ok'], 'Credential insert confirmed');
    $record_id = $saved['data']['credential']['id'];
    $found = $storage->find_credential($row['credential_id']);
    $assert($found['ok'] && $found['data']['credential']['credential_id'] === $row['credential_id'] && $found['data']['credential']['aaguid'] === str_repeat("\0",16), 'Binary credential and zero AAGUID round-trip');
    $duplicate = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->insert_credential($row));
    $assert(!$duplicate['ok'] && $duplicate['code'] === 'credential_exists', 'Duplicate enrollment is rejected');
    $renamed = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->update_credential($record_id, ['name'=>'New name']));
    $unchanged = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->update_credential($record_id, ['name'=>'New name']));
    $assert($renamed['ok'] && $unchanged['ok'], 'Rename and confirmed no-op both succeed');
    $outside = $storage->update_credential($record_id, ['name'=>'Unsafe']);
    $assert(!$outside['ok'], 'Mutation requires owner transaction');
    $rollback = $storage->with_owner_lock($user_id, static function (Storage $store) use ($record_id): array {
        $store->update_credential($record_id, ['name'=>'Rolled back']);
        return ['ok'=>false,'code'=>'state_changed','data'=>[],'message'=>''];
    });
    $assert(!$rollback['ok'] && $storage->get_credential($record_id)['data']['credential']['name'] === 'New name', 'Failed operation rolls back stored changes');
    $attempt_bytes = random_bytes(32);
    $attempt_id = rtrim(strtr(base64_encode($attempt_bytes), '+/', '-_'), '=');
    $binding = ['site_id'=>$site_id,'purpose'=>'login','actor_id'=>0,'browser_hash'=>hash('sha256','browser',true),'session_hash'=>null];
    $attempt = $storage->create_attempt(['id'=>$attempt_bytes,'site_id'=>$site_id,'purpose'=>'login','actor_id'=>null,'target_id'=>$user_id,'browser_hash'=>$binding['browser_hash'],'session_hash'=>null,'challenge'=>random_bytes(32),'issued'=>['mode'=>'named'],'created_at'=>time(),'expires_at'=>time()+90]);
    $assert($attempt['ok'], 'Attempt created');
    $wrong = $storage->claim_attempt($attempt_id, array_replace($binding, ['browser_hash'=>hash('sha256','wrong',true)]));
    $assert(!$wrong['ok'], 'Wrong browser cannot consume attempt');
    $claim = $storage->claim_attempt($attempt_id, $binding);
    $again = $storage->claim_attempt($attempt_id, $binding);
    $assert($claim['ok'] && !$again['ok'], 'Anonymous binding and single claim hold');
    $storage->delete_attempt($attempt_id);
    $flag = $storage->save_password_policy($user_id, true);
    $assert($flag['ok'] && $storage->password_disabled($user_id), 'Password flag persistence confirmed');
    $diag = $settings->save_diagnostics(['logging'=>'1']);
    $assert($diag['ok'], 'Diagnostics save accepts declared form representation');
    $before = $settings->get_effective($site_id);
    $form = ['rp_name'=>'Test site','rp_id'=>'example.test','preferred_login'=>'passkey','remember_login'=>'1','reset_restriction'=>'off','after_registration'=>'add_passkey'];
    $settings_result = $settings->save_site($form);
    $assert($settings_result['ok'] && $settings->get_effective($site_id)['after_registration'] === (is_multisite() ? 'default' : 'add_passkey'), 'After registration saves only on single-site');
    if (!is_multisite()) {
        $missing = $settings->save_site(array_diff_key($form, ['after_registration'=>true]));
        $assert(!$missing['ok'] && in_array('after_registration', $missing['data']['invalid'], true), 'Single-site save requires After registration');
    }
    $assert($settings_result['ok'] && $settings->get_effective($site_id)['logging'] === true, 'Site settings retain diagnostics state');
    foreach (['127.0.0.1', '10.0.0.5', '2130706433'] as $ip) {
        $rejected = $settings->save_site(array_replace($form, ['rp_id'=>$ip]));
        $assert(!$rejected['ok'] && in_array('rp_id', $rejected['data']['invalid'], true), "Passkey domain rejects IP address $ip");
    }
    $assert($settings->save_site(array_replace($form, ['rp_id'=>'localhost']))['ok'], 'Passkey domain accepts localhost');
    $settings->save_site($form);
    $invalid = $settings->save_site(array_replace($form, ['remember_login'=>'invalid']));
    $assert(!$invalid['ok'] && $settings->get_effective($site_id)['remember_login'] === true, 'Invalid site save does not overwrite stored state');
    $storage->append_log($site_id, ['event'=>'authentication','result'=>'ok','detail'=>['password'=>'secret','code'=>'ok']]);
    $logs = $storage->read_logs($site_id);
    $last = end($logs['data']['entries']);
    $assert($logs['ok'] && !array_key_exists('password', $last['detail']) && $last['detail']['code'] === 'ok', 'Log fields are allow-listed');
    $removed = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->delete_credential($record_id));
    $assert($removed['ok'] && $storage->get_credential($record_id)['data']['credential'] === null, 'Deletion confirms absence');
    echo "Storage integration: $checks checks passed.\n";
} finally {
    $storage->cleanup_user($user_id);
    wp_delete_user($user_id);
    if ($original_settings === null) { delete_option('azwp_passkeys_settings'); }
    else { update_option('azwp_passkeys_settings', $original_settings, false); }
}
