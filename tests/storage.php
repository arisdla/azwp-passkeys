<?php
/** Integration checks. Run only in a disposable WordPress database. */
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true) {
    throw new RuntimeException('A disposable WordPress test bootstrap is required.');
}
require_once dirname(__DIR__) . '/autoload.php';
require_once ABSPATH . 'wp-admin/includes/user.php';

use AZWP\Passkeys\Storage;
use AZWP\Passkeys\Settings;
use AZWP\Passkeys\Passkeys;
use AZWP\Passkeys\WebAuthn;

$checks = 0;
$assert = static function (bool $condition, string $label) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($label); }
    ++$checks;
};
$storage = new Storage($GLOBALS['wpdb']);
$settings = new Settings($storage, new \AZWP\Passkeys\Logs($storage));
$passkeys = new Passkeys($settings, $storage, new WebAuthn());
$assert($storage->install_schema()['ok'], 'Transactional schema installs');
$assert($storage->install_schema()['ok'], 'Schema installation is idempotent');
$logs_table = $GLOBALS['wpdb']->base_prefix . 'azwp_passkeys_events';
$plugin_tables = array_map(static fn(string $name): string => $GLOBALS['wpdb']->base_prefix . 'azwp_passkeys_' . $name, ['identities', 'credentials', 'attempts', 'events']);
$engines = static fn(): array => $GLOBALS['wpdb']->get_col("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN ('" . implode("','", $plugin_tables) . "')");
$assert(array_unique(array_map('strtolower', $engines())) === ['innodb'], 'New tables use InnoDB');
$memory_table = $GLOBALS['wpdb']->base_prefix . 'azwp_passkeys_memory';
$GLOBALS['wpdb']->query("CREATE TABLE `$memory_table` (id INT NOT NULL) ENGINE=MEMORY");
$usermeta_table = $GLOBALS['wpdb']->usermeta;
$GLOBALS['wpdb']->usermeta = $memory_table;
try {
    $assert($storage->install_schema()['code'] === 'storage_engine', 'A MEMORY table reports the storage engine');
} finally {
    $GLOBALS['wpdb']->usermeta = $usermeta_table;
    $GLOBALS['wpdb']->query("DROP TABLE `$memory_table`");
}
$GLOBALS['wpdb']->usermeta = $GLOBALS['wpdb']->base_prefix . 'azwp_passkeys_missing';
try {
    $assert($storage->install_schema()['code'] === 'storage_failed', 'A missing table is not reported as the storage engine');
} finally {
    $GLOBALS['wpdb']->usermeta = $usermeta_table;
}
$user_id = wp_insert_user(['user_login' => 'azwp_storage_' . bin2hex(random_bytes(6)), 'user_pass' => wp_generate_password(), 'role' => 'subscriber']);
if (is_wp_error($user_id)) { throw new RuntimeException('Test user creation failed'); }
$original_settings = get_option('azwp_passkeys_settings', null);
$site_id = get_current_blog_id();
try {
    $identity = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->get_identity($user_id));
    $assert($identity['ok'] && strlen($identity['data']['identity']['handle']) === 64 && (int) $identity['data']['identity']['enrollment_initialized'] === 0, 'Lock provisioning does not initialize enrollment');
    $initialized = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->initialize_identity($user_id));
    $assert($initialized['ok'] && $initialized['data']['identity']['handle'] === $identity['data']['identity']['handle'], 'Enrollment retains stable handle');
    $row = ['user_id'=>$user_id,'site_id'=>$site_id,'credential_id'=>"\0%\xff".random_bytes(64),'rp_id'=>'example.test','public_key_pem'=>'validated PEM fixture','public_key_cose'=>"\xa1\x01\x02",'credential_type'=>'public-key','attestation_type'=>'none','trust_path'=>[],'aaguid'=>str_repeat("\0",16),'other_ui'=>null,'algorithm'=>-7,'sign_count'=>0,'backup_eligible'=>false,'backed_up'=>false,'transports'=>['internal'],'name'=>'Test passkey','created_at'=>time(),'created_local'=>current_time('mysql'),'last_used_local'=>null];
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
    $observer = $GLOBALS['wpdb'];
    $disconnect = static function (bool $delete_after_disconnect) use ($observer, $storage, $user_id, $record_id, $assert): array {
        $victim = new wpdb(DB_USER, DB_PASSWORD, DB_NAME, DB_HOST);
        $victim->set_prefix($observer->base_prefix);
        $victim->set_blog_id(get_current_blog_id());
        try {
            $connection_id = (int) $victim->get_var('SELECT CONNECTION_ID()');
            $assert($connection_id > 0 && $connection_id !== (int) $observer->get_var('SELECT CONNECTION_ID()'), 'The victim uses a separate database connection');
            $killed = false;
            $result = (new Storage($victim))->with_owner_lock($user_id, static function (Storage $store) use ($record_id, $observer, $connection_id, $delete_after_disconnect, &$killed): array {
                $changed = $store->update_credential($record_id, ['name'=>'Uncommitted name']);
                if (!$changed['ok']) { return $changed; }
                $killed = $observer->query("KILL CONNECTION $connection_id") !== false;
                return $delete_after_disconnect ? $store->delete_credential($record_id) : $changed;
            });
            $assert($killed, 'The observer disconnected the victim after a successful credential update');
            $observed = $storage->get_credential($record_id);
            $assert($observed['ok'], 'The observer can still read after the victim disconnects');
            return [$result['code'], $result['ok'], $observed['data']['credential']['name'] ?? null];
        } finally {
            $victim->close();
        }
    };
    $commit_loss = $disconnect(false);
    $mutation_loss = $disconnect(true);
    $assert(
        $commit_loss === ['outcome_unknown', false, 'New name'] && $mutation_loss === ['storage_failed', false, 'New name'],
        'Connection loss must fail without committing or replaying writes. Observed ' . wp_json_encode([$commit_loss, $mutation_loss])
    );
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
    $diag = $settings->save_logs(['logging'=>'1']);
    $assert($diag['ok'], 'Log page save accepts declared form representation');
    $form = ['rp_name'=>'Test site','rp_id'=>'example.test','passkey_only'=>'0','remember_login'=>'1','reset_restriction'=>'off','after_registration'=>'add_passkey'];
    $settings_result = $passkeys->save_settings_form('site', $form);
    $assert($settings_result['ok'] && $settings->get_effective($site_id)['after_registration'] === (is_multisite() ? 'default' : 'add_passkey'), 'After registration saves only on single-site');
    if (!is_multisite()) {
        $missing = $passkeys->save_settings_form('site', array_diff_key($form, ['after_registration'=>true]));
        $assert(!$missing['ok'] && in_array('after_registration', $missing['data']['invalid'], true), 'Single-site save requires After registration');
    }
    $assert($settings_result['ok'] && $settings->get_effective($site_id)['logging'] === true, 'Site settings retain the logging state');
    foreach (['127.0.0.1', '10.0.0.5', '2130706433'] as $ip) {
        $rejected = $passkeys->save_settings_form('site', array_replace($form, ['rp_id'=>$ip]));
        $assert(!$rejected['ok'] && in_array('rp_id', $rejected['data']['invalid'], true), "Passkey domain rejects IP address $ip");
    }
    $assert($passkeys->save_settings_form('site', array_replace($form, ['rp_id'=>'localhost']))['ok'], 'Passkey domain accepts localhost');
    $passkeys->save_settings_form('site', $form);
    $invalid = $passkeys->save_settings_form('site', array_replace($form, ['remember_login'=>'invalid']));
    $assert(!$invalid['ok'] && $settings->get_effective($site_id)['remember_login'] === true, 'Invalid site save does not overwrite stored state');
    $event = ['site_id'=>$site_id,'occurred_at'=>time(),'event'=>'passkey.tested','ok'=>1,'code'=>'ok','correlation_id'=>bin2hex(random_bytes(16)),'actor_id'=>$user_id,'actor_login'=>null,'target_id'=>null,'target_login'=>null,'passkey_id'=>$record_id,'passkey_name'=>'Test passkey','passkey_aaguid'=>str_repeat("\0",16),'data'=>null];
    $locked = $storage->with_owner_lock($user_id, static fn(Storage $store): array => ['ok'=>$store->insert_event($event),'code'=>'ok','data'=>[],'message'=>'']);
    $assert($locked['ok'] === false, 'An event write inside an owner transaction is skipped');
    $assert($storage->insert_event($event) && $storage->insert_event(['event'=>'passkey.deleted'] + $event), 'Event writes outside a transaction succeed');
    $page = $storage->read_events($site_id, ['passkey.tested','passkey.deleted'], true, 1, 20);
    $newest = $page['data']['rows'][0] ?? null;
    $assert($page['ok'] && $newest['event'] === 'passkey.deleted' && $page['data']['rows'][1]['event'] === 'passkey.tested' && $newest['actor_id'] === $user_id && $newest['passkey_aaguid'] === str_repeat("\0",16) && $newest['ok'] === true && $newest['data'] === [], 'Events read newest first with typed IDs and raw AAGUID');
    $GLOBALS['wpdb']->query($GLOBALS['wpdb']->prepare("DELETE FROM `$logs_table` WHERE correlation_id=%s", $event['correlation_id']));
    $removed = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->delete_credential($record_id));
    $assert($removed['ok'] && $storage->get_credential($record_id)['data']['credential'] === null, 'Deletion confirms absence');
    $myisam_tables = [...$plugin_tables, $usermeta_table, $GLOBALS['wpdb']->options];
    foreach ($myisam_tables as $table) { $GLOBALS['wpdb']->query("ALTER TABLE `$table` ENGINE=MyISAM"); }
    try {
        $assert($storage->install_schema()['ok'] && array_unique(array_map('strtolower', $engines())) === ['myisam'], 'MyISAM tables are accepted and not converted');
        $saved = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->insert_credential($row));
        $assert($saved['ok'], 'Credential insert works on MyISAM');
        $record_id = $saved['data']['credential']['id'];
        $renamed = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->update_credential($record_id, ['name'=>'MyISAM name']));
        $assert($renamed['ok'] && $storage->save_password_policy($user_id, false)['ok'] && !$storage->password_disabled($user_id), 'Rename and password flag work on MyISAM');
        // A flag write never deletes rows, so no request and no failure can find the flag missing.
        add_user_meta($user_id, 'azwp_passkeys_password_disabled', '0');
        $flags = static fn(): array => $GLOBALS['wpdb']->get_col($GLOBALS['wpdb']->prepare("SELECT meta_value FROM `$usermeta_table` WHERE user_id=%d AND meta_key=%s", $user_id, 'azwp_passkeys_password_disabled'));
        $assert($storage->save_password_policy($user_id, true)['ok'] && $flags() === ['1', '1'], 'Password flag updates every row in place on MyISAM');
        $assert($storage->save_password_policy($user_id, false)['ok'] && $flags() === ['0', '0'], 'Password flag clears every row in place on MyISAM');
        $kept = $storage->with_owner_lock($user_id, static function (Storage $store) use ($record_id): array {
            $store->update_credential($record_id, ['name'=>'Kept']);
            return ['ok'=>false,'code'=>'state_changed','data'=>[],'message'=>''];
        });
        $assert(!$kept['ok'] && $storage->get_credential($record_id)['data']['credential']['name'] === 'Kept', 'Failed operation keeps its writes on MyISAM');
        $oversized = ['credential_id'=>random_bytes(64), 'transports'=>array_map(static fn(int $i): string => "transport-$i-" . str_repeat('x', 20), range(1, 3000))] + $row;
        $rejected = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->insert_credential($oversized));
        $listed = $storage->get_credentials($user_id);
        $assert(!$rejected['ok'] && $listed['ok'] && array_column($listed['data']['credentials'], 'id') === [$record_id], 'A credential that fails its read-back is removed on MyISAM');
        $settings_before = $storage->read_site_settings($site_id);
        $invalid = $storage->save_settings('site', $site_id, ['rp_name'=>"Shop \xff"]);
        $assert(!$invalid['ok'] && $settings_before !== [] && $storage->read_site_settings($site_id) === $settings_before, 'A settings save that fails its read-back keeps the saved settings on MyISAM');
        $removed = $storage->with_owner_lock($user_id, static fn(Storage $store): array => $store->delete_credential($record_id));
        $assert($removed['ok'] && $storage->get_credential($record_id)['data']['credential'] === null, 'Deletion works on MyISAM');
    } finally {
        foreach ($myisam_tables as $table) { $GLOBALS['wpdb']->query("ALTER TABLE `$table` ENGINE=InnoDB"); }
    }
    echo "Storage integration: $checks checks passed.\n";
} finally {
    $storage->cleanup_user($user_id);
    wp_delete_user($user_id);
    if ($original_settings === null) { delete_option('azwp_passkeys_settings'); }
    else { update_option('azwp_passkeys_settings', $original_settings, false); }
}
