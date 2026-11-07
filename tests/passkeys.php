<?php
/** End-to-end service integration. Only for a disposable WordPress database. */
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true) {
    throw new RuntimeException('A disposable WordPress test bootstrap is required.');
}
require_once dirname(__DIR__) . '/autoload.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
require_once __DIR__ . '/fixtures.php';
use AZWP\Passkeys\{Storage, Settings, Passkeys, WebAuthn, Authentication, Ajax};

$storage = new Storage($GLOBALS['wpdb']);
$logs = new \AZWP\Passkeys\Logs($storage);
$settings = new Settings($storage, $logs);
$passkeys = new Passkeys($settings, $storage, new WebAuthn());
check('service schema available', $storage->install_schema()['ok']);
$site = (int) get_current_blog_id();
$original_settings = get_option('azwp_passkeys_settings', null);
$original_network = is_multisite() ? get_network_option(get_current_network_id(), 'azwp_passkeys_network_settings', null) : null;
$original_user = get_current_user_id();
$original_cookie = $_COOKIE[LOGGED_IN_COOKIE] ?? null;
$users = [];
$attempt_ids = [];
$authentication = null;
$owns_authentication_hooks = false;
$granted_super_admin = null;
$events_table = $GLOBALS['wpdb']->base_prefix.'azwp_passkeys_events';
/** Records an operation result as Ajax::dispatch does, then returns the stored row and the entry the reader builds from it. */
$logged = static function (string $action, array $result, int $actor, ?int $target) use ($logs, $site, $events_table): array {
    $correlation = bin2hex(random_bytes(16));
    $logs->record(Ajax::EVENTS[$action], ['enabled'=>true] + Ajax::log_fields($action, $result, $actor, $target, $correlation));
    $row = $GLOBALS['wpdb']->get_row($GLOBALS['wpdb']->prepare("SELECT * FROM `$events_table` WHERE correlation_id=%s", $correlation), ARRAY_A);
    $entry = null;
    foreach ($logs->read($site, [])['data']['entries'] ?? [] as $candidate) { if ($candidate['correlation_id'] === $correlation) { $entry = $candidate; } }
    $GLOBALS['wpdb']->delete($events_table, ['correlation_id'=>$correlation]);
    return ['row'=>$row ?: [], 'details'=>$entry['details'] ?? null];
};
$browser = hash('sha256', random_bytes(32), true);
$become = static function (int $user) use ($site, $browser): array {
    wp_set_current_user($user);
    $token = WP_Session_Tokens::get_instance($user)->create(time() + 3600);
    $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($user, time() + 3600, 'logged_in', $token);
    return ['site_id'=>$site,'network_id'=>is_multisite()?(int)get_current_network_id():0,'actor_id'=>$user,'browser_hash'=>$browser,'session_hash'=>hash('sha256',wp_get_session_token(),true),'purpose'=>'register'];
};
$read_issued = static function (string $id) use ($storage): array {
    $result = $storage->read_attempt($id);
    if (!$result['ok'] || !$result['data']['attempt']) { throw new RuntimeException('Missing issued ceremony'); }
    $attempt = $result['data']['attempt'];
    $issued = $attempt['issued']; $issued['challenge'] = $attempt['challenge'];
    if (isset($issued['user_handle'])) { $issued['user_handle'] = WebAuthn::decode($issued['user_handle']); }
    foreach (['allow_credentials','exclude_credentials'] as $field) {
        foreach ($issued[$field] ?? [] as $i=>$descriptor) { $issued[$field][$i]['credential_id'] = WebAuthn::decode($descriptor['credential_id']); }
    }
    return $issued;
};
try {
    foreach (['subscriber','subscriber','administrator'] as $role) {
        $login = 'azwp_ceremony_'.bin2hex(random_bytes(6)); $user = wp_insert_user(['user_login'=>$login, 'user_email'=>$login.'@example.test', 'user_pass'=>wp_generate_password(), 'role'=>$role]);
        if (is_wp_error($user)) { throw new RuntimeException('Disposable account creation failed'); }
        $users[] = (int) $user;
    }
    [$alice,$bob,$admin] = $users;
    $origin = WebAuthn::canonical_origin(get_site_url($site), true);
    $rp = (string) parse_url($origin, PHP_URL_HOST);
    check('service configuration saved', $storage->save_settings('site',$site,['rp_id'=>$rp,'rp_name'=>'Protocol integration','passkey_only'=>false,'remember_login'=>true,'reset_restriction'=>'off'])['ok']);
    if (is_multisite()) { check('network ceremony policy saved', $storage->save_settings('network',(int)get_current_network_id(),['passkey_only'=>false])['ok']); }
    $context = $become($alice);
    $key = openssl_pkey_new(['private_key_type'=>OPENSSL_KEYTYPE_EC,'curve_name'=>'prime256v1']);
    if (!$key) { throw new RuntimeException('Fixture key generation unavailable'); }
    $cose = es256_cose($key);
    $id = random_bytes(32); $aaguid = random_bytes(16);
    $options = $passkeys->registration_options($context,[]);
    check('real enrollment options issued', $options['ok']);
    $attempt_ids[] = $attempt_id = $options['data']['attempt_id'];
    $issued = $read_issued($attempt_id);
    check('registration uses a 64-byte handle', strlen($issued['user_handle']) === 64);
    $input = ['attempt_id'=>$attempt_id,'credential'=>registration_fixture($issued,$id,$cose,$aaguid)];
    $wrong_context = array_replace($context,['session_hash'=>random_bytes(32)]);
    check('changed session cannot complete enrollment', !$passkeys->complete_registration($wrong_context,$input)['ok']);
    wp_update_user(['ID'=>$alice,'user_email'=>'azwp-'.bin2hex(random_bytes(4)).'@example.test']);
    $mails = [];
    $capture = static function ($short, array $mail) use (&$mails) { $mails[] = $mail; return true; };
    add_filter('pre_wp_mail', $capture, 10, 2);
    $result = $passkeys->complete_registration($context,$input);
    remove_filter('pre_wp_mail', $capture, 10);
    check('real signed enrollment persists successfully', $result['ok']);
    $added = $logged('register_complete', $result, $alice, $alice);
    check('an added row carries the passkey columns', $added['row']['passkey_name']==='Passkey' && (int)$added['row']['passkey_id']>0 && $added['row']['passkey_aaguid']===$aaguid && (int)$added['row']['target_id']===$alice && $added['details']==='Passkey: added');
    check('the browser response carries no log', !array_key_exists('log', $result['data']));
    check('owner is emailed about the new passkey', count($mails)===1 && $mails[0]['to']===get_userdata($alice)->user_email && str_contains($mails[0]['message'],'A passkey from an unknown authenticator (named “Passkey”) was added to your account on') && str_contains($mails[0]['message'],'while you were signed in') && str_contains($mails[0]['message'],'remove the passkey and change your password:'));
    check('enrollment completion replay rejected', !$passkeys->complete_registration($context,$input)['ok']);
    check('a passkey from an unrecognised device is named Passkey', $storage->find_credential($id)['data']['credential']['name'] === 'Passkey');
    $next = $passkeys->registration_options($context,[]);
    if ($next['ok']) { $attempt_ids[] = $next['data']['attempt_id']; }
    check('repeated enrollment keeps exact handle', $next['ok'] && $read_issued($next['data']['attempt_id'])['user_handle'] === $issued['user_handle']);
    $enroll = static function (array $context, string $aaguid) use ($passkeys, $storage, $read_issued, $cose, $capture, &$mails, &$attempt_ids): array {
        $options = $passkeys->registration_options($context,[]);
        if (!$options['ok']) { return []; }
        $attempt_ids[] = $options['data']['attempt_id'];
        $credential_id = random_bytes(32);
        $mails = [];
        add_filter('pre_wp_mail', $capture, 10, 2);
        try { $done = $passkeys->complete_registration($context,['attempt_id'=>$options['data']['attempt_id'],'credential'=>registration_fixture($read_issued($options['data']['attempt_id']),$credential_id,$cose,$aaguid)]); }
        finally { remove_filter('pre_wp_mail', $capture, 10); }
        return $done['ok'] ? $storage->find_credential($credential_id)['data']['credential'] + ['email'=>end($mails)['message'] ?? ''] : [];
    };
    $chrome_mac = ['user_agent'=>'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'] + $context;
    $elsewhere = $storage->with_owner_lock($alice, static fn(Storage $store): array => $store->insert_credential(['user_id'=>$alice,'site_id'=>$site+1000,'credential_id'=>random_bytes(32),'rp_id'=>$rp,'public_key_pem'=>'validated fixture','public_key_cose'=>"\xa1\x01\x02",'credential_type'=>'public-key','attestation_type'=>'none','trust_path'=>[],'aaguid'=>random_bytes(16),'other_ui'=>null,'algorithm'=>-7,'sign_count'=>0,'backup_eligible'=>false,'backed_up'=>false,'transports'=>[],'name'=>'Chrome on Mac','created_at'=>time(),'created_local'=>current_time('mysql'),'last_used_local'=>null]));
    check('a passkey on another site is saved for the numbering check', $elsewhere['ok']);
    $second = $enroll($context, random_bytes(16));
    $apple = $enroll($chrome_mac, hex2bin('fbfc3007154e4ecc8c0b6e020557d7bd'));
    $again = $enroll($chrome_mac, random_bytes(16));
    check('a second unrecognised device is numbered', ($second['name'] ?? null) === 'Passkey (2)');
    check('a recognised browser and device name the passkey, ignoring the same name on another site', ($apple['name'] ?? null) === 'Chrome on Mac');
    check('the email names a known authenticator and the passkey', str_contains($apple['email'] ?? '','A passkey from Apple Passwords (named “Chrome on Mac”) was added to your account on'));
    check('a repeated device name is numbered', ($again['name'] ?? null) === 'Chrome on Mac (2)');
    foreach ([$second, $apple, $again] as $extra) { if ($extra) { $passkeys->remove_credential($context,$alice,(int)$extra['id']); } }
    $storage->cleanup_user($alice,$site+1000);
    $other = $storage->with_owner_lock($bob, static fn(Storage $store): array => $store->get_identity($bob));
    check('different accounts have different 64-byte handles', $other['ok'] && strlen($other['data']['identity']['handle']) === 64 && $other['data']['identity']['handle'] !== $issued['user_handle']);
    $stored = $storage->find_credential($id)['data']['credential'];
    $record = (int) $stored['id'];
    check('database retains exact nonzero AAGUID and COSE', $stored['aaguid']===$aaguid && $stored['public_key_cose']===$cose);
    $stored['user_handle'] = $issued['user_handle'];
    $protected = $storage->save_password_policy($alice,true)['ok'] ? $passkeys->remove_credential($context,$alice,$record) : ['code'=>'storage_failed'];
    check('last passkey protected when password disabled', $protected['code']==='access_required');
    $denied = $logged('remove', $protected, $alice, $alice);
    check('a delete refused for access_required carries the name', $denied['row']['passkey_name']==='Passkey' && $denied['details']==='Passkey deletion failed: would leave the account without a way to sign in');
    $without_password = $enroll($context, random_bytes(16));
    check('with password sign-in off, the email says to tell an administrator', str_contains($without_password['email'] ?? '','remove the passkey and tell a site administrator:') && !str_contains($without_password['email'] ?? '','change your password'));
    if ($without_password) { $passkeys->remove_credential($context,$alice,(int)$without_password['id']); }
    $labels = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0' => 'Edge on Windows',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/131.0.2903.68 Mobile/15E148 Safari/605.1.15' => 'Edge on iPhone',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1' => 'Chrome on iPhone',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1' => 'Safari on iPhone',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1 OPT/4.6.1' => 'Opera on iPhone',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15' => 'Safari on Mac',
        'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36' => 'Chrome on Android',
        'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36' => 'Samsung Internet on Android',
        'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0' => 'Firefox on Linux',
        'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' => 'Chrome on Chromebook',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/490.0.0]' => 'iPhone',
        'Mozilla/5.0 (X11; FreeBSD amd64; rv:132.0) Gecko/20100101 Firefox/132.0' => null,
        '' => null,
    ];
    foreach ($labels as $user_agent => $label) { check('device label: '.($label ?? 'none').' from '.substr($user_agent,0,48), Passkeys::device_label($user_agent) === $label); }
    check('another account management denied', !$passkeys->list_credentials($context,$bob)['ok']);
    $test_context = array_replace($context,['purpose'=>'test']);
    check('test of another account without permission denied', $passkeys->assertion_options($test_context,['target_id'=>(string)$bob])['code']==='forbidden');
    $test = $passkeys->assertion_options($test_context,[]);
    check('test options issued with the target allow-list', $test['ok'] && count($test['data']['publicKey']['allowCredentials'])===1);
    $attempt_ids[] = $test_id = $test['data']['attempt_id'];
    $proof_input = ['attempt_id'=>$test_id,'credential'=>assertion_fixture($read_issued($test_id),$stored,$key,5,1)];
    $proof = $passkeys->verify_assertion($test_context,$proof_input);
    check('real signature yields private acceptance proof', $proof['ok']);
    check('proof acceptance saves security counter', $passkeys->accept_assertion($proof['data']['proof'])['ok'] && $storage->find_credential($id)['data']['credential']['sign_count']===1);
    check('completed assertion replay rejected', !$passkeys->verify_assertion($test_context,$proof_input)['ok']);
    $test = $passkeys->assertion_options($test_context,[]);
    $attempt_ids[] = $test_id = $test['data']['attempt_id'];
    $full_test = $passkeys->complete_test($test_context,['attempt_id'=>$test_id,'credential'=>assertion_fixture($read_issued($test_id),$stored,$key,5,2,$stored['user_handle'])]);
    check('full test completes with matching handle', $full_test['ok']);
    check('test result names the passkey that passed', ($full_test['data']['name'] ?? null) === $stored['name']);
    $tested = $logged('test_complete', $full_test, $alice, $alice);
    check('a tested row carries the passkey columns', $tested['row']['passkey_name']===$stored['name'] && (int)$tested['row']['passkey_id']===$record && (int)$tested['row']['target_id']===$alice && $tested['details']==='Passkey: tested');
    $test = $passkeys->assertion_options($test_context,[]);
    $attempt_ids[] = $test_id = $test['data']['attempt_id'];
    $replayed = $passkeys->complete_test($test_context,['attempt_id'=>$test_id,'credential'=>assertion_fixture($read_issued($test_id),$stored,$key,5,2,$stored['user_handle'])]);
    $own_failure = $logged('test_complete', $replayed, $alice, $alice);
    check('a failed test of the actor\'s own passkey names it, with the owner as target and no " for "', !$replayed['ok'] && $own_failure['row']['passkey_name']===$stored['name'] && (int)$own_failure['row']['target_id']===$alice && $own_failure['details']==='Passkey test failed: passkey not recognized');
    $empty_context = array_replace($become($bob),['purpose'=>'test']);
    check('test without passkeys reports no credentials', $passkeys->assertion_options($empty_context,[])['code']==='no_credentials');
    $context = $become($alice);
    $foreign = ['credential_id'=>random_bytes(32)] + array_diff_key($stored, ['id'=>1,'credential_hash'=>1]);
    $foreign_saved = $storage->with_owner_lock($bob, static fn(Storage $store): array => $store->insert_credential(array_replace($foreign, ['user_id'=>$bob,'site_id'=>$site,'name'=>'Bob key','sign_count'=>0])));
    $test = $passkeys->assertion_options($test_context,[]);
    $attempt_ids[] = $test_id = $test['data']['attempt_id'];
    $crossed = $passkeys->complete_test($test_context,['attempt_id'=>$test_id,'credential'=>assertion_fixture($read_issued($test_id),$foreign,$key,5,9)]);
    $crossed_row = $logged('test_complete', $crossed, $alice, $alice);
    check('a failed test of another account\'s credential ID logs no passkey', $foreign_saved['ok'] && !$crossed['ok'] && $crossed_row['row']['passkey_name']===null && $crossed_row['row']['target_id']===null);
    $storage->cleanup_user($bob,$site);
    $renamed = $passkeys->rename_credential($context,$alice,$record,'Work phone');
    $rename_row = $logged('rename', $renamed, $alice, $alice);
    check('a rename row carries the new name and the previous one', $renamed['ok'] && $rename_row['row']['passkey_name']==='Work phone' && json_decode((string)$rename_row['row']['data'],true)===['previous_name'=>'Passkey'] && $rename_row['details']==='Passkey: renamed to Work phone');
    $wpdb = $GLOBALS['wpdb'];
    $table = $wpdb->base_prefix . 'azwp_passkeys_credentials';
    $trigger = 'azwp_test_rename_' . bin2hex(random_bytes(6));
    check('rename fixture rejects updates to one credential', $wpdb->query("CREATE TRIGGER `$trigger` BEFORE UPDATE ON `$table` FOR EACH ROW BEGIN IF OLD.id=$record THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Test rename failure'; END IF; END") !== false);
    try { $rename_failed = $passkeys->rename_credential($context,$alice,$record,'Never saved'); }
    finally { $wpdb->query("DROP TRIGGER `$trigger`"); }
    $rename_failed_row = $logged('rename', $rename_failed, $alice, $alice);
    check('a failed rename carries the current name and no data', !$rename_failed['ok'] && $rename_failed_row['row']['passkey_name']==='Work phone' && $rename_failed_row['row']['data']===null && $rename_failed_row['details']==='Work phone renaming failed: database error');
    check('passkey renamed back', $passkeys->rename_credential($context,$alice,$record,'Passkey')['ok']);
    $stored['name'] = 'Passkey';
    // Native WordPress authentication is exercised with real signed assertions.
    // The outer bootstrap buffers output before loading this test so cookie headers remain available.
    check('native login fixture has writable headers', !headers_sent());
    wp_set_current_user(0); unset($_COOKIE[LOGGED_IN_COOKIE]);
    $anonymous = ['site_id'=>$site,'network_id'=>is_multisite()?(int)get_current_network_id():0,'actor_id'=>0,'browser_hash'=>$browser,'session_hash'=>null,'purpose'=>'login'];
    $login_input = ['remember'=>false,'redirect_to'=>'','surface'=>'native'];
    $login = $passkeys->assertion_options($anonymous,$login_input);
    check('anonymous usernameless login options issued', $login['ok'] && !array_key_exists('allowCredentials',$login['data']['publicKey']));
    check('oversized redirect is rejected', $passkeys->assertion_options($anonymous,['redirect_to'=>'https://site.test/'.str_repeat('a',Passkeys::REDIRECT_MAX_BYTES)]+$login_input)['code']==='invalid_request');
    check('login attempt binds no target', $storage->read_attempt($login['data']['attempt_id'])['data']['attempt']['target_id']===null);
    $attempt_ids[] = $login_id = $login['data']['attempt_id'];
    // Reuse the live plugin's policy boundary when the bootstrap activates it.
    // A second instance would not share the request-private verified-user guard.
    foreach (($GLOBALS['wp_filter']['authenticate']->callbacks ?? []) as $entries) {
        foreach ($entries as $entry) {
            $callback = $entry['function'];
            if (is_array($callback) && ($callback[0] ?? null) instanceof Authentication) {
                $authentication = $callback[0];
                break 2;
            }
        }
    }
    if (!$authentication) {
        $authentication = new Authentication($settings,$passkeys,$logs);
        $authentication->register_hooks();
        $owns_authentication_hooks = true;
    }
    $cookies = [];
    $capture_cookie = static function ($cookie,$expire,$expiration,$user_id,$scheme,$token) use (&$cookies): void { $cookies[]=['user_id'=>(int)$user_id,'token'=>$token]; };
    add_action('set_auth_cookie',$capture_cookie,10,6);
    try {
        $signed_in = $authentication->complete_login($anonymous,['attempt_id'=>$login_id,'credential'=>assertion_fixture($read_issued($login_id),$stored,$key,5,3,$stored['user_handle'])]);
        check('real WordPress sign-on accepts verified passkey', $signed_in['ok'] && $signed_in['data']['session_changed'] && get_current_user_id()===$alice);
        check('login subject is private verified owner context', $signed_in['subject_id']===$alice && !array_key_exists('subject_id',$signed_in['data']) && !array_key_exists('proof',$signed_in['data']));
        $signin_row = $logged('login_complete', $signed_in, 0, null);
        check('a sign-in row names the passkey and the verified account', $signin_row['row']['passkey_name']==='Passkey' && (int)$signin_row['row']['target_id']===$alice && $signin_row['row']['actor_id']===null && $signin_row['details']==='Passkey: signed in');
        $replay = $passkeys->assertion_options($anonymous,$login_input);
        $attempt_ids[] = $replay_id = $replay['data']['attempt_id'];
        $failed_signin = $logged('login_complete', $authentication->complete_login($anonymous,['attempt_id'=>$replay_id,'credential'=>assertion_fixture($read_issued($replay_id),$stored,$key,5,3,$stored['user_handle'])]), 0, null);
        check('a failed sign-in row names no passkey', $failed_signin['row']['ok']==='0' && $failed_signin['row']['passkey_name']===null && $failed_signin['row']['target_id']===null);
        check('real WordPress session cookie created for owner', count($cookies)===1 && $cookies[0]['user_id']===$alice && $cookies[0]['token']!=='');
        $resolve = static function (int $user, string $token): int {
            $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($user, time() + 3600, 'logged_in', $token);
            return (int) apply_filters('determine_current_user', false);
        };
        $other_token = WP_Session_Tokens::get_instance($alice)->create(time() + 3600);
        check('password sign-in allowed before session checks', $storage->save_password_policy($alice,false)['ok']);
        check('a session not opened by a passkey works while passwords are allowed', $resolve($alice,$other_token)===$alice);
        $_REQUEST['action'] = 'register'; $GLOBALS['pagenow'] = 'wp-login.php'; $_SERVER['HTTP_ORIGIN'] = $passkeys->configuration($site)['data']['origins'][0];
        $storage->save_settings('site',$site,['after_registration'=>'add_passkey']);
        wp_set_current_user(0); unset($_COOKIE[LOGGED_IN_COOKIE]);
        try { $authentication->registration_sign_in($alice); }
        finally { unset($_REQUEST['action'], $GLOBALS['pagenow'], $_SERVER['HTTP_ORIGIN']); $storage->save_settings('site',$site,['after_registration'=>'default']); }
        check('registration sign-in opened one session', count($cookies)===2 && $cookies[1]['user_id']===$alice);
        check('Passkey only mode turned on for the account', $storage->save_password_policy($alice,true)['ok']);
        check('Passkey only mode ends a session not opened by a passkey', $resolve($alice,$other_token)===0 && WP_Session_Tokens::get_instance($alice)->get($other_token)===null);
        check('Passkey only mode keeps a passkey session', $resolve($alice,$cookies[0]['token'])===$alice);
        check('Passkey only mode keeps the session that adds a first passkey after registration', $resolve($alice,$cookies[1]['token'])===$alice);
        unset($_COOKIE[LOGGED_IN_COOKIE]);
        WP_Session_Tokens::get_instance($alice)->destroy($cookies[1]['token']);
        array_splice($cookies, 1);
        WP_Session_Tokens::get_instance($alice)->destroy($cookies[0]['token']);
        $logged_context = $become($bob); $logged_context['purpose']='login';
        $login = $passkeys->assertion_options($logged_context,$login_input);
        check('logged-in assertion options issued', $login['ok']);
        $attempt_ids[] = $login_id = $login['data']['attempt_id'];
        $signed_in = $authentication->complete_login($logged_context,['attempt_id'=>$login_id,'credential'=>assertion_fixture($read_issued($login_id),$stored,$key,5,4,$stored['user_handle'])]);
        check('logged-in passkey proof never switches account', $signed_in['ok'] && !$signed_in['data']['session_changed'] && get_current_user_id()===$bob && count($cookies)===1);
    } finally { remove_action('set_auth_cookie',$capture_cookie,10); }
    $admin_context = $become($admin);
    if (is_multisite()) {
        check('ordinary network site administrator cannot manage another account without permission', !$passkeys->list_credentials($admin_context,$alice)['ok']);
        if (!grant_super_admin($admin)) { throw new RuntimeException('Disposable super administrator grant failed'); }
        $granted_super_admin = $admin;
        $admin_context = $become($admin);
    }
    check('authorized administrator can inspect selected account', $passkeys->list_credentials($admin_context,$alice)['ok']);
    $mails = [];
    $capture_mail = static function ($short, array $mail) use (&$mails) { $mails[] = $mail; return true; };
    add_filter('pre_wp_mail', $capture_mail, 10, 2);
    try {
        $setup_token = static function () use (&$mails): string { preg_match('/[?&]token=([A-Za-z0-9_-]+)/', end($mails)['message'] ?? '', $match); return $match[1] ?? ''; };
        check('an account cannot send itself a setup link', $passkeys->send_setup_link($admin_context,$admin)['code']==='forbidden');
        check('administrator sends a setup link', $passkeys->send_setup_link($admin_context,$bob)['ok'] && count($mails)===1 && $setup_token()!=='');
        $replaced = $setup_token();
        check('a new setup link replaces the old one', $passkeys->send_setup_link($admin_context,$bob)['ok'] && !$passkeys->setup_link_valid($bob,$replaced,$site));
        $token = $setup_token();
        check('opening a setup link does not use it up', $passkeys->setup_link_valid($bob,$token,$site) && $passkeys->setup_link_valid($bob,$token,$site));
        check('a setup link only works on the site that sent it', !$passkeys->setup_link_valid($bob,$token,$site+1000));
        wp_set_current_user(0); unset($_COOKIE[LOGGED_IN_COOKIE]);
        $setup_context = ['site_id'=>$site,'network_id'=>is_multisite()?(int)get_current_network_id():0,'actor_id'=>0,'browser_hash'=>$browser,'session_hash'=>null,'purpose'=>'setup'];
        check('a wrong token gets no setup options', $passkeys->setup_options($setup_context,['user_id'=>(string)$bob,'token'=>WebAuthn::encode(random_bytes(32))])['code']==='attempt_unavailable');
        $setup = $passkeys->setup_options($setup_context,['user_id'=>(string)$bob,'token'=>$token]);
        check('a valid setup link issues options for its account', $setup['ok']);
        $attempt_ids[] = $setup_id = $setup['data']['attempt_id'];
        $setup_key = openssl_pkey_new(['private_key_type'=>OPENSSL_KEYTYPE_EC,'curve_name'=>'prime256v1']);
        $setup_cose = es256_cose($setup_key);
        $added = $passkeys->complete_setup($setup_context,['attempt_id'=>$setup_id,'token'=>$token,'credential'=>registration_fixture($read_issued($setup_id),random_bytes(32),$setup_cose,random_bytes(16))]);
        check('a setup link adds exactly one passkey', $added['ok'] && $added['subject_id']===$bob && count($storage->get_credentials($bob)['data']['credentials'])===1);
        check('a used setup link stops working', !$passkeys->setup_link_valid($bob,$token,$site) && $passkeys->setup_options($setup_context,['user_id'=>(string)$bob,'token'=>$token])['code']==='attempt_unavailable');
        check('the owner is told a setup link added a passkey', str_contains(end($mails)['message'] ?? '','setup link'));
        $storage->save_setup_link($bob,['hash'=>hash('sha256','expired'),'expires_at'=>time()-1,'issued_by'=>$admin,'site_id'=>$site]);
        check('an expired setup link does not work', !$passkeys->setup_link_valid($bob,WebAuthn::encode('expired'),$site));
    } finally {
        remove_filter('pre_wp_mail', $capture_mail, 10);
        $storage->cleanup_user($bob,$site);
        $admin_context = $become($admin);
    }
    $admin_test_context = array_replace($admin_context,['purpose'=>'test']);
    $admin_test = $passkeys->assertion_options($admin_test_context,['target_id'=>(string)$alice]);
    check('administrator ordinary target test options issued', $admin_test['ok']);
    $attempt_ids[] = $admin_test_id = $admin_test['data']['attempt_id'];
    $admin_result = $passkeys->complete_test($admin_test_context,['attempt_id'=>$admin_test_id,'credential'=>assertion_fixture($read_issued($admin_test_id),$stored,$key,5,5)]);
    check('administrator test subject is verified target not actor', $admin_result['ok'] && $admin_result['subject_id']===$alice && $admin_result['subject_id']!==$admin && !array_key_exists('subject_id',$admin_result['data']) && !array_key_exists('proof',$admin_result['data']));
    $admin_row = $logged('test_complete', $admin_result, $admin, $alice);
    check('an administrator test row names the owner after the action', (int)$admin_row['row']['actor_id']===$admin && (int)$admin_row['row']['target_id']===$alice && $admin_row['details']==='Passkey: tested for '.get_userdata($alice)->user_login);

    $context = $become($alice);
    $test_context = array_replace($context,['purpose'=>'test']);
    $test = $passkeys->assertion_options($test_context,[]);
    check('revocation race fixture issued', $test['ok']);
    $attempt_ids[] = $test_id = $test['data']['attempt_id'];
    $proof = $passkeys->verify_assertion($test_context,['attempt_id'=>$test_id,'credential'=>assertion_fixture($read_issued($test_id),$stored,$key,5,6)]);
    check('revocation race proof verified', $proof['ok']);
    check('password sign-in restored', $storage->save_password_policy($alice,false)['ok']);
    check('authenticator catalog names a known model and ignores unknown ones', \AZWP\Passkeys\Authenticators::name(hex2bin('08987058cadc4b81b6e130de50dcbe96')) === 'Windows Hello hardware authenticator' && \AZWP\Passkeys\Authenticators::name(str_repeat("\0", 16)) === null && \AZWP\Passkeys\Authenticators::name('short') === null);
    $listed = $passkeys->list_credentials($context,$alice);
    check('list marks a passkey that is not backed up as not synced', $listed['ok'] && $listed['data']['credentials'] !== [] && $listed['data']['credentials'][0]['synced'] === false);
    $missing = $passkeys->members_without_passkey($site);
    check('readiness lists a member without a passkey and skips one with a passkey', is_array($missing) && in_array($bob,$missing,true) && !in_array($alice,$missing,true));
    check('account switch accepted with a working passkey', $passkeys->set_password_disabled($alice,true)['ok'] && $storage->password_disabled($alice) && $passkeys->set_password_disabled($alice,false)['ok']);
    check('account switch refused without a working passkey', $passkeys->set_password_disabled($bob,true)['code']==='access_required' && !$storage->password_disabled($bob));
    check('account already switched stays saveable without a passkey', $storage->save_password_policy($bob,true)['ok'] && $passkeys->set_password_disabled($bob,true)['ok'] && $storage->save_password_policy($bob,false)['ok']);
    check('administrator without a passkey cannot be the one to need one', !$passkeys->has_usable_credential($bob,$site) && $passkeys->has_usable_credential($alice,$site));
    $alice_cookie = $_COOKIE[LOGGED_IN_COOKIE];
    $alice_rate_key = 'azwp_passkeys_rate_user_' . $alice;
    delete_transient($alice_rate_key);
    try {
        $alice_login = array_replace($context, ['purpose'=>'login']);
        for ($i = 0; $i < Passkeys::SIGNED_IN_ATTEMPTS_PER_MINUTE; $i++) {
            $option = $passkeys->assertion_options($alice_login, $login_input);
            if (!$option['ok']) { throw new RuntimeException('Signed-in login was throttled below the limit'); }
            $storage->delete_attempt($option['data']['attempt_id']);
        }
        check('signed-in account is rate limited after 30 options', $passkeys->assertion_options($alice_login,$login_input)['code']==='rate_limited');
        check('enrollment and testing share the signed-in account limit',
            $passkeys->registration_options($context,[])['code']==='rate_limited'
            && $passkeys->assertion_options($test_context,[])['code']==='rate_limited');
        $unprovisioned = wp_insert_user(['user_login'=>'azwp_rate_target_'.bin2hex(random_bytes(6)), 'user_pass'=>wp_generate_password(), 'role'=>'subscriber']);
        if (is_wp_error($unprovisioned)) { throw new RuntimeException('Could not create the rate test enrollment target'); }
        $users[] = $unprovisioned;
        set_transient('azwp_passkeys_rate_user_' . $admin, Passkeys::SIGNED_IN_ATTEMPTS_PER_MINUTE, MINUTE_IN_SECONDS);
        check('rate-limited enrollment cannot provision a different account',
            $passkeys->registration_options($become($admin), ['target_id'=>(string)$unprovisioned])['code'] === 'rate_limited'
            && $storage->get_identity($unprovisioned)['data']['identity'] === null);
        $bob_login = array_replace($become($bob), ['purpose'=>'login']);
        $other_option = $passkeys->assertion_options($bob_login, $login_input);
        if ($other_option['ok']) { $attempt_ids[] = $other_option['data']['attempt_id']; }
        check('one account hitting its limit leaves a different account on the same address able to sign in', $other_option['ok']);
    } finally {
        delete_transient($alice_rate_key);
        wp_set_current_user($alice);
        $_COOKIE[LOGGED_IN_COOKIE] = $alice_cookie;
    }
    $removed = $passkeys->remove_credential($context,$alice,$record);
    check('credential removal confirmed with alternative sign-in', $removed['ok']);
    $deleted_row = $logged('remove', $removed, $alice, $alice);
    check('a deleted row carries the passkey columns', $deleted_row['row']['passkey_name']==='Passkey' && (int)$deleted_row['row']['passkey_id']===$record && $deleted_row['details']==='Passkey: deleted');
    check('revocation before acceptance rejects verified proof', !$passkeys->accept_assertion($proof['data']['proof'])['ok']);
    check('credential absent after removal', $storage->find_credential($id)['data']['credential']===null);
    $absent = $passkeys->remove_credential($context,$alice,$record);
    check('already absent authorized removal is idempotent', $absent['ok']);
    $absent_row = $logged('remove', $absent, $alice, $alice);
    check('deleting an already-deleted passkey writes an ok row with no passkey columns', $absent_row['row']['ok']==='1' && $absent_row['row']['passkey_id']===null && $absent_row['row']['passkey_name']===null && $absent_row['details']==='Passkey already deleted');
    $original_address = $_SERVER['REMOTE_ADDR'] ?? null;
    $_SERVER['REMOTE_ADDR'] = '192.0.2.'.random_int(1,254);
    $limited = null;
    for ($i = 0; $i <= Passkeys::ANONYMOUS_ATTEMPTS_PER_MINUTE; $i++) {
        $limited = $passkeys->assertion_options($anonymous,$login_input);
        if ($limited['ok']) { $attempt_ids[] = $limited['data']['attempt_id']; }
    }
    if ($original_address === null) { unset($_SERVER['REMOTE_ADDR']); } else { $_SERVER['REMOTE_ADDR'] = $original_address; }
    check('anonymous sign-in requests are limited per address', !$limited['ok'] && $limited['code']==='rate_limited' && count(array_unique($attempt_ids))===count($attempt_ids));
    $flood_ids = [];
    try {
        for ($address = 1; count($flood_ids) < 1000 && $address < 100; $address++) {
            $_SERVER['REMOTE_ADDR'] = '198.51.100.'.$address;
            for ($i = 0; $i < Passkeys::ANONYMOUS_ATTEMPTS_PER_MINUTE; $i++) {
                $flooded = $passkeys->assertion_options($anonymous,$login_input);
                if (!$flooded['ok']) { break; }
                $flood_ids[] = $flooded['data']['attempt_id'];
            }
        }
        $_SERVER['REMOTE_ADDR'] = '203.0.113.'.random_int(1,254);
        $bystander = $passkeys->assertion_options($anonymous,$login_input);
        if ($bystander['ok']) { $flood_ids[] = $bystander['data']['attempt_id']; }
        check('other addresses cannot use up sign-in for a new visitor', count($flood_ids) >= 1000 && $bystander['ok']);
    } finally {
        foreach ($flood_ids as $flood_id) { $storage->delete_attempt($flood_id); }
        if ($original_address === null) { unset($_SERVER['REMOTE_ADDR']); } else { $_SERVER['REMOTE_ADDR'] = $original_address; }
    }
    $expired = random_bytes(32);
    $storage->create_attempt(['id'=>$expired,'site_id'=>$site,'purpose'=>'login','actor_id'=>null,'target_id'=>null,'browser_hash'=>$browser,'session_hash'=>null,'challenge'=>random_bytes(32),'issued'=>[],'created_at'=>time()-200,'expires_at'=>time()-100]);
    $fresh = $passkeys->assertion_options($anonymous,$login_input);
    if ($fresh['ok']) { $storage->delete_attempt($fresh['data']['attempt_id']); }
    check('new anonymous sign-in removes expired attempts', $fresh['ok'] && $storage->read_attempt(WebAuthn::encode($expired))['data']['attempt'] === null);
    echo "Passkeys integration checks complete.\n";
} finally {
    if ($owns_authentication_hooks && $authentication) {
        foreach ($GLOBALS['wp_filter'] as $hook=>$registered) {
            foreach ($registered->callbacks as $priority=>$entries) {
                foreach ($entries as $entry) {
                    $callback = $entry['function'];
                    if (is_array($callback) && ($callback[0] ?? null)===$authentication) { remove_filter($hook,$callback,$priority); }
                }
            }
        }
    }
    foreach ($attempt_ids as $attempt_id) { $storage->delete_attempt($attempt_id); }
    $storage->delete_rate_limits($site);
    if ($granted_super_admin !== null) { revoke_super_admin($granted_super_admin); }
    foreach ($users as $user) { $storage->cleanup_user($user); WP_Session_Tokens::get_instance($user)->destroy_all(); wp_delete_user($user); }
    if ($original_settings === null) { delete_option('azwp_passkeys_settings'); } else { update_option('azwp_passkeys_settings',$original_settings); }
    if (is_multisite()) {
        if ($original_network === null) { delete_network_option(get_current_network_id(),'azwp_passkeys_network_settings'); } else { update_network_option(get_current_network_id(),'azwp_passkeys_network_settings',$original_network); }
    }
    wp_set_current_user($original_user);
    if ($original_cookie === null) { unset($_COOKIE[LOGGED_IN_COOKIE]); } else { $_COOKIE[LOGGED_IN_COOKIE]=$original_cookie; }
}
