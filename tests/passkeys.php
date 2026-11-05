<?php
/** End-to-end service integration. Only for a disposable WordPress database. */
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true) {
    throw new RuntimeException('A disposable WordPress test bootstrap is required.');
}
require_once dirname(__DIR__) . '/autoload.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
require_once __DIR__ . '/fixtures.php';
use AZWP\Passkeys\{Storage, Settings, Passkeys, WebAuthn, Authentication};

$storage = new Storage($GLOBALS['wpdb']);
$settings = new Settings($storage);
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
$test_log_correlation = null;
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
    check('owner is emailed about the new passkey', count($mails)===1 && $mails[0]['to']===get_userdata($alice)->user_email && str_contains($mails[0]['message'],'passkey_1') && str_contains($mails[0]['message'],'while you were signed in'));
    check('enrollment completion replay rejected', !$passkeys->complete_registration($context,$input)['ok']);
    check('new passkey gets the first default name', $storage->find_credential($id)['data']['credential']['name'] === 'passkey_1');
    $next = $passkeys->registration_options($context,[]);
    if ($next['ok']) { $attempt_ids[] = $next['data']['attempt_id']; }
    check('next default name skips one already in use', $next['ok'] && $read_issued($next['data']['attempt_id'])['name'] === 'passkey_2');
    $stored = $storage->find_credential($id)['data']['credential'];
    $record = (int) $stored['id'];
    check('database retains exact nonzero AAGUID and COSE', $stored['aaguid']===$aaguid && $stored['public_key_cose']===$cose);
    $stored['user_handle'] = $issued['user_handle'];
    check('last passkey protected when password disabled', $storage->save_password_policy($alice,true)['ok'] && $passkeys->remove_credential($context,$alice,$record)['code']==='access_required');
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
    $empty_context = array_replace($become($bob),['purpose'=>'test']);
    check('test without passkeys reports no credentials', $passkeys->assertion_options($empty_context,[])['code']==='no_credentials');
    $become($alice);
    // Native WordPress authentication is exercised with real signed assertions.
    // The outer bootstrap buffers output before loading this test so cookie headers remain available.
    check('native login fixture has writable headers', !headers_sent());
    wp_set_current_user(0); unset($_COOKIE[LOGGED_IN_COOKIE]);
    $anonymous = ['site_id'=>$site,'network_id'=>is_multisite()?(int)get_current_network_id():0,'actor_id'=>0,'browser_hash'=>$browser,'session_hash'=>null,'purpose'=>'login'];
    $login_input = ['remember'=>false,'redirect_to'=>'','surface'=>'native'];
    $login = $passkeys->assertion_options($anonymous,$login_input);
    check('anonymous usernameless login options issued', $login['ok'] && !array_key_exists('allowCredentials',$login['data']['publicKey']));
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
        $authentication = new Authentication($settings,$passkeys,$storage);
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
    check('diagnostic fixture logging enabled', $storage->save_settings('site',$site,['logging'=>true])['ok']);
    $test_log_correlation = $correlation = bin2hex(random_bytes(16));
    check('diagnostic actor and subject recorded', $storage->append_log($site,['event'=>'credential_test','actor_id'=>$admin,'target_id'=>$admin_result['subject_id'],'result'=>'ok','correlation_id'=>$correlation,'detail'=>[]])['ok']);
    $logs = $storage->read_logs($site);
    $entry = null;
    foreach ($logs['data']['entries'] ?? [] as $candidate) { if ($candidate['correlation_id']===$correlation) { $entry=$candidate; break; } }
    check('authorized log reader retains distinct numeric actor and subject', $logs['ok'] && $entry!==null && $entry['actor_id']===$admin && $entry['target_id']===$alice);

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
    check('credential removal confirmed with alternative sign-in', $passkeys->remove_credential($context,$alice,$record)['ok']);
    check('revocation before acceptance rejects verified proof', !$passkeys->accept_assertion($proof['data']['proof'])['ok']);
    check('credential absent after removal', $storage->find_credential($id)['data']['credential']===null);
    check('already absent authorized removal is idempotent', $passkeys->remove_credential($context,$alice,$record)['ok']);
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
    if ($test_log_correlation !== null) {
        $GLOBALS['wpdb']->delete($GLOBALS['wpdb']->base_prefix.'azwp_passkeys_logs',['correlation_id'=>$test_log_correlation]);
        $storage->save_settings('site',$site,['logging'=>false]);
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
