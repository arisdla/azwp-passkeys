<?php
/** Actual Two-Factor release integration; run each release in a separate disposable WP process. */
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true
    || !defined('AZWP_TWO_FACTOR_SOURCE') || class_exists('Two_Factor_Core', false)) {
    throw new RuntimeException('A disposable WordPress bootstrap and one isolated Two-Factor release are required.');
}
require_once dirname(__DIR__) . '/autoload.php';
require_once __DIR__ . '/fixtures.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
use AZWP\Passkeys\{Storage, Settings, Passkeys, WebAuthn, Authentication};

$source = realpath(AZWP_TWO_FACTOR_SOURCE);
if (!$source || !is_file($source . '/two-factor.php')) { throw new RuntimeException('Official release source is missing.'); }
$hooks_before = [];
foreach ($GLOBALS['wp_filter'] as $name=>$hook) { $hooks_before[$name] = clone $hook; }
$site = (int) get_current_blog_id();
$settings_before = get_option('azwp_passkeys_settings', null);
$network_before = is_multisite() ? get_network_option(get_current_network_id(), 'azwp_passkeys_network_settings', null) : null;
$uninstall_before = get_option('uninstall_plugins', null);
$actor_before = get_current_user_id();
$cookie_before = $_COOKIE[LOGGED_IN_COOKIE] ?? null;
$users = [];
$storage = new Storage($GLOBALS['wpdb']);
$settings = new Settings($storage);
$passkeys = new Passkeys($settings, $storage, new WebAuthn());
$authentication = null;
foreach (($GLOBALS['wp_filter']['authenticate']->callbacks ?? []) as $entries) {
    foreach ($entries as $entry) {
        $callback = $entry['function'];
        if (is_array($callback) && ($callback[0] ?? null) instanceof Authentication) { $authentication = $callback[0]; break 2; }
    }
}
if (!$authentication) { $authentication = new Authentication($settings, $passkeys, $storage); $authentication->register_hooks(); }
$read_issued = static function (string $attempt_id) use ($storage): array {
    $attempt = $storage->read_attempt($attempt_id)['data']['attempt'];
    $issued = $attempt['issued']; $issued['challenge'] = $attempt['challenge'];
    if (isset($issued['user_handle'])) { $issued['user_handle'] = WebAuthn::decode($issued['user_handle']); }
    foreach (['allow_credentials','exclude_credentials'] as $field) {
        foreach ($issued[$field] ?? [] as $i=>$descriptor) { $issued[$field][$i]['credential_id'] = WebAuthn::decode($descriptor['credential_id']); }
    }
    return $issued;
};
try {
    require $source . '/two-factor.php';
    check('supported Two-Factor release', version_compare(TWO_FACTOR_VERSION, '0.17.0', '>='));
    check('cookie headers remain writable', !headers_sent());
    check('schema available', $storage->install_schema()['ok']);
    foreach (['alice','bob'] as $name) {
        $id = wp_insert_user(['user_login'=>'azwp_twofactor_'.$name.'_'.bin2hex(random_bytes(5)), 'user_email'=>$name.'-'.bin2hex(random_bytes(3)).'@example.test', 'user_pass'=>'Disposable-2fa-test-password', 'role'=>'subscriber']);
        if (is_wp_error($id)) { throw new RuntimeException('Disposable account creation failed.'); }
        $users[] = (int) $id;
        update_user_meta($id, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, ['Two_Factor_Email']);
        update_user_meta($id, Two_Factor_Core::PROVIDER_USER_META_KEY, 'Two_Factor_Email');
        check('real email second factor enabled', Two_Factor_Core::is_user_using_two_factor($id));
    }
    [$alice,$bob] = $users;
    $origin = WebAuthn::canonical_origin(get_site_url($site), true);
    check('test site policy saved', $storage->save_settings('site',$site,['rp_id'=>parse_url($origin,PHP_URL_HOST),'rp_name'=>'Two-Factor integration','passkey_only'=>false,'remember_login'=>false,'reset_restriction'=>'off'])['ok']);
    if (is_multisite()) { check('test network policy saved', $storage->save_settings('network',(int)get_current_network_id(),['passkey_only'=>false])['ok']); }
    wp_set_current_user($alice);
    $token = WP_Session_Tokens::get_instance($alice)->create(time()+3600);
    $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($alice,time()+3600,'logged_in',$token);
    $browser = hash('sha256',random_bytes(32),true);
    $context = ['site_id'=>$site,'network_id'=>is_multisite()?(int)get_current_network_id():0,'actor_id'=>$alice,'browser_hash'=>$browser,'session_hash'=>hash('sha256',wp_get_session_token(),true),'purpose'=>'register'];
    $key = openssl_pkey_new(['private_key_type'=>OPENSSL_KEYTYPE_EC,'curve_name'=>'prime256v1']);
    $cose = es256_cose($key);
    $credential_id = random_bytes(32);
    $options = $passkeys->registration_options($context,[]);
    check('real enrollment issued', $options['ok']);
    $attempt_id = $options['data']['attempt_id'];
    $enrollment = $read_issued($attempt_id);
    check('real passkey enrolled', $passkeys->complete_registration($context,['attempt_id'=>$attempt_id,'credential'=>registration_fixture($enrollment,$credential_id,$cose,random_bytes(16))])['ok']);
    $stored = $storage->find_credential($credential_id)['data']['credential'];
    $stored['user_handle'] = $enrollment['user_handle'];
    wp_set_current_user(0); unset($_COOKIE[LOGGED_IN_COOKIE]);
    $anonymous = array_replace($context,['actor_id'=>0,'session_hash'=>null,'purpose'=>'login']);
    $options = $passkeys->assertion_options($anonymous,['remember'=>false,'surface'=>'native','redirect_to'=>'']);
    check('real login options issued', $options['ok']);
    $attempt_id = $options['data']['attempt_id'];
    $actual_callbacks = [];
    foreach (['authenticate'=>'filter_authenticate','wp_login'=>'wp_login'] as $hook=>$method) {
        foreach ($GLOBALS['wp_filter'][$hook]->callbacks as $priority=>$entries) {
            foreach ($entries as $entry) {
                if ($entry['function'] === ['Two_Factor_Core',$method]) { $actual_callbacks[$hook] = [$priority,$entry['accepted_args']]; }
            }
        }
    }
    check('official authentication and challenge callbacks installed', count($actual_callbacks)===2);
    $other_required = null;
    $observe_other = static function ($user) use ($bob,&$other_required) { $other_required = Two_Factor_Core::is_user_using_two_factor($bob); return $user; };
    add_filter('authenticate',$observe_other,40);
    $result = $authentication->complete_login($anonymous,['attempt_id'=>$attempt_id,'credential'=>assertion_fixture($read_issued($attempt_id),$stored,$key,5,1,$stored['user_handle'])]);
    remove_filter('authenticate',$observe_other,40);
    check('verified passkey bypasses actual additional challenge', $result['ok'] && $result['data']['session_changed'] && get_current_user_id()===$alice);
    check('other account still requires its configured second factor', $other_required===true);
    check('verified account second factor remains configured after passkey request', Two_Factor_Core::is_user_using_two_factor($alice));
    foreach ($actual_callbacks as $hook=>[$priority,$arguments]) {
        $method = $hook==='authenticate'?'filter_authenticate':'wp_login';
        $found = false;
        foreach ($GLOBALS['wp_filter'][$hook]->callbacks[$priority] ?? [] as $entry) {
            if ($entry['function']===['Two_Factor_Core',$method] && $entry['accepted_args']===$arguments) { $found=true; }
        }
        check('actual '.$hook.' callback retained at original priority', $found);
    }
    // Run genuine password authentication. Stop only after the real challenge path
    // tries to create its nonce, before sending email or rendering/exiting the process.
    wp_set_current_user(0); unset($_COOKIE[LOGGED_IN_COOKIE]);
    $challenge = new RuntimeException('Observed actual Two-Factor challenge.');
    $challenge_entered = false;
    $observe_nonce = static function ($value,$user_id,$meta_key) use ($alice,$challenge,&$challenge_entered) {
        if ((int)$user_id===$alice && $meta_key===Two_Factor_Core::USER_META_NONCE_KEY) { $challenge_entered=true; throw $challenge; }
        return $value;
    };
    $password_cookies = null;
    $password_token = '';
    $observe_send = static function ($send) use (&$password_cookies) { $password_cookies=$send; return $send; };
    // Two-Factor installs its suppression filter during authenticate. Attach the
    // observer afterwards so the same-priority callback sees the final value.
    $observe_token = static function ($cookie,$expire,$expiration,$user_id,$scheme,$token) use ($alice,&$password_token,$observe_send) {
        if ((int)$user_id===$alice) {
            $password_token=(string)$token;
            add_filter('send_auth_cookies',$observe_send,PHP_INT_MAX);
        }
    };
    add_filter('update_user_metadata',$observe_nonce,10,3);
    add_action('set_auth_cookie',$observe_token,PHP_INT_MAX,6);
    try { wp_signon(['user_login'=>get_userdata($alice)->user_login,'user_password'=>'Disposable-2fa-test-password','remember'=>false]); }
    catch (RuntimeException $exception) { if ($exception!==$challenge) { throw $exception; } }
    finally { remove_filter('update_user_metadata',$observe_nonce,10); remove_filter('send_auth_cookies',$observe_send,PHP_INT_MAX); remove_action('set_auth_cookie',$observe_token,PHP_INT_MAX); }
    check('normal password login enters real second-factor challenge', $challenge_entered);
    check('password login does not issue cookies before second factor', $password_cookies===false);
    check('password session token invalidated before challenge', $password_token!=='' && !WP_Session_Tokens::get_instance($alice)->verify($password_token));
    echo 'Actual Two-Factor '.TWO_FACTOR_VERSION." compatibility checks complete.\n";
} finally {
    $GLOBALS['wp_filter'] = $hooks_before;
    foreach ($users as $user) { $storage->cleanup_user($user); WP_Session_Tokens::get_instance($user)->destroy_all(); wp_delete_user($user); }
    foreach (['azwp_passkeys_settings'=>$settings_before,'uninstall_plugins'=>$uninstall_before] as $option=>$value) {
        if ($value===null) { delete_option($option); } else { update_option($option,$value); }
    }
    if (is_multisite()) {
        if ($network_before===null) { delete_network_option(get_current_network_id(),'azwp_passkeys_network_settings'); }
        else { update_network_option(get_current_network_id(),'azwp_passkeys_network_settings',$network_before); }
    }
    wp_set_current_user($actor_before);
    if ($cookie_before===null) { unset($_COOKIE[LOGGED_IN_COOKIE]); } else { $_COOKIE[LOGGED_IN_COOKIE]=$cookie_before; }
}
