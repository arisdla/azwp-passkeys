<?php
/** Passkey only mode safeguards against the real settings handler. Only for a disposable WordPress database. */
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true) {
    throw new RuntimeException('A disposable WordPress test bootstrap is required.');
}
require_once dirname(__DIR__) . '/autoload.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
require_once __DIR__ . '/fixtures.php';
use AZWP\Passkeys\{Storage, Settings, Passkeys, WebAuthn, Screens};

$storage = new Storage($GLOBALS['wpdb']);
$settings = new Settings($storage);
$passkeys = new Passkeys($settings, $storage, new WebAuthn());
$screens = new Screens($settings, $passkeys, $storage);
$site = (int) get_current_blog_id();
$scope = is_multisite() ? ['network', (int) get_current_network_id()] : ['site', $site];
$original = get_option('azwp_passkeys_settings');
$original_network = is_multisite() ? get_network_option(get_current_network_id(), 'azwp_passkeys_network_settings') : null;
$browser = hash('sha256', random_bytes(32), true);
$users = [];

$make_user = static function (string $role) use (&$users): int {
    $login = 'azwp_only_' . bin2hex(random_bytes(5));
    $id = wp_insert_user(['user_login' => $login, 'user_email' => $login . '@example.test', 'user_pass' => wp_generate_password(), 'role' => $role]);
    if (is_wp_error($id)) { throw new RuntimeException('Could not create test user'); }
    $users[] = $id;
    return $id;
};
$become = static function (int $user) use ($site, $browser): array {
    wp_set_current_user($user);
    $token = WP_Session_Tokens::get_instance($user)->create(time() + 3600);
    $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($user, time() + 3600, 'logged_in', $token);
    return ['site_id' => $site, 'network_id' => is_multisite() ? (int) get_current_network_id() : 0, 'actor_id' => $user, 'browser_hash' => $browser, 'session_hash' => hash('sha256', wp_get_session_token(), true), 'purpose' => 'register'];
};
$enroll = static function (int $user) use ($become, $passkeys, $storage): bool {
    $context = $become($user);
    $options = $passkeys->registration_options($context, []);
    if (!$options['ok']) { return false; }
    $attempt = $storage->read_attempt($options['data']['attempt_id'])['data']['attempt'];
    $issued = $attempt['issued']; $issued['challenge'] = $attempt['challenge'];
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    $cose = es256_cose($key);
    add_filter('pre_wp_mail', '__return_true');
    try {
        return $passkeys->complete_registration($context, ['attempt_id' => $options['data']['attempt_id'], 'credential' => registration_fixture($issued, random_bytes(32), $cose, random_bytes(16))])['ok'];
    } finally { remove_filter('pre_wp_mail', '__return_true'); }
};
$save = static function (string $form, array $post) use ($screens, $site): string {
    $nonce_scope = $form === 'network' ? (int) get_current_network_id() : $site;
    $_POST = array_map('wp_slash', $post + ['_wpnonce' => wp_create_nonce('azwp_passkeys_save_' . $form . '_' . $nonce_scope)]);
    $_REQUEST = $_POST;
    $location = '';
    $capture = static function ($url) use (&$location) { $location = (string) $url; throw new RuntimeException('redirected'); };
    add_filter('wp_redirect', $capture, PHP_INT_MAX);
    try { (new ReflectionMethod($screens, 'save_form'))->invoke($screens, $form); }
    catch (RuntimeException $redirect) { if ($redirect->getMessage() !== 'redirected') { throw $redirect; } }
    finally { remove_filter('wp_redirect', $capture, PHP_INT_MAX); $_POST = $_REQUEST = []; wp_cache_flush(); }
    return $location;
};
$page_token = static function () use ($screens): string {
    ob_start(); is_multisite() ? $screens->render_network_settings() : $screens->render_site_settings(); $html = (string) ob_get_clean();
    return preg_match('/data-passkey-only-token="([^"]+)"/', $html, $match) ? $match[1] : '';
};
$mode_on = static fn(): bool => !empty($settings->get_effective($site)['passkey_only']);

try {
    $storage->save_settings($scope[0], $scope[1], ['passkey_only' => false]);
    $form = is_multisite() ? 'network' : 'site';
    $site_fields = is_multisite() ? [] : ['rp_name' => $original['rp_name'], 'rp_id' => $original['rp_id'], 'remember_login' => !empty($original['remember_login']) ? '1' : '0', 'reset_restriction' => $original['reset_restriction'], 'after_registration' => $original['after_registration'] ?? 'default'];
    $admin = $make_user('administrator');
    check('saving administrator holds a working passkey', $enroll($admin) && $passkeys->has_usable_credential($admin, $site));
    if (is_multisite() && !grant_super_admin($admin)) { throw new RuntimeException('Super administrator grant failed'); }
    $become($admin);

    $stranded = $make_user('subscriber');
    $no_caps = $make_user('subscriber');
    (new WP_User($no_caps))->remove_all_caps();
    $missing = $passkeys->members_without_passkey($site);
    if (!is_multisite()) {
        check('readiness counts a single-site account with no capabilities record', in_array($no_caps, $missing, true));
    }

    $token = $page_token();
    check('settings page carries a confirmation token for the accounts without a passkey', $token !== '' && in_array($stranded, $missing, true));
    check('the mode cannot be turned on with another account in place of a now-ready one', $enroll($stranded) && ($become($admin) && true) && $make_user('subscriber') > 0
        && str_contains($save($form, $site_fields + ['passkey_only' => '1', 'passkey_only_confirmed' => $token]), 'passkey_only_confirm') && !$mode_on());

    if (!is_multisite()) {
        $fresh = $page_token();
        check('the mode cannot be turned on while changing the passkey domain', str_contains($save('site', array_replace($site_fields, ['rp_id' => 'example.org']) + ['passkey_only' => '1', 'passkey_only_confirmed' => $fresh]), 'invalid=rp_id') && !$mode_on() && $settings->get_effective($site)['rp_id'] === $original['rp_id']);
        check('the mode turns on with a fresh confirmation for the current accounts', str_contains($save('site', $site_fields + ['passkey_only' => '1', 'passkey_only_confirmed' => $fresh]), 'settings_saved') && $mode_on());
        check('the passkey domain cannot change while the mode is on', str_contains($save('site', array_replace($site_fields, ['rp_id' => 'example.org']) + ['passkey_only' => '1']), 'invalid=rp_id') && $settings->get_effective($site)['rp_id'] === $original['rp_id']);
        check('the website name cannot be emptied while the mode is on', str_contains($save('site', array_replace($site_fields, ['rp_name' => '']) + ['passkey_only' => '1']), 'invalid=rp_name') && $settings->get_effective($site)['rp_name'] === $original['rp_name']);
        check('the mode can be turned off together with a domain change', str_contains($save('site', array_replace($site_fields, ['rp_id' => 'example.org']) + ['passkey_only' => '0']), 'settings_saved') && !$mode_on());
        $storage->save_settings('site', $site, ['rp_id' => $original['rp_id']]);
    }

    $storage->save_settings($scope[0], $scope[1], ['passkey_only' => true]);
    $mails = [];
    $capture_mail = static function ($short, array $mail) use (&$mails) { $mails[] = $mail; return true; };
    add_filter('pre_wp_mail', $capture_mail, 10, 2);
    try {
        $welcomed = $make_user('subscriber');
        do_action('edit_user_created_user', $welcomed, 'both');
        $to_user = array_values(array_filter($mails, static fn(array $mail): bool => $mail['to'] === get_userdata($welcomed)->user_email));
        check('Passkey only mode still sends the welcome email, without a set-password link', count($to_user) === 1 && str_contains($to_user[0]['message'], 'passkey setup link') && !str_contains($to_user[0]['message'], 'action=rp'));
        $mails = [];
        wp_new_user_notification($welcomed, null, 'user');
        check('a direct welcome notification is sent too', count($mails) === 1 && str_contains($mails[0]['message'], 'passkey setup link'));
        check('the welcome exemption does not allow a later password reset', is_wp_error(get_password_reset_key(get_userdata($welcomed))));
    } finally { remove_filter('pre_wp_mail', $capture_mail, 10); }
    $storage->save_settings($scope[0], $scope[1], ['passkey_only' => false]);

    $owner = $make_user('subscriber');
    $admin_context = $become($admin);
    $mails = [];
    add_filter('pre_wp_mail', $capture_mail, 10, 2);
    try { check('a setup link is sent', $passkeys->send_setup_link($admin_context, $owner)['ok']); }
    finally { remove_filter('pre_wp_mail', $capture_mail, 10); }
    preg_match('/[?&]token=([A-Za-z0-9_-]+)/', end($mails)['message'] ?? '', $match);
    add_filter('pre_wp_mail', '__return_false');
    try { $failed = $passkeys->send_setup_link($admin_context, $owner); }
    finally { remove_filter('pre_wp_mail', '__return_false'); }
    check('a send whose email fails keeps the link the owner already has', $failed['code'] === 'mail_failed' && $passkeys->setup_link_valid($owner, $match[1] ?? '', $site));
    echo "Passkey only checks complete.\n";
} finally {
    update_option('azwp_passkeys_settings', $original);
    if (is_multisite()) { update_network_option(get_current_network_id(), 'azwp_passkeys_network_settings', $original_network); revoke_super_admin($admin ?? 0); }
    foreach ($users as $user) { $storage->cleanup_user($user); WP_Session_Tokens::get_instance($user)->destroy_all(); wp_delete_user($user); }
    wp_set_current_user(0); unset($_COOKIE[LOGGED_IN_COOKIE]);
    wp_cache_flush();
}
