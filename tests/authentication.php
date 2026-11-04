<?php
/** Isolated observable-behavior tests; no WordPress installation or database writes. */
namespace AZWP\Passkeys {
    class Settings {
        public array $values = ['preferred_login' => 'passkey', 'reset_restriction' => 'off', 'after_registration' => 'default'];
        public function get_effective(int $site): array { return $this->values; }
    }
    class Storage {
        public array $logs = [];
        public function append_log(int $site, array $entry): array { $this->logs[] = $entry; return ['ok' => true]; }
    }
    class Passkeys {
        public int $accepted = 0;
        public bool $valid = true;
        public bool $save = true;
        public bool $configured = true;
        public function configuration(int $site): array {
            return ['ok' => $this->configured, 'code' => $this->configured ? 'ok' : 'not_configured', 'message' => '', 'data' => $this->configured ? ['origins' => ['https://site.test']] : []];
        }
        public function verify_assertion(array $context, array $input): array {
            return ['ok' => $this->valid, 'code' => 'authentication_failed', 'message' => '', 'data' => ['proof' => [
                'purpose' => 'login', 'owner_id' => 1,
                'issued_options' => ['remember' => false, 'redirect_to' => 'https://site.test/account', 'surface' => 'frontend'],
            ]]];
        }
        public function accept_assertion(array $proof): array {
            $this->accepted++;
            return ['ok' => $this->save, 'code' => $this->save ? 'ok' : 'storage_failed', 'message' => '', 'data' => ['last_used_local' => '2026-10-30 12:00:00']];
        }
    }
}
namespace {
    define('ABSPATH', __DIR__);
    class WP_Error { public function __construct(public string $code, public string $message = '') {} }
    class WP_User {
        public string $user_login;
        public bool $spam = false;
        public bool $deleted = false;
        public function __construct(public int $ID) { $this->user_login = 'user' . $ID; }
        public function exists(): bool { return isset($GLOBALS['users'][$this->ID]); }
        public function has_cap(string $cap): bool { return $cap === 'read'; }
    }
    class WP_Session_Tokens {
        public static array $destroyed = [];
        public static function get_instance($id): self { return new self(); }
        public function destroy($token): void { self::$destroyed[] = $token; }
    }
    function __(string $text, string $domain = ''): string { return $text; }
    function is_wp_error($value): bool { return $value instanceof WP_Error; }
    function hook_id($callback): string { return is_array($callback) ? (is_object($callback[0]) ? spl_object_hash($callback[0]) : $callback[0]) . ':' . $callback[1] : (is_object($callback) ? spl_object_hash($callback) : $callback); }
    function add_filter($hook, $callback, $priority = 10, $arguments = 1): void {
        $GLOBALS['wp_filter'][$hook] ??= (object) ['callbacks' => []];
        $GLOBALS['wp_filter'][$hook]->callbacks[$priority][hook_id($callback)] = ['function' => $callback, 'accepted_args' => $arguments];
    }
    function add_action(...$args): void { add_filter(...$args); }
    function remove_filter($hook, $callback, $priority = 10): void { unset($GLOBALS['wp_filter'][$hook]->callbacks[$priority][hook_id($callback)]); }
    function remove_action(...$args): void { remove_filter(...$args); }
    function apply_filters($hook, $value, ...$arguments) {
        $callbacks = $GLOBALS['wp_filter'][$hook]->callbacks ?? []; ksort($callbacks);
        foreach ($callbacks as $entries) { foreach ($entries as $entry) { $value = ($entry['function'])(...array_slice([$value, ...$arguments], 0, $entry['accepted_args'])); } }
        return $value;
    }
    function do_action($hook, ...$arguments): void {
        $callbacks = $GLOBALS['wp_filter'][$hook]->callbacks ?? []; ksort($callbacks);
        foreach ($callbacks as $entries) { foreach ($entries as $entry) { ($entry['function'])(...array_slice($arguments, 0, $entry['accepted_args'])); } }
    }
    function get_current_blog_id(): int { return 1; }
    function get_current_user_id(): int { return $GLOBALS['actor']; }
    function get_user_by($field, $id) { return $GLOBALS['users'][(int) $id] ?? false; }
    function get_user_meta($id, $key, $single) { return $GLOBALS['disabled'][$id] ?? 0; }
    function current_user_can($cap): bool { return $GLOBALS['admin']; }
    function is_multisite(): bool { return false; }
    function admin_url($path = ''): string { return 'https://site.test/wp-admin/' . $path; }
    function home_url(): string { return 'https://site.test/'; }
    function wp_validate_redirect($value, $fallback): string { return str_starts_with($value, 'https://site.test/') ? $value : $fallback; }
    function wp_set_current_user($id): void { $GLOBALS['actor'] = $id; }
    function wp_unslash($value) { return $value; }
    function add_query_arg($key, $value, $url): string { return $url . '?' . $key . '=' . $value; }
    function wp_set_auth_cookie($id, $remember): void {
        do_action('set_auth_cookie', 'cookie', 0, 0, $id, 'auth', 'registration-token');
        if (apply_filters('send_auth_cookies', true, 0, 0, $id, 'auth', 'registration-token')) { $GLOBALS['cookies']++; }
    }
    function wp_signon($credentials) {
        $GLOBALS['signons']++;
        $user = apply_filters('authenticate', null, $credentials['user_login'], $credentials['user_password']);
        if (!$user instanceof WP_User) { return $user; }
        do_action('set_auth_cookie', 'cookie', 0, 0, $user->ID, 'auth', 'new-token');
        $send = apply_filters('send_auth_cookies', true, 0, 0, $user->ID, 'auth', 'new-token');
        if ($send) { $GLOBALS['cookies']++; }
        do_action('wp_login', $user->user_login, $user);
        return $user;
    }
    require dirname(__DIR__) . '/src/class-webauthn.php';
    require dirname(__DIR__) . '/src/class-authentication.php';
    function setup_case(): array {
        $GLOBALS['wp_filter'] = []; $GLOBALS['actor'] = 0; $GLOBALS['admin'] = false;
        $GLOBALS['users'] = [1 => new WP_User(1), 2 => new WP_User(2)];
        $GLOBALS['disabled'] = []; $GLOBALS['signons'] = 0; $GLOBALS['cookies'] = 0;
        WP_Session_Tokens::$destroyed = [];
        unset($_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_REFERER'], $_REQUEST['action'], $GLOBALS['pagenow']);
        $settings = new \AZWP\Passkeys\Settings(); $passkeys = new \AZWP\Passkeys\Passkeys();
        $storage = new \AZWP\Passkeys\Storage();
        $auth = new \AZWP\Passkeys\Authentication($settings, $passkeys, $storage); $auth->register_hooks();
        return [$auth, $settings, $passkeys, $storage];
    }
    function check($condition, $message): void { if (!$condition) { throw new \RuntimeException($message); } }
    function complete($auth): array { return $auth->complete_login(['site_id' => 1, 'actor_id' => $GLOBALS['actor']], []); }

    [$auth, $settings, $passkeys] = setup_case();
    $result = complete($auth);
    check($result['ok'] && $result['data']['session_changed'] && $GLOBALS['actor'] === 1 && $GLOBALS['cookies'] === 1 && $passkeys->accepted === 1, 'Valid proof signs in exactly once.');
    check($result['data']['redirect_to'] === 'https://site.test/account', 'Approved frontend destination retained.');
    [$auth, $settings, $passkeys] = setup_case(); $GLOBALS['actor'] = 2;
    $result = complete($auth);
    check($result['ok'] && !$result['data']['session_changed'] && $GLOBALS['actor'] === 2 && $GLOBALS['signons'] === 0, 'Existing session is never switched.');
    [$auth, $settings, $passkeys] = setup_case(); $passkeys->valid = false;
    check(!complete($auth)['ok'] && $GLOBALS['signons'] === 0 && $passkeys->accepted === 0, 'Invalid proof never enters sign-on.');
    [$auth, $settings, $passkeys] = setup_case();
    add_filter('authenticate', fn($user) => new WP_Error('disabled'), 50);
    check(!complete($auth)['ok'] && $GLOBALS['cookies'] === 0 && $passkeys->accepted === 0, 'Downstream denial remains authoritative.');
    [$auth, $settings, $passkeys] = setup_case();
    add_filter('authenticate', fn($user) => $GLOBALS['users'][2], 50);
    check(!complete($auth)['ok'] && $GLOBALS['cookies'] === 0 && $passkeys->accepted === 0, 'A downstream replacement account is rejected.');
    [$auth, $settings, $passkeys] = setup_case(); $passkeys->save = false;
    check(!complete($auth)['ok'] && $GLOBALS['cookies'] === 0, 'Failed security-state persistence cannot issue cookies.');
    [$auth] = setup_case(); $success_events = 0;
    add_filter('send_auth_cookies', fn($send) => false, 30);
    add_action('wp_login', function () use (&$success_events) { $success_events++; }, 10, 2);
    check(!complete($auth)['ok'] && $success_events === 0 && WP_Session_Tokens::$destroyed === ['new-token'], 'Cookie suppression destroys only new token before success actions.');
    [$auth] = setup_case(); $late_success_events = 0;
    add_filter('authenticate', function ($user) {
        add_filter('send_auth_cookies', fn($send) => false, PHP_INT_MAX);
        return $user;
    }, 50);
    add_action('wp_login', function () use (&$late_success_events) { $late_success_events++; }, 10, 2);
    check(!complete($auth)['ok'] && $late_success_events === 0 && $GLOBALS['cookies'] === 0 && WP_Session_Tokens::$destroyed === ['new-token'], 'Dynamically added terminal cookie rejection cannot report login success.');
    [$auth, $settings] = setup_case(); $settings->values['preferred_login'] = 'only';
    check(is_wp_error($auth->check_password_login($GLOBALS['users'][1], 'password')), 'Passkey only mode rejects password authentication.');
    do_action('application_password_did_authenticate', $GLOBALS['users'][1]);
    check($auth->check_password_result($GLOBALS['users'][1], 'user1', 'app') instanceof WP_User, 'Application-password authentication remains allowed.');
    check(is_wp_error($auth->check_password_result($GLOBALS['users'][1], 'user1', 'password')), 'Application-password exemption is consumed, not a persistent bypass.');
    $settings->values['reset_restriction'] = 'except_admin';
    check($auth->allow_password_reset(true, 1) === false && $auth->filter_reset_url('link') === '', 'Anonymous reset is blocked and reset link hidden.');
    $GLOBALS['admin'] = true;
    check($auth->allow_password_reset(true, 1) === true && $auth->filter_reset_url('link') === '', 'Admin permission exception does not expose native reset links.');
    check($auth->allow_password_reset(false, 1) === false, 'Reset integration preserves another denial.');
    $settings->values['reset_restriction'] = 'everyone';
    check(!$auth->allow_password_reset(true, 1), 'Everyone mode also denies administrator reset permission.');
    check(empty($GLOBALS['wp_filter']['show_password_fields']), 'Profile password fields are not disabled.');

    $registration_case = function (string $mode = 'add_passkey'): array {
        [$auth, $settings, $passkeys, $storage] = setup_case();
        $settings->values['after_registration'] = $mode;
        $_SERVER['HTTP_ORIGIN'] = 'https://site.test';
        $GLOBALS['pagenow'] = 'wp-login.php'; $_REQUEST['action'] = 'register';
        return [$auth, $settings, $passkeys, $storage];
    };
    $results = static fn($storage): array => array_column($storage->logs, 'result');
    [$auth, , , $storage] = $registration_case('default');
    check($auth->registration_sign_in(1) === '' && $GLOBALS['actor'] === 0 && $GLOBALS['cookies'] === 0 && !$storage->logs, 'WordPress default leaves registration signed out.');
    [$auth, , , $storage] = $registration_case(); $logins = 0;
    add_action('wp_login', function () use (&$logins) { $logins++; }, 10, 2);
    $destination = $auth->registration_sign_in(1);
    check($destination === 'https://site.test/wp-admin/profile.php?azwp_passkeys_registered=1#azwp-passkeys', 'Registration sign-in opens the profile marker.');
    check($GLOBALS['actor'] === 1 && $GLOBALS['cookies'] === 1 && $logins === 1 && $results($storage) === ['ok'], 'Registration sign-in issues one session and one login event.');
    [$auth, , , $storage] = $registration_case(); $GLOBALS['pagenow'] = 'admin-ajax.php'; unset($_REQUEST['action']);
    check($auth->registration_sign_in(1) === '' && $GLOBALS['cookies'] === 0 && !$storage->logs, 'Other callers of register_new_user keep their own flow.');
    [$auth, , , $storage] = $registration_case(); $_REQUEST['action'] = 'lostpassword';
    check($auth->registration_sign_in(1) === '' && $GLOBALS['cookies'] === 0, 'Only the register action of wp-login.php signs in.');
    [$auth, , , $storage] = $registration_case(); $_SERVER['HTTP_ORIGIN'] = 'https://attacker.test';
    check($auth->registration_sign_in(1) === '' && $GLOBALS['cookies'] === 0 && $results($storage) === ['cross_origin'], 'A cross-site registration post is not signed in.');
    [$auth, , , $storage] = $registration_case(); $_SERVER['HTTP_ORIGIN'] = 'null';
    check($auth->registration_sign_in(1) === '' && $results($storage) === ['cross_origin'], 'A null origin is not signed in.');
    [$auth] = $registration_case(); unset($_SERVER['HTTP_ORIGIN']); $_SERVER['HTTP_REFERER'] = 'https://site.test/wp-login.php?action=register';
    check($auth->registration_sign_in(1) !== '' && $GLOBALS['cookies'] === 1, 'A same-site referer stands in for a missing Origin header.');
    [$auth, , , $storage] = $registration_case(); unset($_SERVER['HTTP_ORIGIN']);
    check($auth->registration_sign_in(1) === '' && $results($storage) === ['cross_origin'], 'A request without Origin or Referer is not signed in.');
    [$auth, , $passkeys, $storage] = $registration_case(); $passkeys->configured = false;
    check($auth->registration_sign_in(1) === '' && $results($storage) === ['cross_origin'], 'An unconfigured site has no permitted origin.');
    [$auth, , , $storage] = $registration_case(); $GLOBALS['actor'] = 2;
    check($auth->registration_sign_in(1) === '' && $GLOBALS['actor'] === 2 && $GLOBALS['cookies'] === 0 && !$storage->logs, 'An existing session is never replaced at registration.');
    [$auth, $settings] = $registration_case(); $settings->values['preferred_login'] = 'only';
    check($auth->registration_sign_in(1) !== '', 'Passkey only mode does not block passwordless registration sign-in.');
    check(is_wp_error($auth->check_password_login($GLOBALS['users'][1], 'password')), 'Registration exemption does not outlive the sign-in.');
    [$auth, , , $storage] = $registration_case();
    add_filter('wp_authenticate_user', fn($user) => new WP_Error('pending_approval'), 20, 2);
    check($auth->registration_sign_in(1) === '' && $GLOBALS['cookies'] === 0 && $results($storage) === ['denied'], 'An approval plugin denial keeps the account signed out.');
    [$auth, , , $storage] = $registration_case(); $logins = 0;
    add_filter('send_auth_cookies', fn($send) => false, 30);
    add_action('wp_login', function () use (&$logins) { $logins++; }, 10, 2);
    check($auth->registration_sign_in(1) === '' && $GLOBALS['actor'] === 0 && $logins === 0, 'Suppressed cookies fire no login event.');
    check(WP_Session_Tokens::$destroyed === ['registration-token'] && $results($storage) === ['cookies_suppressed'], 'Suppressed cookies destroy only the new token.');
    [$auth] = setup_case(); $other_account_required = null;
    add_filter('authenticate', function ($user) use (&$other_account_required) {
        $other_account_required = apply_filters('two_factor_is_required_for_user', true, $GLOBALS['users'][2]);
        return apply_filters('two_factor_is_required_for_user', true, $user) ? new WP_Error('second_factor') : $user;
    }, 31);
    check(complete($auth)['ok'] && $other_account_required === true, 'Two-Factor exception applies only to the verified account.');
    check(apply_filters('two_factor_is_required_for_user', true, $GLOBALS['users'][1]) === true, 'Two-Factor exception removed after request-scoped sign-on.');
    echo "Authentication behavior checks passed.\n";
}
