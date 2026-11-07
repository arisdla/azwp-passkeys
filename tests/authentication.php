<?php
namespace AZWP\Passkeys {
    class Settings {
        public array $values = ['passkey_only' => false, 'reset_restriction' => 'off', 'after_registration' => 'default'];
        public function get_effective(int $site): array { return $this->values; }
    }
    class Logs {
        public array $entries = [];
        public function record(string $event, array $fields = []): void { $this->entries[] = ['event' => $event] + $fields; }
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
                'purpose' => 'login', 'owner_id' => 1, 'record_id' => 7, 'name' => 'Phone', 'aaguid' => str_repeat("\1", 16),
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
    define('ABSPATH', rtrim($argv[1] ?? dirname(__DIR__, 4), '/') . '/');
    define('DAY_IN_SECONDS', 86400);
    define('HOUR_IN_SECONDS', 3600);
    define('AUTH_COOKIE', 'wordpress_auth_test');
    define('SECURE_AUTH_COOKIE', 'wordpress_secure_auth_test');
    define('LOGGED_IN_COOKIE', 'wordpress_logged_in_test');
    define('COOKIEPATH', '/');
    define('SITECOOKIEPATH', '/');
    define('PLUGINS_COOKIE_PATH', '/wp-content/plugins');
    define('ADMIN_COOKIE_PATH', '/wp-admin');
    define('COOKIE_DOMAIN', '');
    class WP_User {
        public string $user_login;
        public string $user_activation_key = '';
        public bool $spam = false;
        public bool $deleted = false;
        public function __construct(public int $ID) { $this->user_login = 'user' . $ID; }
        public function exists(): bool { return isset($GLOBALS['users'][$this->ID]); }
        public function has_cap(string $cap): bool { return $cap === 'read'; }
    }
    class WP_Session_Tokens {
        public static array $created = [];
        public static array $destroyed = [];
        private function __construct(private int $user_id) {}
        public static function get_instance($id): self { return new self($id); }
        public function create($expiration): string {
            $token = 'token-' . (count(self::$created) + 1);
            self::$created[] = [$this->user_id, $token];
            return $token;
        }
        public function destroy($token): void { self::$destroyed[] = [$this->user_id, $token]; }
    }
    function __(string $text, string $domain = ''): string { return $text; }
    function is_wp_error($value): bool { return $value instanceof WP_Error; }
    function sanitize_user($username): string { return trim($username); }
    function get_current_blog_id(): int { return 1; }
    function get_user_by($field, $id) { return $GLOBALS['users'][(int) $id] ?? false; }
    function get_metadata($type, $id, $key, $single) { return $GLOBALS['disabled'][$id] ?? 0; }
    function current_user_can($cap): bool { return $GLOBALS['admin']; }
    function is_multisite(): bool { return false; }
    function is_ssl(): bool { return true; }
    function get_option($name): string { return home_url(); }
    function admin_url($path = ''): string { return 'https://site.test/wp-admin/' . $path; }
    function home_url(): string { return 'https://site.test/'; }
    function wp_login_url(): string { return 'https://site.test/wp-login.php'; }
    function wp_validate_redirect($value, $fallback): string { return str_starts_with($value, 'https://site.test/') ? $value : $fallback; }
    function wp_set_current_user($id): void { $GLOBALS['actor'] = $id; }
    function wp_get_current_user(): WP_User { return new WP_User($GLOBALS['actor']); }
    function wp_generate_auth_cookie($id, $expiration, $scheme, $token): string { return "$id|$expiration|$scheme|$token"; }
    function wp_unslash($value) { return $value; }
    function add_query_arg($key, $value, $url): string { return $url . '?' . $key . '=' . $value; }
    require ABSPATH . 'wp-includes/plugin.php';
    require ABSPATH . 'wp-includes/class-wp-error.php';
    require ABSPATH . 'wp-includes/user.php';
    require ABSPATH . 'wp-includes/pluggable.php';
    require dirname(__DIR__) . '/src/class-webauthn.php';
    require dirname(__DIR__) . '/src/class-authentication.php';
    require dirname(__DIR__) . '/src/class-ajax.php';
    function setup_case(): array {
        $GLOBALS['wp_filter'] = []; $GLOBALS['wp_actions'] = []; $GLOBALS['wp_filters'] = []; $GLOBALS['wp_current_filter'] = [];
        $GLOBALS['actor'] = 0; $GLOBALS['admin'] = false;
        $GLOBALS['users'] = [1 => new WP_User(1), 2 => new WP_User(2)];
        $GLOBALS['disabled'] = [];
        WP_Session_Tokens::$created = [];
        WP_Session_Tokens::$destroyed = [];
        unset($_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_REFERER'], $_REQUEST['action'], $GLOBALS['pagenow']);
        $settings = new \AZWP\Passkeys\Settings(); $passkeys = new \AZWP\Passkeys\Passkeys();
        $logs = new \AZWP\Passkeys\Logs();
        $auth = new \AZWP\Passkeys\Authentication($settings, $passkeys, $logs); $auth->register_hooks();
        return [$auth, $settings, $passkeys, $logs];
    }
    function check($condition, $message): void { if (!$condition) { throw new \RuntimeException($message); } }
    function complete($auth): array { return $auth->complete_login(['site_id' => 1, 'actor_id' => $GLOBALS['actor']], []); }

    [$auth, $settings, $passkeys] = setup_case();
    $result = complete($auth);
    check($result['ok'] && $result['data']['session_changed'] && $GLOBALS['actor'] === 1 && WP_Session_Tokens::$created === [[1, 'token-1']] && $passkeys->accepted === 1, 'Valid proof signs in exactly once.');
    check($result['data']['redirect_to'] === 'https://site.test/account', 'Approved frontend destination retained.');
    $signed_in = \AZWP\Passkeys\Ajax::log_fields('login_complete', $result, 0, null, str_repeat('a', 32));
    check($signed_in['ok'] && $signed_in['target_id'] === 1 && $signed_in['actor_id'] === null && $signed_in['passkey']['name'] === 'Phone' && $signed_in['passkey']['id'] === 7, 'A passkey sign-in row names the verified account and the passkey, with no actor.');
    [$auth, , $passkeys] = setup_case();
    add_filter('authenticate', function ($candidate) {
        apply_filters('auth_cookie_expiration', DAY_IN_SECONDS, $candidate->ID, false);
        return new WP_Error('denied_after_duration_check');
    }, 50);
    check(!complete($auth)['ok'] && $passkeys->accepted === 0 && !WP_Session_Tokens::$created, 'Reading cookie duration before an authentication denial does not accept the proof.');
    [$auth, , $passkeys] = setup_case();
    add_action('wp_login', function ($login, $user) use ($passkeys) {
        $passkeys->save = false;
        wp_set_auth_cookie($user->ID, true);
    }, 10, 2);
    check(complete($auth)['ok'] && $passkeys->accepted === 1 && WP_Session_Tokens::$created === [[1, 'token-1'], [1, 'token-2']], 'A login handler can refresh cookies without accepting the same passkey proof again.');
    [$auth, $settings, $passkeys] = setup_case(); $passkeys->valid = false;
    $failed = \AZWP\Passkeys\Ajax::log_fields('login_complete', complete($auth), 0, null, str_repeat('a', 32));
    check(!$failed['ok'] && $failed['target_id'] === null && $failed['passkey'] === null, 'A failed sign-in row names no account and no passkey.');
    [$auth, $settings, $passkeys] = setup_case(); $GLOBALS['actor'] = 2;
    $result = complete($auth);
    check($result['ok'] && !$result['data']['session_changed'] && $GLOBALS['actor'] === 2 && did_action('wp_authenticate') === 0, 'Existing session is never switched.');
    [$auth, $settings, $passkeys] = setup_case(); $passkeys->valid = false;
    check(!complete($auth)['ok'] && did_action('wp_authenticate') === 0 && $passkeys->accepted === 0, 'Invalid proof never enters sign-on.');
    [$auth, $settings, $passkeys] = setup_case();
    add_filter('authenticate', fn($user) => new WP_Error('disabled'), 50);
    check(!complete($auth)['ok'] && !WP_Session_Tokens::$created && $passkeys->accepted === 0, 'Downstream denial remains authoritative.');
    [$auth, $settings, $passkeys] = setup_case();
    add_filter('authenticate', fn($user) => $GLOBALS['users'][2], 50);
    check(!complete($auth)['ok'] && !WP_Session_Tokens::$created && $passkeys->accepted === 0, 'A downstream replacement account is rejected.');
    [$auth, $settings, $passkeys] = setup_case(); $passkeys->save = false;
    check(complete($auth)['code'] === 'storage_failed' && !WP_Session_Tokens::$created, 'Failed security-state persistence cannot issue cookies.');
    [$auth] = setup_case(); $success_events = 0;
    add_filter('send_auth_cookies', fn($send) => false, 30);
    add_action('wp_login', function () use (&$success_events) { $success_events++; }, 10, 2);
    check(!complete($auth)['ok'] && $success_events === 0 && WP_Session_Tokens::$destroyed === [[1, 'token-1']], 'Cookie suppression destroys only new token before success actions.');
    [$auth] = setup_case(); $late_success_events = 0;
    add_filter('authenticate', function ($user) {
        add_filter('send_auth_cookies', fn($send) => false, PHP_INT_MAX);
        return $user;
    }, 50);
    add_action('wp_login', function () use (&$late_success_events) { $late_success_events++; }, 10, 2);
    check(!complete($auth)['ok'] && $late_success_events === 0 && WP_Session_Tokens::$destroyed === [[1, 'token-1']], 'Dynamically added terminal cookie rejection cannot report login success.');
    [$auth, , $passkeys] = setup_case();
    add_filter('authenticate', function ($user) {
        add_filter('authenticate', fn() => $GLOBALS['users'][2], PHP_INT_MAX);
        return $user;
    }, 50);
    $replaced = complete($auth);
    $replacement_sessions = WP_Session_Tokens::$created;
    $replacement_acceptances = $passkeys->accepted;

    [$auth] = setup_case(); $suppressed_logins = 0;
    add_action('set_logged_in_cookie', function () {
        add_filter('send_auth_cookies', fn() => false, PHP_INT_MAX);
    });
    add_action('wp_login', function () use (&$suppressed_logins) { $suppressed_logins++; });
    $suppressed = complete($auth);
    $suppressed_tokens = WP_Session_Tokens::$destroyed;
    check(
        !$replaced['ok'] && !$replacement_sessions && $replacement_acceptances === 0
        && !$suppressed['ok'] && $suppressed_logins === 0 && $suppressed_tokens === [[1, 'token-1']],
        'Late account replacement and cookie suppression must fail. Observed ' . json_encode([
            'replacement' => ['ok' => $replaced['ok'], 'accepted' => $replacement_acceptances, 'created' => $replacement_sessions],
            'suppression' => ['ok' => $suppressed['ok'], 'logins' => $suppressed_logins, 'destroyed' => $suppressed_tokens],
        ])
    );
    [$auth, $settings] = setup_case(); $settings->values['passkey_only'] = true;
    check(is_wp_error($auth->check_password_login($GLOBALS['users'][1], 'password')), 'Passkey only mode rejects password authentication.');
    do_action('application_password_did_authenticate', $GLOBALS['users'][1]);
    check($auth->check_password_result($GLOBALS['users'][1], 'user1', 'app') instanceof WP_User, 'Application-password authentication remains allowed.');
    check(is_wp_error($auth->check_password_result($GLOBALS['users'][1], 'user1', 'password')), 'Application-password exemption is consumed, not a persistent bypass.');
    $settings->values['passkey_only'] = false;
    $settings->values['reset_restriction'] = 'except_admin';
    check($auth->allow_password_reset(true, 1) === false && $auth->filter_reset_url('link') === '', 'Anonymous reset is blocked and reset link hidden.');
    $GLOBALS['admin'] = true;
    check($auth->allow_password_reset(true, 1) === true && $auth->filter_reset_url('link') === '', 'Admin permission exception does not expose native reset links.');
    check($auth->allow_password_reset(false, 1) === false, 'Reset integration preserves another denial.');
    $settings->values['reset_restriction'] = 'everyone';
    check(!$auth->allow_password_reset(true, 1), 'Everyone mode also denies administrator reset permission.');
    $settings->values['reset_restriction'] = 'off'; $settings->values['passkey_only'] = true; $GLOBALS['admin'] = true;
    check(!$auth->allow_password_reset(true, 1) && $auth->filter_reset_url('link') === '', 'Passkey only mode closes resets for everyone even when resets are allowed.');
    $welcome = $auth->filter_welcome_email(['to' => 'a@example.test', 'subject' => 'Welcome', 'message' => "To set your password, visit wp-login.php?action=rp&key=k"], $GLOBALS['users'][1]);
    check(!str_contains($welcome['message'], 'action=rp') && str_contains($welcome['message'], 'passkey setup link'), 'Passkey only welcome email has no set-password link.');
    $settings->values['passkey_only'] = false;
    check($auth->filter_welcome_email(['message' => 'keep'], $GLOBALS['users'][1])['message'] === 'keep', 'Welcome email is unchanged when passwords are allowed.');
    check(empty($GLOBALS['wp_filter']['show_password_fields']), 'Profile password fields are not disabled.');

    $registration_case = function (string $mode = 'add_passkey'): array {
        [$auth, $settings, $passkeys, $logs] = setup_case();
        $settings->values['after_registration'] = $mode;
        $_SERVER['HTTP_ORIGIN'] = 'https://site.test';
        $GLOBALS['pagenow'] = 'wp-login.php'; $_REQUEST['action'] = 'register';
        return [$auth, $settings, $passkeys, $logs];
    };
    $results = static fn($logs): array => array_column($logs->entries, 'code');
    [$auth, , , $logs] = $registration_case('default');
    check($auth->registration_sign_in(1) === '' && $GLOBALS['actor'] === 0 && !WP_Session_Tokens::$created && !$logs->entries, 'WordPress default leaves registration signed out.');
    [$auth, , , $logs] = $registration_case(); $logins = 0;
    add_action('wp_login', function () use (&$logins) { $logins++; }, 10, 2);
    $destination = $auth->registration_sign_in(1);
    check($destination === 'https://site.test/wp-admin/profile.php?azwp_passkeys_registered=1#azwp-passkeys', 'Registration sign-in opens the profile marker.');
    check($GLOBALS['actor'] === 1 && WP_Session_Tokens::$created === [[1, 'token-1']] && $logins === 1 && $results($logs) === ['ok'], 'Registration sign-in issues one session and one login event.');
    [$auth, , , $logs] = $registration_case(); $GLOBALS['pagenow'] = 'admin-ajax.php'; unset($_REQUEST['action']);
    check($auth->registration_sign_in(1) === '' && !WP_Session_Tokens::$created && !$logs->entries, 'Other callers of register_new_user keep their own flow.');
    [$auth, , , $logs] = $registration_case(); $_REQUEST['action'] = 'lostpassword';
    check($auth->registration_sign_in(1) === '' && !WP_Session_Tokens::$created, 'Only the register action of wp-login.php signs in.');
    [$auth, , , $logs] = $registration_case(); $_SERVER['HTTP_ORIGIN'] = 'https://attacker.test';
    check($auth->registration_sign_in(1) === '' && !WP_Session_Tokens::$created && $results($logs) === ['cross_origin'], 'A cross-site registration post is not signed in.');
    [$auth, , , $logs] = $registration_case(); $_SERVER['HTTP_ORIGIN'] = 'null';
    check($auth->registration_sign_in(1) === '' && $results($logs) === ['cross_origin'], 'A null origin is not signed in.');
    [$auth] = $registration_case(); unset($_SERVER['HTTP_ORIGIN']); $_SERVER['HTTP_REFERER'] = 'https://site.test/wp-login.php?action=register';
    check($auth->registration_sign_in(1) !== '' && WP_Session_Tokens::$created === [[1, 'token-1']], 'A same-site referer stands in for a missing Origin header.');
    [$auth, , , $logs] = $registration_case(); unset($_SERVER['HTTP_ORIGIN']);
    check($auth->registration_sign_in(1) === '' && $results($logs) === ['cross_origin'], 'A request without Origin or Referer is not signed in.');
    [$auth, , $passkeys, $logs] = $registration_case(); $passkeys->configured = false;
    check($auth->registration_sign_in(1) === '' && $results($logs) === ['cross_origin'], 'An unconfigured site has no permitted origin.');
    [$auth, , , $logs] = $registration_case(); $GLOBALS['actor'] = 2;
    check($auth->registration_sign_in(1) === '' && $GLOBALS['actor'] === 2 && !WP_Session_Tokens::$created && !$logs->entries, 'An existing session is never replaced at registration.');
    [$auth, $settings] = $registration_case(); $settings->values['passkey_only'] = true;
    check($auth->registration_sign_in(1) !== '', 'Passkey only mode does not block passwordless registration sign-in.');
    check(is_wp_error($auth->check_password_login($GLOBALS['users'][1], 'password')), 'Registration exemption does not outlive the sign-in.');
    [$auth, , , $logs] = $registration_case();
    add_filter('wp_authenticate_user', fn($user) => new WP_Error('pending_approval'), 20, 2);
    check($auth->registration_sign_in(1) === '' && !WP_Session_Tokens::$created && $results($logs) === ['denied'], 'An approval plugin denial keeps the account signed out.');
    [$auth, , , $logs] = $registration_case(); $logins = 0;
    add_action('set_logged_in_cookie', function () {
        add_filter('send_auth_cookies', fn() => false, PHP_INT_MAX);
    });
    add_action('wp_login', function () use (&$logins) { $logins++; }, 10, 2);
    check($auth->registration_sign_in(1) === '' && $GLOBALS['actor'] === 0 && $logins === 0, 'Suppressed cookies fire no login event.');
    check(WP_Session_Tokens::$destroyed === [[1, 'token-1']] && $results($logs) === ['cookies_suppressed'], 'Suppressed cookies destroy only the new token.');
    [$auth] = setup_case(); $other_account_required = null;
    add_filter('authenticate', function ($user) use (&$other_account_required) {
        $other_account_required = apply_filters('two_factor_is_required_for_user', true, $GLOBALS['users'][2]);
        return apply_filters('two_factor_is_required_for_user', true, $user) ? new WP_Error('second_factor') : $user;
    }, 31);
    check(complete($auth)['ok'] && $other_account_required === true, 'Two-Factor exception applies only to the verified account.');
    check(apply_filters('two_factor_is_required_for_user', true, $GLOBALS['users'][1]) === true, 'Two-Factor exception removed after request-scoped sign-on.');
    echo "Authentication behavior checks passed.\n";
}
