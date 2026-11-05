<?php
/** WordPress session, password and reset integration. */
namespace AZWP\Passkeys;

if (!defined('ABSPATH')) {
    exit;
}

final class Authentication
{
    private ?int $proven_user_id = null;
    /** @var array<int, true> */
    private array $application_password_users = [];
    /** @var array<int, string> How the session being created right now for each account was earned. */
    private array $session_origin = [];
    /** @var array<int, string> The session token of the auth cookie that identified each account in this request. */
    private array $cookie_tokens = [];

    public function __construct(
        private Settings $settings,
        private Passkeys $passkeys,
        private Storage $storage
    ) {
    }

    public function register_hooks(): void
    {
        add_filter('wp_authenticate_user', [$this, 'check_password_login'], PHP_INT_MAX, 2);
        add_filter('authenticate', [$this, 'check_password_result'], PHP_INT_MAX, 3);
        add_action('application_password_did_authenticate', [$this, 'mark_application_password'], 10, 1);
        add_filter('attach_session_information', [$this, 'tag_session'], 10, 2);
        add_action('auth_cookie_valid', [$this, 'record_cookie_session'], 10, 2);
        // After core cookie (10, 20) and Application Password (20) resolution.
        add_filter('determine_current_user', [$this, 'enforce_passkey_session'], 30);
        add_filter('allow_password_reset', [$this, 'allow_password_reset'], PHP_INT_MAX, 2);
        foreach (['lostpassword', 'retrievepassword', 'resetpass', 'rp'] as $action) {
            add_action('login_form_' . $action, [$this, 'redirect_reset']);
        }
        add_filter('lostpassword_url', [$this, 'filter_reset_url'], PHP_INT_MAX);
        add_filter('lost_password_html_link', [$this, 'filter_reset_url'], PHP_INT_MAX);
        add_filter('get_user_option_default_password_nag', [$this, 'filter_password_nag']);
        add_filter('login_link_separator', [$this, 'filter_login_separator']);
        // Runs after WordPress sends the new-user notification at priority 10.
        add_action('register_new_user', [$this, 'sign_in_registered_user'], PHP_INT_MAX);
    }

    public function sign_in_registered_user(int $user_id): void
    {
        $destination = $this->registration_sign_in($user_id);
        if ($destination !== '') {
            wp_safe_redirect($destination);
            exit;
        }
    }

    /** Returns the profile destination, or '' to keep WordPress's registration continuation. */
    public function registration_sign_in(int $user_id): string
    {
        // Only WordPress's own registration form; other callers of register_new_user() keep their flow.
        $native = ($GLOBALS['pagenow'] ?? '') === 'wp-login.php' && ($_REQUEST['action'] ?? '') === 'register';
        if (!$native || is_multisite() || get_current_user_id() !== 0
            || ($this->settings->get_effective(get_current_blog_id())['after_registration'] ?? 'default') !== 'add_passkey') {
            return '';
        }
        $user = get_user_by('id', $user_id);
        if (!$this->account_available($user)) {
            return '';
        }
        if (!$this->same_site_request()) {
            return $this->registration_outcome($user_id, 'cross_origin');
        }
        // No password is used, so only this plugin's password restriction is exempt.
        $this->proven_user_id = $user_id;
        try {
            $checked = apply_filters('wp_authenticate_user', $user, '');
        } finally {
            $this->proven_user_id = null;
        }
        if (!$checked instanceof \WP_User || (int) $checked->ID !== $user_id) {
            return $this->registration_outcome($user_id, 'denied');
        }

        $new_token = '';
        $cookies_allowed = null;
        $observe_permission = function ($send, $expire, $expiration, $cookie_user, $scheme, $token) use ($user_id, &$cookies_allowed, &$new_token) {
            if ((int) $cookie_user === $user_id) {
                $cookies_allowed = (bool) $send;
                $new_token = (string) $token;
            }
            return $send;
        };
        $observe_cookie = function ($cookie, $expire, $expiration, $cookie_user, $scheme, $token) use ($user_id, &$new_token, &$observe_permission): void {
            if ((int) $cookie_user === $user_id) {
                $new_token = (string) $token;
                remove_filter('send_auth_cookies', $observe_permission, PHP_INT_MAX);
                add_filter('send_auth_cookies', $observe_permission, PHP_INT_MAX, 6);
            }
        };
        add_action('set_auth_cookie', $observe_cookie, PHP_INT_MAX, 6);
        add_filter('send_auth_cookies', $observe_permission, PHP_INT_MAX, 6);
        $this->session_origin[$user_id] = 'registration';
        try {
            wp_set_auth_cookie($user_id, false);
        } finally {
            unset($this->session_origin[$user_id]);
            remove_action('set_auth_cookie', $observe_cookie, PHP_INT_MAX);
            remove_filter('send_auth_cookies', $observe_permission, PHP_INT_MAX);
        }
        if ($cookies_allowed !== true) {
            if ($new_token !== '') {
                \WP_Session_Tokens::get_instance($user_id)->destroy($new_token);
            }
            return $this->registration_outcome($user_id, 'cookies_suppressed');
        }
        wp_set_current_user($user_id);
        $this->registration_outcome($user_id, 'ok');
        // A Two-Factor challenge may take over the request here.
        do_action('wp_login', $user->user_login, $user);
        return add_query_arg('azwp_passkeys_registered', '1', admin_url('profile.php')) . '#azwp-passkeys';
    }

    /** The registration form must come from one of this site's permitted origins. */
    private function same_site_request(): bool
    {
        $configuration = $this->passkeys->configuration(get_current_blog_id());
        if (!$configuration['ok']) {
            return false;
        }
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        $from_referer = !is_string($origin) || $origin === '';
        if ($from_referer) {
            $origin = $_SERVER['HTTP_REFERER'] ?? '';
        }
        if (!is_string($origin) || $origin === '') {
            return false;
        }
        try {
            // A referer carries a path; an Origin header must already be origin-only.
            $origin = WebAuthn::canonical_origin(wp_unslash($origin), $from_referer);
        } catch (\Throwable) {
            return false;
        }
        return in_array($origin, $configuration['data']['origins'], true);
    }

    private function registration_outcome(int $user_id, string $result): string
    {
        try {
            $this->storage->append_log(get_current_blog_id(), ['event' => 'registration_sign_in', 'actor_id' => null, 'target_id' => $user_id, 'result' => $result, 'detail' => []]);
        } catch (\Throwable) {
            // Logging cannot change the registration outcome.
        }
        return '';
    }

    public function complete_login(array $context, array $input): array
    {
        return $this->complete_verified_login($context, $input);
    }

    /** The only accepted proof is produced by Passkeys in this request. */
    private function complete_verified_login(array $context, array $input): array
    {
        $verified = $this->passkeys->verify_assertion($context, $input);
        if (!$verified['ok']) {
            return $verified;
        }
        $proof = $verified['data']['proof'];
        if ($proof['purpose'] !== 'login') {
            return $this->failure();
        }
        $user = get_user_by('id', $proof['owner_id']);
        if (!$this->account_available($user)) {
            return $this->failure();
        }
        if (get_current_user_id() !== 0) {
            $accepted = $this->passkeys->accept_assertion($proof);
            return $accepted['ok'] ? $this->success($user, $proof, $accepted, false) : $accepted;
        }

        // These callbacks exist only while this one verified sign-on runs.
        $this->proven_user_id = (int) $user->ID;
        $accepted = null;
        $new_token = '';
        $cookies_allowed = null;
        $stop = new \RuntimeException('Passkey session was not issued.');
        $early = function ($candidate) use ($user) {
            if (is_wp_error($candidate)) {
                return $candidate;
            }
            return apply_filters('wp_authenticate_user', $user, '');
        };
        $terminal = function ($candidate) use ($user, $proof, &$accepted) {
            if (is_wp_error($candidate)) {
                return $candidate;
            }
            if (!$this->account_available($candidate) || (int) $candidate->ID !== (int) $user->ID) {
                return $this->authentication_error();
            }
            $accepted = $this->passkeys->accept_assertion($proof);
            return $accepted['ok'] ? $candidate : $this->authentication_error();
        };
        $observe_cookie = function ($cookie, $expire, $expiration, $user_id, $scheme, $token) use ($user, &$new_token, &$observe_permission): void {
            if ((int) $user_id === (int) $user->ID) {
                $new_token = (string) $token;
                // Authentication filters may add cookie restrictions at PHP_INT_MAX.
                // Observe after those callbacks rather than their earlier input.
                remove_filter('send_auth_cookies', $observe_permission, PHP_INT_MAX);
                add_filter('send_auth_cookies', $observe_permission, PHP_INT_MAX, 6);
            }
        };
        $observe_permission = function ($send, $expire, $expiration, $user_id, $scheme, $token) use ($user, &$cookies_allowed, &$new_token) {
            if ((int) $user_id === (int) $user->ID) {
                $cookies_allowed = (bool) $send;
                $new_token = (string) $token;
            }
            return $send;
        };
        $before_login = function ($login, $logged_user) use ($user, &$cookies_allowed, &$new_token, &$accepted, $stop): void {
            if ((int) $logged_user->ID !== (int) $user->ID || $cookies_allowed !== true || !$accepted || !$accepted['ok']) {
                if ($new_token !== '') {
                    \WP_Session_Tokens::get_instance((int) $user->ID)->destroy($new_token);
                    $new_token = '';
                }
                // Unwind to the AJAX boundary before later wp_login actions.
                throw $stop;
            }
        };
        $two_factor = function ($required, $candidate) use ($user) {
            $id = $candidate instanceof \WP_User ? (int) $candidate->ID : (int) $candidate;
            return $id === (int) $user->ID ? false : $required;
        };
        add_filter('two_factor_is_required_for_user', $two_factor, PHP_INT_MAX, 2);
        add_filter('authenticate', $early, 19, 3);
        add_filter('authenticate', $terminal, PHP_INT_MAX, 3);
        add_action('set_auth_cookie', $observe_cookie, PHP_INT_MAX, 6);
        add_filter('send_auth_cookies', $observe_permission, PHP_INT_MAX, 6);
        add_action('wp_login', $before_login, PHP_INT_MIN, 2);
        $this->session_origin[(int) $user->ID] = 'passkey';
        try {
            $signed_in = wp_signon([
                'user_login' => $user->user_login,
                'user_password' => '',
                'remember' => !empty($proof['issued_options']['remember']),
            ]);
            if (is_wp_error($signed_in)) {
                return $accepted !== null && !$accepted['ok'] ? $accepted : $this->failure();
            }
            if (!$accepted || !$accepted['ok'] || $cookies_allowed !== true || (int) $signed_in->ID !== (int) $user->ID) {
                return $this->failure();
            }
            wp_set_current_user((int) $user->ID);
            return $this->success($user, $proof, $accepted, true);
        } catch (\RuntimeException $exception) {
            if ($exception !== $stop) {
                throw $exception;
            }
            return $this->failure();
        } finally {
            remove_filter('authenticate', $early, 19);
            remove_filter('authenticate', $terminal, PHP_INT_MAX);
            remove_action('set_auth_cookie', $observe_cookie, PHP_INT_MAX);
            remove_filter('send_auth_cookies', $observe_permission, PHP_INT_MAX);
            remove_action('wp_login', $before_login, PHP_INT_MIN);
            remove_filter('two_factor_is_required_for_user', $two_factor, PHP_INT_MAX);
            unset($this->session_origin[(int) $user->ID]);
            $this->proven_user_id = null;
        }
    }

    public function tag_session($session, $user_id)
    {
        if (is_array($session) && isset($this->session_origin[(int) $user_id])) {
            $session['azwp_passkeys'] = $this->session_origin[(int) $user_id];
        }
        return $session;
    }

    public function record_cookie_session($cookie_elements, $user): void
    {
        if ($user instanceof \WP_User && is_string($cookie_elements['token'] ?? null)) {
            $this->cookie_tokens[(int) $user->ID] = $cookie_elements['token'];
        }
    }

    /** Under Passkey only mode a cookie session counts only if a passkey sign-in, or the first-passkey registration sign-in, opened it. */
    public function enforce_passkey_session($user_id)
    {
        $id = (int) $user_id;
        $token = $this->cookie_tokens[$id] ?? null;
        unset($this->cookie_tokens[$id]);
        if ($id <= 0 || $token === null || !$this->password_disabled($id)) {
            return $user_id;
        }
        $sessions = \WP_Session_Tokens::get_instance($id);
        $session = $sessions->get($token);
        if (in_array($session['azwp_passkeys'] ?? null, ['passkey', 'registration'], true)) {
            return $user_id;
        }
        $sessions->destroy($token);
        return false;
    }

    public function check_password_login($user, $password)
    {
        if (!$user instanceof \WP_User || $this->proven_user_id === (int) $user->ID) {
            return $user;
        }
        return $this->password_disabled((int) $user->ID) ? $this->authentication_error() : $user;
    }

    public function check_password_result($user, $username, $password)
    {
        if (!$user instanceof \WP_User) {
            return $user;
        }
        $id = (int) $user->ID;
        if (isset($this->application_password_users[$id])) {
            unset($this->application_password_users[$id]);
            return $user;
        }
        return $this->check_password_login($user, $password);
    }

    public function mark_application_password($user): void
    {
        if ($user instanceof \WP_User) {
            $this->application_password_users[(int) $user->ID] = true;
        }
    }

    public function allow_password_reset($allowed, $user_id)
    {
        if (is_wp_error($allowed) || !$allowed) {
            return $allowed;
        }
        $mode = $this->reset_mode();
        return $mode === 'off' || ($mode === 'except_admin' && current_user_can('edit_users'));
    }

    public function redirect_reset(): void
    {
        if ($this->reset_mode() !== 'off') {
            wp_safe_redirect(wp_login_url());
            exit;
        }
    }

    public function filter_reset_url($url): string
    {
        return $this->reset_mode() === 'off' ? (string) $url : '';
    }

    public function filter_login_separator($separator): string
    {
        return $this->reset_mode() === 'off' ? (string) $separator : '';
    }

    public function filter_password_nag($value)
    {
        return $this->reset_mode() === 'off' ? $value : false;
    }

    private function reset_mode(): string
    {
        return $this->settings->get_effective(get_current_blog_id())['reset_restriction'];
    }

    private function password_disabled(int $user_id): bool
    {
        $policy = $this->settings->get_effective(get_current_blog_id());
        return $policy['preferred_login'] === 'only' || (bool) get_user_meta($user_id, 'azwp_passkeys_password_disabled', true);
    }

    private function account_available($user): bool
    {
        if (!$user instanceof \WP_User || !$user->exists()) {
            return false;
        }
        // Re-resolve account state rather than treating a filter's user object as proof of existence.
        $current = get_user_by('id', $user->ID);
        return $current instanceof \WP_User && $current->exists()
            && (!is_multisite() || (empty($current->spam) && empty($current->deleted)));
    }

    private function destination(\WP_User $user, array $options): string
    {
        $requested = (string) ($options['redirect_to'] ?? '');
        $destination = $requested !== '' ? $requested : admin_url();
        $destination = apply_filters('login_redirect', $destination, $requested, $user);
        if (!is_string($destination)) {
            $destination = '';
        }
        if ($destination === '' || $destination === 'wp-admin/' || $destination === admin_url()) {
            $destination = admin_url();
            if (is_multisite() && !get_active_blog_for_user($user->ID) && !is_super_admin($user->ID)) {
                $destination = user_admin_url();
            } elseif (is_multisite() && !$user->has_cap('read')) {
                $destination = get_dashboard_url($user->ID);
            } elseif (!$user->has_cap('edit_posts')) {
                $destination = $user->has_cap('read') ? admin_url('profile.php') : home_url();
            }
        }
        $fallback = apply_filters('wp_safe_redirect_fallback', admin_url(), 302);
        return wp_validate_redirect($destination, is_string($fallback) ? $fallback : admin_url());
    }

    private function success(\WP_User $user, array $proof, array $accepted, bool $session_changed): array
    {
        return [
            'ok' => true,
            'code' => 'ok',
            'message' => __('Passkey verified.', 'azwp-passkeys'),
            'subject_id' => (int) $user->ID,
            'data' => [
                'verified' => true,
                'session_changed' => $session_changed,
                'redirect_to' => $this->destination($user, $proof['issued_options']),
                'last_used_local' => $accepted['data']['last_used_local'] ?? null,
            ],
        ];
    }

    private function authentication_error(): \WP_Error
    {
        return new \WP_Error('authentication_failed', __('Sign-in failed. Please try again.', 'azwp-passkeys'));
    }

    private function failure(): array
    {
        return ['ok' => false, 'code' => 'authentication_failed', 'data' => [],
            'message' => __('Sign-in failed. Please try again.', 'azwp-passkeys')];
    }
}
