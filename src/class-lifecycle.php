<?php
/** Installation, account cleanup and the public related-origin document. */
namespace AZWP\Passkeys;

final class Lifecycle {
    private const CRON_HOOK = 'azwp_passkeys_cleanup';
    private const REWRITE = '^\\.well-known/webauthn/?$';
    public function __construct(private Settings $settings, private Storage $storage) {}

    public function register_hooks(): void {
        add_action('init', [$this, 'register_route']);
        add_filter('query_vars', static function (array $vars): array { $vars[] = 'azwp_passkeys_related_origins'; return $vars; });
        add_action('template_redirect', [$this, 'render_related_origins']);
        add_action('wp_initialize_site', [$this, 'initialize_site'], 100);
        add_action('remove_user_from_blog', [$this, 'remove_membership'], 10, 2);
        add_action('wpmu_delete_user', [$this, 'early_delete_account']);
        add_action('deleted_user', [$this, 'delete_account']);
        add_action(self::CRON_HOOK, [$this, 'cleanup_attempts']);
        add_filter('azwp_passkeys_version', static fn(string $version): string => AZWP_PASSKEYS_VERSION);
    }
    public function register_route(): void {
        add_rewrite_rule(self::REWRITE, 'index.php?azwp_passkeys_related_origins=1', 'top');
    }
    private function main_site(): int {
        return is_multisite() ? (int) get_main_site_id(get_main_network_id()) : get_current_blog_id();
    }
    private function on_site(int $site_id, callable $callback): mixed {
        $switched = $site_id !== get_current_blog_id();
        if ($switched) { switch_to_blog($site_id); }
        try { return $callback(); }
        finally { if ($switched) { restore_current_blog(); } }
    }
    private function initialize_current_site(): array {
        $site_id = get_current_blog_id();
        $defaults = $this->settings->get_site($site_id);
        if (is_multisite()) {
            foreach ($this->settings->definitions() as $key => $definition) {
                if ($definition['scope'] === 'network') { unset($defaults[$key]); }
            }
        }
        $result = $this->storage->save_settings('site', $site_id, $defaults);
        if ($result['ok']) {
            // Regenerate each site's route cache on its next request.
            delete_option('rewrite_rules');
        }
        return $result;
    }
    public function activate(bool $network_wide): void {
        if (is_multisite() && !$network_wide) {
            wp_die(esc_html__('Activate AZ\'s WP Passkeys for the network.', 'azwp-passkeys'));
        }
        $schema = $this->storage->install_schema();
        if ($schema['code'] === 'storage_engine') { wp_die(esc_html__('Passkey storage could not be initialized. The database tables must use the InnoDB storage engine.', 'azwp-passkeys')); }
        if (!$schema['ok']) { wp_die(esc_html__('Passkey storage could not be initialized.', 'azwp-passkeys')); }
        if (is_multisite()) {
            $network_id = get_current_network_id();
            $network = $this->storage->save_settings('network', $network_id, $this->settings->get_network($network_id));
            if (!$network['ok']) { wp_die(esc_html__('Passkey settings could not be initialized.', 'azwp-passkeys')); }
            $offset = 0;
            do {
                $sites = get_sites(['network_id' => $network_id, 'fields' => 'ids', 'number' => 100, 'offset' => $offset]);
                foreach ($sites as $site_id) {
                    $saved = $this->on_site((int) $site_id, fn(): array => $this->initialize_current_site());
                    if (!$saved['ok']) { wp_die(esc_html__('Passkey settings could not be initialized.', 'azwp-passkeys')); }
                }
                $offset += count($sites);
            } while (count($sites) === 100);
        } else {
            if (!$this->initialize_current_site()['ok']) { wp_die(esc_html__('Passkey settings could not be initialized.', 'azwp-passkeys')); }
        }
        $this->on_site($this->main_site(), static function (): void {
            if (!wp_next_scheduled(self::CRON_HOOK)) { wp_schedule_event(time(), 'hourly', self::CRON_HOOK); }
        });
        $this->register_route();
        flush_rewrite_rules(false);
    }
    public function initialize_site(\WP_Site $site): void {
        $this->on_site((int) $site->blog_id, function (): void {
            $result = $this->initialize_current_site();
            if (!$result['ok']) {
                $this->storage->append_log(get_current_blog_id(), ['event'=>'configuration_error','result'=>'storage_failed']);
            }
        });
    }
    public function deactivate(bool $network_wide = false): void {
        if (!is_multisite() || $network_wide) {
            $this->on_site($this->main_site(), static fn() => wp_clear_scheduled_hook(self::CRON_HOOK));
        }
        global $wp_rewrite;
        if (isset($wp_rewrite->extra_rules_top[self::REWRITE])) { unset($wp_rewrite->extra_rules_top[self::REWRITE]); }
        flush_rewrite_rules(false);
    }
    public function early_delete_account(int $user_id): void {
        $result = $this->storage->cleanup_user($user_id);
        $this->storage->append_log(get_current_blog_id(), ['event'=>'account_cleanup','target_id'=>$user_id,'result'=>$result['ok']?'ok':$result['code']]);
    }
    public function delete_account(int $user_id): void {
        // deleted_user can represent a membership-only operation on multisite.
        $result = $this->storage->cleanup_user($user_id, null, true);
        if (empty($result['data']['unchanged'])) {
            $this->storage->append_log(get_current_blog_id(), ['event'=>'account_cleanup','target_id'=>$user_id,'result'=>$result['ok']?'ok':$result['code']]);
        }
    }
    public function remove_membership(int $user_id, int $site_id): void {
        $result = $this->storage->cleanup_user($user_id, $site_id);
        $this->storage->append_log($site_id, ['event'=>'membership_cleanup','target_id'=>$user_id,'result'=>$result['ok']?'ok':$result['code']]);
    }
    public function cleanup_attempts(): void { $this->storage->cleanup_attempts(); }
    public function render_related_origins(): void {
        if ((string) get_query_var('azwp_passkeys_related_origins') !== '1') { return; }
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
            status_header(405);
            header('Allow: GET');
            exit;
        }
        $settings = $this->settings->get_effective(get_current_blog_id());
        $origins = [];
        foreach ($settings['related_origins'] as $value) {
            try { $origins[] = WebAuthn::canonical_origin($value, true); }
            catch (\Throwable $error) { /* Invalid publication entries are omitted. */ }
        }
        header('Access-Control-Allow-Origin: *');
        wp_send_json(['origins'=>array_values(array_unique($origins))]);
    }
    public function uninstall(): void {
        $this->on_site($this->main_site(), static fn() => wp_clear_scheduled_hook(self::CRON_HOOK));
        if (is_multisite()) {
            foreach (get_networks(['fields'=>'ids','number'=>0]) as $network_id) {
                delete_network_option((int) $network_id, 'azwp_passkeys_network_settings');
            }
            $offset = 0;
            do {
                $sites = get_sites(['fields'=>'ids','number'=>100,'offset'=>$offset]);
                foreach ($sites as $site_id) { $this->on_site((int) $site_id, fn() => $this->delete_site_options()); }
                $offset += count($sites);
            } while (count($sites) === 100);
        } else { $this->delete_site_options(); }
        $result = $this->storage->uninstall();
        if (!$result['ok']) { wp_die(esc_html__('Passkey data could not be completely removed. Try deleting the plugin again.', 'azwp-passkeys')); }
    }
    private function delete_site_options(): void {
        delete_option('azwp_passkeys_settings');
        $this->storage->delete_rate_limits(get_current_blog_id());
        wp_clear_scheduled_hook(self::CRON_HOOK);
        // The route disappears with plugin hooks; regenerate stored rewrite rules.
        global $wp_rewrite;
        if (isset($wp_rewrite->extra_rules_top[self::REWRITE])) { unset($wp_rewrite->extra_rules_top[self::REWRITE]); }
        delete_option('rewrite_rules');
    }
}
