<?php
/** Typed site and network configuration. */
namespace AZWP\Passkeys;

final class Settings {
    public function __construct(private Storage $storage, private Logs $logs) {}
    /** Free of translation calls, because determine_current_user reaches it before init loads the text domain. */
    public static function definitions(): array {
        return [
            'rp_name' => ['scope' => 'site', 'type' => 'string', 'default' => ''],
            'rp_id' => ['scope' => 'site', 'type' => 'host', 'default' => ''],
            'passkey_only' => ['scope' => 'network', 'type' => 'boolean', 'default' => false],
            'remember_login' => ['scope' => 'site', 'type' => 'boolean', 'default' => false],
            'reset_restriction' => ['scope' => 'site', 'type' => 'choice', 'default' => 'off', 'choices' => ['off','except_admin','everyone']],
            'after_registration' => ['scope' => 'site', 'type' => 'choice', 'default' => 'default', 'choices' => ['default','add_passkey'], 'single_site' => true],
            'logging' => ['scope' => 'site', 'type' => 'boolean', 'default' => true],
            'related_origins' => ['scope' => 'network', 'type' => 'origins', 'default' => []],
        ];
    }
    /** Setting and choice labels for the settings screens and the log. Call only after init. */
    public static function labels(): array {
        return [
            'settings' => [
                'rp_name' => __('Website name', 'azwp-passkeys'),
                'rp_id' => __('Passkey domain', 'azwp-passkeys'),
                'passkey_only' => __('Passkey only mode', 'azwp-passkeys'),
                'remember_login' => __('Remember me', 'azwp-passkeys'),
                'reset_restriction' => __('Block password resets', 'azwp-passkeys'),
                'after_registration' => __('After registration', 'azwp-passkeys'),
                'logging' => __('Logging', 'azwp-passkeys'),
                'related_origins' => __('Related origins', 'azwp-passkeys'),
            ],
            'choices' => [
                'reset_restriction' => ['off' => __('No', 'azwp-passkeys'), 'except_admin' => __('Except for administrators', 'azwp-passkeys'), 'everyone' => __('For everyone', 'azwp-passkeys')],
                'after_registration' => ['default' => __('WordPress default', 'azwp-passkeys'), 'add_passkey' => __('Sign in and add a passkey', 'azwp-passkeys')],
            ],
        ];
    }
    public static function site_values(array $defaults, array $stored): array {
        $definitions = self::definitions();
        return array_replace(array_map(static fn(array $d) => $d['default'], $definitions), $defaults, array_intersect_key($stored, $definitions));
    }
    public static function network_values(array $stored): array {
        $definitions = array_filter(self::definitions(), static fn(array $d): bool => $d['scope'] === 'network');
        return array_replace(array_map(static fn(array $d) => $d['default'], $definitions), array_intersect_key($stored, $definitions));
    }
    public function get_site(int $site_id): array {
        return self::site_values($this->storage->site_defaults($site_id), $this->storage->read_site_settings($site_id));
    }
    public function get_network(int $network_id): array {
        return self::network_values($this->storage->read_network_settings($network_id));
    }
    public function get_effective(int $site_id): array {
        $site = $this->get_site($site_id);
        if (is_multisite()) {
            $network_id = (int) get_current_network_id();
            if ($site_id !== get_current_blog_id()) {
                $site_object = get_site($site_id);
                if ($site_object) { $network_id = (int) $site_object->network_id; }
            }
            $site = array_replace($site, $this->get_network($network_id));
        }
        return $site;
    }
    private static function failure(array $invalid = []): array {
        return ['ok' => false, 'code' => 'invalid_request', 'data' => ['invalid' => $invalid], 'message' => ''];
    }
    private function host(string $value): ?string {
        $value = strtolower(trim($value));
        if ($value === '') { return ''; }
        if (preg_match('/[^\x00-\x7f]/', $value)) {
            try {
                if (!class_exists('WpOrg\\Requests\\IdnaEncoder')) { return null; }
                $value = \WpOrg\Requests\IdnaEncoder::encode($value);
            } catch (\Throwable $e) { return null; }
        }
        if (strlen($value) > 253 || strpbrk($value, '/:@?#') !== false || preg_match('/\s/', $value)) { return null; }
        if ($value === 'localhost') { return $value; }
        $labels = explode('.', $value);
        foreach ($labels as $label) {
            if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $label)) { return null; }
        }
        // Browsers refuse an IP address as a passkey domain, and a real top-level label is never all digits.
        return ctype_digit(end($labels)) ? null : $value;
    }
    private function parse(string $key, mixed $value): array {
        $definition = $this->definitions()[$key];
        switch ($definition['type']) {
            case 'boolean':
                return in_array($value, ['0','1'], true) ? [true, $value === '1'] : [false, null];
            case 'choice':
                return is_string($value) && in_array($value, $definition['choices'], true) ? [true, $value] : [false, null];
            case 'string':
                return is_string($value) ? [true, sanitize_text_field($value)] : [false, null];
            case 'host':
                $host = is_string($value) ? $this->host($value) : null;
                return [$host !== null, $host];
            case 'origins':
                if (!is_array($value) || !array_is_list($value)) { return [false, null]; }
                foreach ($value as $origin) { if (!is_string($origin)) { return [false, null]; } }
                return [true, array_values(array_unique(array_map('sanitize_text_field', $value)))];
        }
        return [false, null];
    }
    public function save_site(array $input, callable $validate): array {
        $values = [];
        $invalid = [];
        foreach ($this->definitions() as $key => $definition) {
            if ($key === 'logging' || (is_multisite() && ($definition['scope'] === 'network' || !empty($definition['single_site'])))) { continue; }
            if ($key === 'related_origins' && !array_key_exists($key, $input)) { continue; }
            [$valid, $value] = $this->parse($key, $input[$key] ?? null);
            if (!$valid) { $invalid[] = $key; } else { $values[$key] = $value; }
        }
        if ($invalid) { return self::failure($invalid); }
        return $this->save('site', get_current_blog_id(), $values, $validate);
    }
    public function save_network(array $input, callable $validate): array {
        $values = [];
        foreach ($this->definitions() as $key => $definition) {
            if ($definition['scope'] !== 'network') { continue; }
            [$valid, $value] = $this->parse($key, $input[$key] ?? null);
            $values[$key] = $valid ? $value : $definition['default'];
        }
        return $this->save(is_multisite() ? 'network' : 'site', is_multisite() ? get_current_network_id() : get_current_blog_id(), $values, $validate);
    }
    public function save_logs(array $input): array {
        [$valid, $logging] = $this->parse('logging', $input['logging'] ?? null);
        if (!$valid) { return self::failure(['logging']); }
        return $this->save('site', get_current_blog_id(), ['logging' => $logging]);
    }
    private function save(string $scope, int $scope_id, array $values, ?callable $validate = null): array {
        $site_id = get_current_blog_id();
        try { $before_effective = $this->get_effective($site_id); }
        catch (\Throwable) { return ['ok' => false, 'code' => 'storage_failed', 'data' => [], 'message' => '']; }
        $result = $this->storage->save_settings($scope, $scope_id, $values, $validate);
        if (!$result['ok']) { return $result; }
        $correlation = bin2hex(random_bytes(16));
        // Turning logging on or off writes its own row, so a save is logged when logging was on before or after it.
        $enabled = !empty($before_effective['logging']) || !empty($values['logging'] ?? $before_effective['logging']);
        foreach ($values as $key => $value) {
            $old = $result['data']['previous'][$key] ?? $this->definitions()[$key]['default'];
            if ($old === $value) { continue; }
            $this->logs->record('settings.changed', ['actor_id' => get_current_user_id(), 'correlation_id' => $correlation, 'enabled' => $enabled, 'data' => ['setting' => $key, 'previous' => $old, 'value' => $value]]);
        }
        if ($scope === 'site') { do_action('azwp_passkeys_settings_saved', $correlation); }
        $result['data']['correlation_id'] = $correlation;
        return $result;
    }
}
