<?php
/** Writes, reads, clears and erases log events against the Events registry. */
namespace AZWP\Passkeys;

final class Logs {
    public const PER_PAGE = 20;
    public const ERASE_PAGE = 100;
    private const REDACT = '/(?:bearer\s+\S+|(?:password|cookie|token|challenge|secret|authorization|signature)\s*[:=]\s*\S+|-----BEGIN[\s\S]*?-----END[^-]*-----)/i';

    public function __construct(private Storage $storage) {}

    /** Never throws and never changes the result of the operation being logged. */
    public function record(string $event, array $fields = []): void {
        try {
            $schema = Events::schema()[$event] ?? null;
            if ($schema === null) { return; }
            $site_id = self::id($fields['site_id'] ?? null) ?? (int) get_current_blog_id();
            $enabled = $fields['enabled'] ?? (bool) ($this->storage->read_site_settings($site_id)['logging'] ?? Settings::definitions()['logging']['default']);
            if (!$enabled) { return; }
            $ok = (bool) ($fields['ok'] ?? true);
            $code = $ok ? 'ok' : (string) ($fields['code'] ?? '');
            if (!preg_match('/^[a-z_]{1,32}$/D', $code)) { $code = 'unknown'; }
            $correlation = $fields['correlation_id'] ?? null;
            $row = [
                'site_id' => $site_id, 'occurred_at' => time(), 'event' => $event, 'ok' => (int) $ok, 'code' => $code,
                'correlation_id' => is_string($correlation) && preg_match('/^[a-f0-9]{32}$/D', $correlation) ? $correlation : bin2hex(random_bytes(16)),
            ];
            foreach (['actor', 'target'] as $who) {
                $id = self::id($fields[$who . '_id'] ?? null);
                $login = array_key_exists($who . '_login', $fields) ? $fields[$who . '_login'] : ($id ? (get_userdata($id)->user_login ?? null) : null);
                $row[$who . '_id'] = $id;
                $row[$who . '_login'] = is_string($login) && $id ? mb_substr($login, 0, 60) : null;
            }
            $passkey = $schema['passkey'] && is_array($fields['passkey'] ?? null) ? $fields['passkey'] : [];
            $row['passkey_id'] = self::id($passkey['id'] ?? null);
            $row['passkey_name'] = is_string($passkey['name'] ?? null) ? self::text($passkey['name'], 255) : null;
            $row['passkey_aaguid'] = is_string($passkey['aaguid'] ?? null) && strlen($passkey['aaguid']) === 16 ? $passkey['aaguid'] : null;
            // Reverse proxies must supply the real REMOTE_ADDR, as for the sign-in rate limit.
            $ip = $_SERVER['REMOTE_ADDR'] ?? null;
            $row['ip'] = is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) ? $ip : null;
            $data = [];
            foreach ($schema['data'] as $key => $type) {
                if (!array_key_exists($key, $fields['data'] ?? [])) { continue; }
                $value = self::typed($type, $fields['data'][$key], ($fields['data']['setting'] ?? null) === 'related_origins');
                if ($value !== null) { $data[$key] = $value; }
            }
            $row['data'] = $data === [] ? null : json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            $this->storage->insert_event($row);
        } catch (\Throwable) {
            // A logging failure is dropped silently.
        }
    }

    private static function id(mixed $value): ?int {
        return is_int($value) && $value > 0 ? $value : null;
    }

    private static function text(string $value, int $length = 500): string {
        return mb_substr((string) preg_replace(self::REDACT, '[redacted]', strip_tags($value)), 0, $length);
    }

    /** The stored form of a data value, or null when it has the wrong type. */
    private static function typed(string $type, mixed $value, bool $origins): mixed {
        return match ($type) {
            'string' => is_string($value) ? self::text($value) : null,
            'int' => is_int($value) ? $value : null,
            'bool' => is_bool($value) ? $value : null,
            'setting_value' => match (true) {
                is_bool($value) => $value,
                is_string($value) => self::text($value),
                is_array($value) && array_is_list($value) => array_map(static fn(mixed $item): string => $origins ? self::origin($item) : (is_string($item) ? self::text($item) : ''), $value),
                default => null,
            },
            default => null,
        };
    }

    /** Related origins keep only scheme, host and port. */
    private static function origin(mixed $value): string {
        $parts = is_string($value) ? parse_url($value) : false;
        return is_array($parts) && isset($parts['scheme'], $parts['host'])
            ? strtolower($parts['scheme']) . '://' . strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : '')
            : '[invalid origin]';
    }

    /** The site's entries, newest first, filtered and paged in SQL. */
    public function read(int $site_id, array $request): array {
        $paged = array_key_exists('paged', $request) ? Passkeys::numeric_id($request['paged']) : 1;
        $category = $request['category'] ?? null;
        $ok = $request['ok'] ?? null;
        $schema = Events::schema();
        $categories = array_unique(array_column($schema, 'category'));
        if ($paged === null || ($category !== null && !in_array($category, $categories, true)) || ($ok !== null && !is_bool($ok))) {
            return ['ok' => false, 'code' => 'invalid_request', 'data' => [], 'message' => ''];
        }
        $events = $category === null ? null : array_keys(array_filter($schema, static fn(array $d): bool => $d['category'] === $category));
        $result = $this->storage->read_events($site_id, $events, $ok, $paged, self::PER_PAGE);
        if (!$result['ok']) { return $result; }
        $page = $result['data'];
        $all = Events::all();
        $labels = Events::categories();
        $format = get_option('date_format') . ' ' . get_option('time_format');
        $entries = array_map(static function (array $row) use ($all, $labels, $format): array {
            $definition = $all[$row['event']] ?? null;
            return [
                'id' => $row['id'], 'occurred_at' => $row['occurred_at'], 'time' => (string) wp_date($format, $row['occurred_at']),
                'event' => $row['event'],
                'category' => $definition ? $labels[$definition['category']] : '',
                'action' => $definition ? $definition['action'] : $row['event'],
                'user' => self::user($row, $definition['user'] ?? null),
                'ok' => $row['ok'], 'code' => $row['code'],
                'details' => $definition ? ($definition['details'])($row) : $row['code'],
                'correlation_id' => $row['correlation_id'],
                'ip' => $row['ip'] ?? '-',
            ];
        }, $page['rows']);
        $categories = array_map(static fn(string $key): array => ['key' => $key, 'label' => $labels[$key] ?? $key], array_values($categories));
        return ['ok' => true, 'code' => 'ok', 'message' => '', 'data' => [
            'total' => $page['total'], 'matched' => $page['matched'], 'paged' => $page['paged'], 'per_page' => self::PER_PAGE,
            'total_pages' => $page['total_pages'], 'categories' => $categories, 'entries' => $entries,
        ]];
    }

    /** The User cell, chosen by the registry's rule. A retired event shows whichever login it stored. */
    private static function user(array $row, ?string $rule): string {
        return match ($rule) {
            'system' => __('system', 'azwp-passkeys'),
            'actor' => Events::login($row, 'actor') ?? '—',
            'verified' => Events::login($row, 'actor') ?? ($row['ok'] ? Events::login($row, 'target') : null) ?? '—',
            default => $row['actor_login'] ?? $row['target_login'] ?? '—',
        };
    }

    public function clear(int $site_id): array {
        return $this->storage->clear_events($site_id);
    }

    /** WordPress personal-data eraser: keeps the rows and replaces the user's logins, passkey names and personal data keys on every site. */
    public function erase(string $email, int $page = 1): array|\WP_Error {
        $user = get_user_by('email', $email);
        if (!$user) { return ['items_removed' => false, 'items_retained' => false, 'messages' => [], 'done' => true]; }
        $user_id = (int) $user->ID;
        $changed = 0;
        if ($page <= 1) {
            $logins = $this->storage->erase_event_logins($user_id);
            if (!$logins['ok']) { return self::erase_failed(); }
            $changed = $logins['data']['changed'];
        }
        $personal = array_filter(array_map(static fn(array $d): array => $d['personal'], Events::schema()));
        $data = $this->storage->erase_event_data($user_id, $personal, max(1, $page), self::ERASE_PAGE);
        $retained = $data['ok'] ? $this->storage->count_user_events($user_id) : null;
        if (!$data['ok'] || $retained === null) { return self::erase_failed(); }
        return [
            'items_removed' => $changed + $data['data']['changed'] > 0,
            'items_retained' => $retained > 0,
            'messages' => $retained > 0 ? [__('Passkey log entries are kept with usernames and passkey names erased.', 'azwp-passkeys')] : [],
            'done' => $data['data']['rows'] < self::ERASE_PAGE,
        ];
    }

    private static function erase_failed(): \WP_Error {
        return new \WP_Error('azwp_passkeys_erase_failed', __('Passkey logs could not be erased. Try again.', 'azwp-passkeys'));
    }

    public function register_eraser(array $erasers): array {
        $erasers['azwp-passkeys-logs'] = ['eraser_friendly_name' => __('Passkey Logs', 'azwp-passkeys'), 'callback' => [$this, 'erase']];
        return $erasers;
    }
}
