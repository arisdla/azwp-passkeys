<?php
/** The one registry of log types: how each is written, shown and erased. */
namespace AZWP\Passkeys;

final class Events {
    /**
     * Keys, types and flags only. The writer reads this before init, so it calls no translation function.
     * Keys are never reused: a retired or renamed event keeps its old key out of use.
     */
    public static function schema(): array {
        $event = static fn(string $category, string $user, bool $passkey, array $data = [], array $personal = []): array
            => ['category' => $category, 'user' => $user, 'passkey' => $passkey, 'data' => $data, 'personal' => $personal];
        return [
            'signin.passkey' => $event('signin', 'verified', true),
            'signin.registration' => $event('signin', 'verified', false),
            'passkey.added' => $event('passkey', 'actor', true),
            'passkey.added_by_link' => $event('passkey', 'verified', true),
            'passkey.tested' => $event('passkey', 'actor', true),
            'passkey.renamed' => $event('passkey', 'actor', true, ['previous_name' => 'string'], ['previous_name' => 'target']),
            'passkey.deleted' => $event('passkey', 'actor', true),
            'passkey.account_deleted' => $event('passkey', 'system', false, ['count' => 'int']),
            'admin.setup_link' => $event('admin', 'actor', false),
            'settings.changed' => $event('settings', 'actor', false, ['setting' => 'string', 'previous' => 'setting_value', 'value' => 'setting_value']),
        ];
    }

    public static function categories(): array {
        return [
            'signin' => __('Sign-in', 'azwp-passkeys'),
            'passkey' => __('Passkey', 'azwp-passkeys'),
            'admin' => __('Admin', 'azwp-passkeys'),
            'settings' => __('Settings', 'azwp-passkeys'),
        ];
    }

    /** The schema plus the translated action and the Details builder. Details builders treat every data key as possibly absent. */
    public static function all(): array {
        $added = [
            'ok' => __('%s: added', 'azwp-passkeys'),
            /* translators: 1: passkey, 2: username of the account it was added to. */
            'ok_for' => __('%1$s: added for %2$s', 'azwp-passkeys'),
            /* translators: %s: failure reason. */
            'unknown' => __('Adding failed: %s', 'azwp-passkeys'),
        ];
        $entries = [
            'signin.passkey' => [__('Passkey', 'azwp-passkeys'), static fn(array $e): string => self::passkey_text($e, [
                'ok' => __('%s: signed in', 'azwp-passkeys'),
                'unknown' => __('Sign-in failed: %s', 'azwp-passkeys'),
            ])],
            'signin.registration' => [__('New registration', 'azwp-passkeys'), static fn(array $e): string => match (true) {
                $e['ok'] => __('Signed in after registering', 'azwp-passkeys'),
                $e['target_id'] === null => sprintf(__('Sign-in failed: %s', 'azwp-passkeys'), self::reason($e['code'])),
                /* translators: 1: account, such as "User #42 (marie)", 2: failure reason. */
                default => sprintf(__('%1$s sign-in failed: %2$s', 'azwp-passkeys'), self::who($e), self::reason($e['code'])),
            }],
            'passkey.added' => [__('Added', 'azwp-passkeys'), static fn(array $e): string => self::passkey_text($e, $added)],
            'passkey.added_by_link' => [__('Added by link', 'azwp-passkeys'), static fn(array $e): string => self::passkey_text($e, array_diff_key($added, ['ok_for' => 1]))],
            'passkey.tested' => [__('Tested', 'azwp-passkeys'), static fn(array $e): string => self::passkey_text($e, [
                'ok' => __('%s: tested', 'azwp-passkeys'),
                'ok_for' => __('%1$s: tested for %2$s', 'azwp-passkeys'),
                /* translators: 1: passkey, 2: failure reason. */
                'failed' => __('%1$s test failed: %2$s', 'azwp-passkeys'),
                /* translators: 1: passkey, 2: username of the account it belongs to, 3: failure reason. */
                'failed_for' => __('%1$s test failed for %2$s: %3$s', 'azwp-passkeys'),
                'unknown' => __('Test failed: %s', 'azwp-passkeys'),
            ])],
            'passkey.renamed' => [__('Renamed', 'azwp-passkeys'), static fn(array $e): string => self::passkey_text($e, [
                /* translators: 1: passkey with its old name, 2: new name. */
                'ok' => __('%1$s: renamed to %2$s', 'azwp-passkeys'),
                /* translators: 1: passkey with its old name, 2: new name, 3: username of the account it belongs to. */
                'ok_for' => __('%1$s: renamed to %2$s for %3$s', 'azwp-passkeys'),
                'failed' => __('%1$s renaming failed: %2$s', 'azwp-passkeys'),
                'failed_for' => __('%1$s renaming failed for %2$s: %3$s', 'azwp-passkeys'),
                'unknown' => __('Renaming failed: %s', 'azwp-passkeys'),
            ], [self::passkey($e, is_string($e['data']['previous_name'] ?? null) ? $e['data']['previous_name'] : null), $e['passkey_name'] ?? __('Passkey', 'azwp-passkeys')])],
            'passkey.deleted' => [__('Deleted', 'azwp-passkeys'), static fn(array $e): string => $e['ok'] && $e['passkey_name'] === null
                ? __('Passkey already deleted', 'azwp-passkeys')
                : self::passkey_text($e, [
                    'ok' => __('%s: deleted', 'azwp-passkeys'),
                    'ok_for' => __('%1$s: deleted for %2$s', 'azwp-passkeys'),
                    'failed' => __('%1$s deletion failed: %2$s', 'azwp-passkeys'),
                    'failed_for' => __('%1$s deletion failed for %2$s: %3$s', 'azwp-passkeys'),
                    'unknown' => __('Deletion failed: %s', 'azwp-passkeys'),
                ])],
            'passkey.account_deleted' => [__('Account deleted', 'azwp-passkeys'), static function (array $e): string {
                if (!$e['ok']) { return sprintf(__('%1$s passkey deletion failed: %2$s', 'azwp-passkeys'), self::who($e), self::reason($e['code'])); }
                $count = is_int($e['data']['count'] ?? null) ? $e['data']['count'] : 0;
                /* translators: 1: account, such as "User #42 (marie)", 2: number of passkeys. */
                return sprintf(_n('%1$s deleted with %2$d passkey', '%1$s deleted with %2$d passkeys', $count, 'azwp-passkeys'), self::who($e), $count);
            }],
            'admin.setup_link' => [__('Setup link', 'azwp-passkeys'), static fn(array $e): string => $e['ok']
                ? sprintf(__('Setup link sent to %s', 'azwp-passkeys'), self::login($e, 'target') ?? '—')
                /* translators: 1: username, 2: failure reason. */
                : sprintf(__('Setup link to %1$s failed: %2$s', 'azwp-passkeys'), self::login($e, 'target') ?? '—', self::reason($e['code']))],
            'settings.changed' => [null, static fn(array $e): string => self::setting_text($e)],
        ];
        $all = [];
        foreach (self::schema() as $key => $definition) {
            [$action, $details] = $entries[$key];
            $all[$key] = $definition + ['action' => $action, 'details' => $details];
        }
        return $all;
    }

    /** Failure codes in words. */
    public static function reason(string $code): string {
        return match ($code) {
            'authentication_failed' => __('passkey not recognized', 'azwp-passkeys'),
            'attempt_unavailable' => __('request expired or already used', 'azwp-passkeys'),
            'state_changed' => __('session or settings changed mid-request', 'azwp-passkeys'),
            'credential_exists' => __('passkey already added', 'azwp-passkeys'),
            'access_required' => __('would leave the account without a way to sign in', 'azwp-passkeys'),
            'forbidden' => __('not allowed', 'azwp-passkeys'),
            'invalid_request' => __('bad request', 'azwp-passkeys'),
            'not_configured' => __('passkeys not set up on this site', 'azwp-passkeys'),
            'outcome_unknown' => __('result not confirmed', 'azwp-passkeys'),
            'mail_failed' => __('email not sent', 'azwp-passkeys'),
            'storage_failed' => __('database error', 'azwp-passkeys'),
            'cross_origin' => __('registered from another site', 'azwp-passkeys'),
            'denied' => __('blocked by another plugin', 'azwp-passkeys'),
            'cookies_suppressed' => __('sign-in cookie blocked', 'azwp-passkeys'),
            default => str_replace('_', ' ', $code),
        };
    }

    /** The login saved for the actor or target, "User #42" when only the ID survives, or null when there is no such user. */
    public static function login(array $e, string $who): ?string {
        if ($e[$who . '_id'] === null) { return null; }
        return $e[$who . '_login'] ?? sprintf(__('User #%d', 'azwp-passkeys'), $e[$who . '_id']);
    }

    private static function who(array $e): string {
        if ($e['target_id'] === null) { return '—'; }
        /* translators: 1: user ID, 2: username. */
        return $e['target_login'] === null ? sprintf(__('User #%d', 'azwp-passkeys'), $e['target_id']) : sprintf(__('User #%1$d (%2$s)', 'azwp-passkeys'), $e['target_id'], $e['target_login']);
    }

    /** "Work phone (iCloud Keychain)", or the name alone when the authenticator is not in the catalog. */
    private static function passkey(array $e, ?string $name = null): string {
        $name ??= $e['passkey_name'] ?? __('Passkey', 'azwp-passkeys');
        $authenticator = $e['passkey_aaguid'] === null ? null : Authenticators::name($e['passkey_aaguid']);
        return $authenticator === null ? $name : sprintf('%s (%s)', $name, $authenticator);
    }

    /** Picks the template for the result, whether the passkey is known, and whether the actor acted on another account. */
    private static function passkey_text(array $e, array $templates, ?array $ok_args = null): string {
        $for = isset($templates['ok_for']) && $e['target_id'] !== null && $e['target_id'] !== $e['actor_id'] ? self::login($e, 'target') : null;
        $reason = self::reason($e['code']);
        if ($e['ok']) {
            $args = $ok_args ?? [self::passkey($e)];
            return $for === null ? sprintf($templates['ok'], ...$args) : sprintf($templates['ok_for'], ...[...$args, $for]);
        }
        if ($e['passkey_name'] !== null && isset($templates['failed'])) {
            return $for === null ? sprintf($templates['failed'], self::passkey($e), $reason) : sprintf($templates['failed_for'], self::passkey($e), $for, $reason);
        }
        return sprintf($templates['unknown'], $reason);
    }

    private static function setting_text(array $e): string {
        $labels = Settings::labels();
        $key = is_string($e['data']['setting'] ?? null) ? $e['data']['setting'] : '';
        $label = $labels['settings'][$key] ?? ($key === '' ? __('Settings', 'azwp-passkeys') : $key);
        $value = $e['data']['value'] ?? null;
        /* translators: %s: setting name. */
        if (is_bool($value)) { return sprintf($value ? __('%s turned on', 'azwp-passkeys') : __('%s turned off', 'azwp-passkeys'), $label); }
        $choices = $labels['choices'][$key] ?? [];
        $text = static function (mixed $v) use ($choices): string {
            if (is_bool($v)) { return $v ? __('on', 'azwp-passkeys') : __('off', 'azwp-passkeys'); }
            if (is_array($v)) { $v = implode(', ', $v); }
            if (!is_string($v) || $v === '') { return '—'; }
            return $choices[$v] ?? $v;
        };
        /* translators: 1: setting name, 2: old value, 3: new value. */
        return sprintf(__('%1$s changed: %2$s → %3$s', 'azwp-passkeys'), $label, $text($e['data']['previous'] ?? null), $text($value));
    }
}
