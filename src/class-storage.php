<?php
/** Database persistence and transaction ownership. */
namespace AZWP\Passkeys;

final class Storage {
    public const LOCK_WAIT_SECONDS = 5;
    /** 2 replaced the logs table with the events table. */
    public const SCHEMA_VERSION = 2;
    private const SETUP_LINK_KEY = 'azwp_passkeys_setup_link';
    private const ENGINE_FAILURE = 1;
    private \wpdb $db;
    private array $tables;
    private ?int $locked_owner = null;
    private bool $in_transaction = false;
    private string $lock_name;
    private array $invalidate = [];

    public function __construct(\wpdb $wpdb) {
        $this->db = $wpdb;
        foreach (['identities', 'credentials', 'attempts', 'events'] as $name) {
            $this->tables[$name] = $wpdb->base_prefix . 'azwp_passkeys_' . $name;
        }
        $this->lock_name = 'azwp-passkeys:' . substr(hash('sha256', (defined('DB_NAME') ? DB_NAME : '') . ':' . $wpdb->base_prefix), 0, 32);
    }

    private static function ok(array $data = []): array { return ['ok' => true, 'code' => 'ok', 'data' => $data, 'message' => '']; }
    private static function error(string $code = 'storage_failed'): array { return ['ok' => false, 'code' => $code, 'data' => [], 'message' => '']; }
    private function query(string $sql): int {
        $result = $this->db->query($sql);
        if ($result === false) { throw new \RuntimeException('Database operation failed'); }
        return (int) $result;
    }
    private function row(string $sql): ?array {
        $row = $this->db->get_row($sql, ARRAY_A);
        if ($this->db->last_error !== '') { throw new \RuntimeException('Database read failed'); }
        return $row;
    }
    private function rows(string $sql): array {
        $rows = $this->db->get_results($sql, ARRAY_A);
        if ($this->db->last_error !== '') { throw new \RuntimeException('Database read failed'); }
        return $rows ?: [];
    }
    /** The events table is left out, so a missing events table never blocks a passkey operation. */
    private function transactional_tables(array $extra = []): void {
        $names = array_merge(array_values(array_diff_key($this->tables, ['events' => true])), [$this->db->users, $this->db->usermeta, $this->db->options], $extra);
        if (is_multisite()) { $names[] = $this->db->sitemeta; }
        foreach (array_unique($names) as $name) {
            $row = $this->row($this->db->prepare('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s', $name));
            if (!$row) { throw new \RuntimeException('Table unavailable'); }
            if (strcasecmp((string) $row['ENGINE'], 'InnoDB') !== 0) { throw new \RuntimeException('Transactional storage unavailable', self::ENGINE_FAILURE); }
        }
    }
    /** Activation writes settings into every site's options table on the network. */
    private function network_options_tables(): array {
        if (!is_multisite()) { return []; }
        $names = [];
        $offset = 0;
        do {
            $sites = get_sites(['network_id' => get_current_network_id(), 'fields' => 'ids', 'number' => 100, 'offset' => $offset]);
            foreach ($sites as $site_id) { $names[] = $this->options_table((int) $site_id); }
            $offset += count($sites);
        } while (count($sites) === 100);
        return $names;
    }
    public function install_schema(): array {
        $charset = $this->db->get_charset_collate();
        $t = $this->tables;
        $schemas = [
            "CREATE TABLE IF NOT EXISTS `{$t['identities']}` (user_id BIGINT UNSIGNED NOT NULL, handle BINARY(64) NOT NULL, enrollment_initialized TINYINT UNSIGNED NOT NULL DEFAULT 0, created_at BIGINT UNSIGNED NOT NULL, PRIMARY KEY (user_id), UNIQUE KEY handle (handle)) ENGINE=InnoDB $charset",
            "CREATE TABLE IF NOT EXISTS `{$t['credentials']}` (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, user_id BIGINT UNSIGNED NOT NULL, site_id BIGINT UNSIGNED NOT NULL, credential_hash BINARY(32) NOT NULL, credential_id BLOB NOT NULL, rp_id VARCHAR(253) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, public_key_pem TEXT NOT NULL, public_key_cose BLOB NOT NULL, credential_type VARCHAR(10) NOT NULL, attestation_type VARCHAR(32) NOT NULL, trust_path TEXT NOT NULL, aaguid BINARY(16) NOT NULL, other_ui TEXT NULL, algorithm SMALLINT NOT NULL, sign_count BIGINT UNSIGNED NOT NULL, backup_eligible TINYINT UNSIGNED NOT NULL, backed_up TINYINT UNSIGNED NOT NULL, transports TEXT NOT NULL, name TEXT NOT NULL, created_at BIGINT UNSIGNED NOT NULL, created_local DATETIME NOT NULL, last_used_local DATETIME NULL, PRIMARY KEY (id), UNIQUE KEY credential_hash (credential_hash), KEY owner_site_created (user_id,site_id,created_at,id), KEY owner_rp (user_id,rp_id)) ENGINE=InnoDB $charset",
            "CREATE TABLE IF NOT EXISTS `{$t['attempts']}` (id BINARY(32) NOT NULL, site_id BIGINT UNSIGNED NOT NULL, purpose VARCHAR(16) NOT NULL, actor_id BIGINT UNSIGNED NULL, target_id BIGINT UNSIGNED NULL, browser_hash BINARY(32) NULL, session_hash BINARY(32) NULL, challenge BINARY(32) NOT NULL, issued TEXT NOT NULL, status VARCHAR(8) NOT NULL, created_at BIGINT UNSIGNED NOT NULL, expires_at BIGINT UNSIGNED NOT NULL, PRIMARY KEY (id), KEY expires_at (expires_at)) ENGINE=InnoDB $charset",
            "CREATE TABLE IF NOT EXISTS `{$t['events']}` (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, site_id BIGINT UNSIGNED NOT NULL, occurred_at BIGINT UNSIGNED NOT NULL, event VARCHAR(48) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, ok TINYINT UNSIGNED NOT NULL, code VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, correlation_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL, actor_id BIGINT UNSIGNED NULL, actor_login VARCHAR(60) NULL, target_id BIGINT UNSIGNED NULL, target_login VARCHAR(60) NULL, passkey_id BIGINT UNSIGNED NULL, passkey_name VARCHAR(255) NULL, passkey_aaguid BINARY(16) NULL, ip VARCHAR(45) CHARACTER SET ascii COLLATE ascii_bin NULL, data TEXT NULL, PRIMARY KEY (id), KEY site_id_id (site_id,id), KEY site_event (site_id,event,id), KEY actor (actor_id), KEY target (target_id)) ENGINE=InnoDB $charset",
        ];
        try {
            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            foreach ($schemas as $sql) {
                $sql = str_replace('CREATE TABLE IF NOT EXISTS', 'CREATE TABLE', $sql);
                // dbDelta requires one definition per line and two spaces after PRIMARY KEY.
                $sql = preg_replace('/, (?=[a-zA-Z_]+ (?:BIGINT|BINARY|TINYINT|BLOB|VARCHAR|TEXT|SMALLINT|DATETIME|CHAR)|PRIMARY KEY|UNIQUE KEY|KEY )/', ",\n", $sql);
                $sql = str_replace('PRIMARY KEY (', 'PRIMARY KEY  (', $sql);
                $sql = preg_replace('/^(CREATE TABLE `[^`]+` \()/', "$1\n", $sql);
                $sql = str_replace(') ENGINE=', "\n) ENGINE=", $sql);
                dbDelta($sql);
                if ($this->db->last_error !== '') { throw new \RuntimeException('Schema installation failed'); }
            }
            $this->verify_schema();
            $this->transactional_tables([$this->tables['events'], ...$this->network_options_tables()]);
            return self::ok();
        } catch (\Throwable $e) { return self::error($e->getCode() === self::ENGINE_FAILURE ? 'storage_engine' : 'storage_failed'); }
    }

    private function verify_schema(): void {
        $indexes = [
            'identities' => ['PRIMARY' => ['user_id'], 'handle' => ['handle']],
            'credentials' => ['PRIMARY' => ['id'], 'credential_hash' => ['credential_hash'], 'owner_site_created' => ['user_id','site_id','created_at','id'], 'owner_rp' => ['user_id','rp_id']],
            'attempts' => ['PRIMARY' => ['id'], 'expires_at' => ['expires_at']],
            'events' => ['PRIMARY' => ['id'], 'site_id_id' => ['site_id','id'], 'site_event' => ['site_id','event','id'], 'actor' => ['actor_id'], 'target' => ['target_id']],
        ];
        foreach ($indexes as $name => $required) {
            $found = [];
            foreach ($this->rows("SHOW INDEX FROM `{$this->tables[$name]}`") as $index) {
                $found[$index['Key_name']][(int) $index['Seq_in_index']] = $index['Column_name'];
                if (in_array($index['Key_name'], ['PRIMARY','handle','credential_hash'], true) && (int) $index['Non_unique'] !== 0) { throw new \RuntimeException('Unique index unavailable'); }
            }
            foreach ($required as $key => $columns) {
                if (!isset($found[$key])) { throw new \RuntimeException('Index unavailable'); }
                ksort($found[$key]);
                if (array_values($found[$key]) !== $columns) { throw new \RuntimeException('Incorrect index'); }
            }
        }
    }

    /** A callback cannot commit, nest transactions or perform external side effects. */
    private function transaction(callable $operation): array {
        if ($this->in_transaction) { return self::error(); }
        $acquired = false;
        try {
            $this->transactional_tables();
            $lock = $this->db->get_var($this->db->prepare('SELECT GET_LOCK(%s,%d)', $this->lock_name, self::LOCK_WAIT_SECONDS));
            if ((string) $lock !== '1') { return self::error(); }
            $acquired = true;
            $this->query('START TRANSACTION');
            $this->in_transaction = true;
            $result = $operation();
            if (!is_array($result) || empty($result['ok'])) {
                $this->query('ROLLBACK');
                return is_array($result) ? $result : self::error();
            }
            if ($this->db->query('COMMIT') === false) {
                $this->db->query('ROLLBACK');
                return self::error('outcome_unknown');
            }
            return $result;
        } catch (\Throwable $e) {
            if ($this->in_transaction) { $this->db->query('ROLLBACK'); }
            return self::error();
        } finally {
            $this->locked_owner = null;
            $this->in_transaction = false;
            if ($acquired) { $this->db->get_var($this->db->prepare('SELECT RELEASE_LOCK(%s)', $this->lock_name)); }
            foreach ($this->invalidate as [$kind, $id]) { $this->invalidate_cache($kind, $id); }
            $this->invalidate = [];
        }
    }
    public function with_owner_lock(int $user_id, callable $operation, bool $allow_missing_account = false): array {
        if ($user_id <= 0) { return self::error('invalid_request'); }
        return $this->transaction(function () use ($user_id, $operation, $allow_missing_account): array {
            $exists = $this->account_exists($user_id);
            if (!$exists && !$allow_missing_account) { return self::error('authentication_failed'); }
            $identity = $this->identity_row($user_id);
            if (!$identity && $exists) {
                do {
                    $handle = random_bytes(64);
                    // The global advisory lock serializes plugin provisioning. Unique keys
                    // also protect against another writer without replacing an existing handle.
                    $inserted = $this->db->insert($this->tables['identities'], ['user_id' => $user_id, 'handle' => $handle, 'enrollment_initialized' => 0, 'created_at' => time()], ['%d', '%s', '%d', '%d']);
                    if ($inserted === false) {
                        $identity = $this->identity_row($user_id);
                        if ($identity) { break; }
                        $collision = $this->row($this->db->prepare("SELECT user_id FROM `{$this->tables['identities']}` WHERE handle=%s", $handle));
                        if (!$collision) { throw new \RuntimeException('Identity insert failed'); }
                    }
                } while ($inserted === false);
            }
            $this->row($this->db->prepare("SELECT user_id FROM `{$this->tables['identities']}` WHERE user_id=%d FOR UPDATE", $user_id));
            $this->locked_owner = $user_id;
            // Lock every owned credential in the documented stable order.
            $this->rows($this->db->prepare("SELECT id FROM `{$this->tables['credentials']}` WHERE user_id=%d ORDER BY id FOR UPDATE", $user_id));
            return $operation($this);
        });
    }
    private function owner(int $user_id): void {
        if (!$this->in_transaction || $this->locked_owner !== $user_id) { throw new \RuntimeException('Owner transaction required'); }
    }
    public function account_exists(int $user_id): bool {
        return $this->row($this->db->prepare("SELECT ID FROM `{$this->db->users}` WHERE ID=%d", $user_id)) !== null;
    }
    public function get_account_password(int $user_id): string {
        $row = $this->row($this->db->prepare("SELECT user_pass FROM `{$this->db->users}` WHERE ID=%d", $user_id));
        return $row ? (string) $row['user_pass'] : '';
    }
    private function identity_row(int $user_id): ?array {
        return $this->row($this->db->prepare("SELECT * FROM `{$this->tables['identities']}` WHERE user_id=%d", $user_id));
    }
    public function get_identity(int $user_id): array {
        try { return self::ok(['identity' => $this->identity_row($user_id)]); } catch (\Throwable $e) { return self::error(); }
    }
    public function initialize_identity(int $user_id): array {
        try {
            $this->owner($user_id);
            if (!$this->account_exists($user_id)) { return self::error('authentication_failed'); }
            $this->query($this->db->prepare("UPDATE `{$this->tables['identities']}` SET enrollment_initialized=1 WHERE user_id=%d", $user_id));
            $row = $this->identity_row($user_id);
            return $row && (int) $row['enrollment_initialized'] === 1 ? self::ok(['identity' => $row]) : self::error();
        } catch (\Throwable $e) { return self::error(); }
    }
    private function credential_row(array $row): array {
        foreach (['id', 'user_id', 'site_id'] as $key) {
            $value = (string) $row[$key];
            if (strlen($value) > strlen((string) PHP_INT_MAX) || (strlen($value) === strlen((string) PHP_INT_MAX) && strcmp($value, (string) PHP_INT_MAX) > 0)) { throw new \RuntimeException('ID out of range'); }
            $row[$key] = (int) $value;
        }
        foreach (['created_at', 'sign_count', 'algorithm'] as $key) { $row[$key] = (int) $row[$key]; }
        foreach (['backup_eligible', 'backed_up'] as $key) { $row[$key] = (bool) $row[$key]; }
        foreach (['transports', 'trust_path'] as $key) { $row[$key] = json_decode($row[$key], true, 512, JSON_THROW_ON_ERROR); }
        return $row;
    }
    public function get_credential(int $record_id): array {
        try {
            $row = $this->row($this->db->prepare("SELECT * FROM `{$this->tables['credentials']}` WHERE id=%d", $record_id));
            return self::ok(['credential' => $row ? $this->credential_row($row) : null]);
        } catch (\Throwable $e) { return self::error(); }
    }
    public function find_credential(string $credential_id): array {
        try {
            $row = $this->row($this->db->prepare("SELECT * FROM `{$this->tables['credentials']}` WHERE credential_hash=%s", hash('sha256', $credential_id, true)));
            if ($row && !hash_equals($row['credential_id'], $credential_id)) { return self::error('authentication_failed'); }
            return self::ok(['credential' => $row ? $this->credential_row($row) : null]);
        } catch (\Throwable $e) { return self::error(); }
    }
    public function get_credentials(int $user_id, ?int $site_id = null): array {
        try {
            $sql = $this->db->prepare("SELECT * FROM `{$this->tables['credentials']}` WHERE user_id=%d", $user_id);
            if ($site_id !== null) { $sql .= $this->db->prepare(' AND site_id=%d', $site_id); }
            return self::ok(['credentials' => array_map([$this, 'credential_row'], $this->rows($sql . ' ORDER BY created_at,id'))]);
        } catch (\Throwable $e) { return self::error(); }
    }
    public function get_locked_credentials(int $user_id): array { $this->owner($user_id); return $this->get_credentials($user_id); }
    public function insert_credential(array $credential): array {
        try {
            $this->owner($credential['user_id']);
            if (!$this->account_exists($credential['user_id'])) { return self::error('authentication_failed'); }
            $existing = $this->find_credential($credential['credential_id']);
            if (!$existing['ok']) { return $existing; }
            if ($existing['data']['credential']) { return self::error('credential_exists'); }
            $fields = ['user_id','site_id','credential_id','rp_id','public_key_pem','public_key_cose','credential_type','attestation_type','trust_path','aaguid','other_ui','algorithm','sign_count','backup_eligible','backed_up','transports','name','created_at','created_local','last_used_local'];
            $data = array_intersect_key($credential, array_flip($fields));
            $data['credential_hash'] = hash('sha256', $credential['credential_id'], true);
            $credential['transports'] = array_values(array_unique($data['transports']));
            $data['transports'] = json_encode($credential['transports'], JSON_THROW_ON_ERROR);
            $data['trust_path'] = json_encode($data['trust_path'], JSON_THROW_ON_ERROR);
            foreach (['backup_eligible','backed_up'] as $key) { $data[$key] = (int) $data[$key]; }
            if ($this->db->insert($this->tables['credentials'], $data) === false) { return self::error(); }
            $result = $this->get_credential((int) $this->db->insert_id);
            if (!$result['ok'] || !$result['data']['credential']) { return self::error(); }
            foreach ($fields as $key) {
                if (array_key_exists($key, $credential) && $result['data']['credential'][$key] !== $credential[$key] && !in_array($key, ['user_id','site_id','created_at','sign_count','algorithm'], true)) { return self::error(); }
            }
            return $result;
        } catch (\Throwable $e) { return self::error(); }
    }
    public function update_credential(int $record_id, array $values): array {
        try {
            $current = $this->get_credential($record_id);
            if (!$current['ok']) { return $current; }
            $row = $current['data']['credential'];
            if (!$row) { return self::error('state_changed'); }
            $this->owner($row['user_id']);
            $data = array_intersect_key($values, array_flip(['name','sign_count','backed_up','last_used_local']));
            if (isset($data['backed_up'])) { $data['backed_up'] = (int) $data['backed_up']; }
            if ($data && $this->db->update($this->tables['credentials'], $data, ['id' => $record_id, 'user_id' => $row['user_id']]) === false) { return self::error(); }
            $saved = $this->get_credential($record_id);
            if (!$saved['ok'] || !$saved['data']['credential']) { return self::error(); }
            foreach ($values as $key => $value) { if (!array_key_exists($key, $data) || $saved['data']['credential'][$key] !== $value) { return self::error(); } }
            return $saved;
        } catch (\Throwable $e) { return self::error(); }
    }
    public function delete_credential(int $record_id): array {
        try {
            if ($this->locked_owner === null) { return self::error(); }
            $this->query($this->db->prepare("DELETE FROM `{$this->tables['credentials']}` WHERE id=%d AND user_id=%d", $record_id, $this->locked_owner));
            $remaining = $this->get_credential($record_id);
            return $remaining['ok'] && $remaining['data']['credential'] === null ? self::ok(['removed' => true]) : self::error();
        } catch (\Throwable $e) { return self::error(); }
    }
    private static function attempt_bytes(string $id): ?string {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/D', $id)) { return null; }
        $bytes = base64_decode(strtr($id, '-_', '+/') . '=', true);
        return $bytes !== false && strlen($bytes) === 32 && rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=') === $id ? $bytes : null;
    }
    public function create_attempt(array $attempt): array {
        $write = function () use ($attempt): array {
            foreach (['actor_id','target_id'] as $key) {
                if (!empty($attempt[$key]) && !$this->account_exists((int) $attempt[$key])) { return self::error('authentication_failed'); }
            }
            $data = array_intersect_key($attempt, array_flip(['id','site_id','purpose','actor_id','target_id','browser_hash','session_hash','challenge','issued','created_at','expires_at']));
            $data['status'] = 'pending';
            $data['issued'] = json_encode($attempt['issued'], JSON_THROW_ON_ERROR);
            if ($this->db->insert($this->tables['attempts'], $data) === false) { return self::error(); }
            return self::ok(['attempt' => $attempt + ['status' => 'pending']]);
        };
        try {
            if ($this->in_transaction) { return $write(); }
            if (empty($attempt['actor_id'])) {
                // Anonymous attempts change no owner state, so they skip the installation-wide lock.
                // A shared cap would let a few addresses lock everyone out, so the table holds only unexpired attempts instead.
                $this->query($this->db->prepare("DELETE FROM `{$this->tables['attempts']}` WHERE expires_at<=%d LIMIT 100", time()));
                return $write();
            }
            $owner = (int) ($attempt['target_id'] ?? $attempt['actor_id'] ?? 0);
            return $owner > 0 ? $this->with_owner_lock($owner, $write) : $this->transaction($write);
        } catch (\Throwable $e) { return self::error(); }
    }
    public function read_attempt(string $attempt_id): array {
        $id = self::attempt_bytes($attempt_id);
        if ($id === null) { return self::error('invalid_request'); }
        try {
            $row = $this->row($this->db->prepare("SELECT * FROM `{$this->tables['attempts']}` WHERE id=%s", $id));
            if ($row) {
                $row['issued'] = json_decode($row['issued'], true, 512, JSON_THROW_ON_ERROR);
                foreach (['site_id','actor_id','target_id','created_at','expires_at'] as $key) {
                    if ($row[$key] !== null) {
                        if (strlen((string) $row[$key]) > strlen((string) PHP_INT_MAX) || (strlen((string) $row[$key]) === strlen((string) PHP_INT_MAX) && strcmp((string) $row[$key], (string) PHP_INT_MAX) > 0)) { return self::error(); }
                        $row[$key] = (int) $row[$key];
                    }
                }
            }
            return self::ok(['attempt' => $row]);
        } catch (\Throwable $e) { return self::error(); }
    }
    public function claim_attempt(string $attempt_id, array $binding): array {
        if ($this->in_transaction) { return self::error(); }
        $binding['actor_id'] = empty($binding['actor_id']) ? null : (int) $binding['actor_id'];
        $read = $this->read_attempt($attempt_id);
        if (!$read['ok']) { return $read; }
        $attempt = $read['data']['attempt'];
        if (!$attempt || $attempt['status'] !== 'pending' || $attempt['expires_at'] <= time()) { return self::error('attempt_unavailable'); }
        foreach (['site_id','purpose','actor_id','browser_hash','session_hash'] as $key) {
            if (!array_key_exists($key, $binding) || $attempt[$key] !== $binding[$key]) { return self::error('attempt_unavailable'); }
        }
        if (array_key_exists('target_id', $binding) && $attempt['target_id'] !== $binding['target_id']) { return self::error('attempt_unavailable'); }
        if (array_key_exists('name', $binding) && ($attempt['issued']['name'] ?? null) !== $binding['name']) { return self::error('attempt_unavailable'); }
        try {
            $where = $this->db->prepare('id=%s AND site_id=%d AND purpose=%s AND status=%s AND expires_at>%d', $attempt['id'], $binding['site_id'], $binding['purpose'], 'pending', time());
            foreach (['actor_id','target_id','browser_hash','session_hash'] as $key) {
                $value = $attempt[$key];
                $where .= $value === null ? " AND $key IS NULL" : $this->db->prepare(" AND $key=%s", $value);
            }
            // Autocommit makes the unique winning claim durable before verification.
            $count = $this->query("UPDATE `{$this->tables['attempts']}` SET status='claimed' WHERE $where");
            if ($count !== 1) { return self::error('attempt_unavailable'); }
            $attempt['status'] = 'claimed';
            return self::ok(['attempt' => $attempt]);
        } catch (\Throwable $e) { return self::error(); }
    }
    public function delete_attempt(string $attempt_id): array {
        $id = self::attempt_bytes($attempt_id);
        if ($id === null) { return self::error('invalid_request'); }
        try { $this->query($this->db->prepare("DELETE FROM `{$this->tables['attempts']}` WHERE id=%s", $id)); return self::ok(); }
        catch (\Throwable $e) { return self::error(); }
    }
    public function cleanup_attempts(): array {
        try { $count = $this->query($this->db->prepare("DELETE FROM `{$this->tables['attempts']}` WHERE expires_at<=%d", time())); return self::ok(['removed' => $count]); }
        catch (\Throwable $e) { return self::error(); }
    }
    public function save_last_used(int $record_id, string $local_datetime): array {
        if ($this->in_transaction) { return self::error(); }
        try {
            $this->query($this->db->prepare("UPDATE `{$this->tables['credentials']}` SET last_used_local=%s WHERE id=%d", $local_datetime, $record_id));
            $row = $this->get_credential($record_id);
            return $row['ok'] && ($row['data']['credential']['last_used_local'] ?? null) === $local_datetime ? self::ok(['last_used_local' => $local_datetime]) : self::error();
        } catch (\Throwable $e) { return self::error(); }
    }
    private function options_table(int $site_id): string { return $this->db->get_blog_prefix($site_id) . 'options'; }
    public function read_site_settings(int $site_id): array {
        return $this->read_option_record($this->options_table($site_id), 'azwp_passkeys_settings');
    }
    public function site_defaults(int $site_id): array {
        $table = $this->options_table($site_id);
        $rows = $this->rows("SELECT option_name,option_value FROM `$table` WHERE option_name IN ('blogname','siteurl')");
        $values = array_column($rows, 'option_value', 'option_name');
        if ($site_id === get_current_blog_id() && defined('WP_SITEURL')) { $values['siteurl'] = WP_SITEURL; }
        return ['rp_name' => (string) ($values['blogname'] ?? ''), 'rp_id' => (string) (parse_url($values['siteurl'] ?? '', PHP_URL_HOST) ?: '')];
    }
    private function read_option_record(string $table, string $key): array {
        $row = $this->row($this->db->prepare("SELECT option_value FROM `$table` WHERE option_name=%s", $key));
        $value = $row ? maybe_unserialize($row['option_value']) : [];
        return is_array($value) ? $value : [];
    }
    public function read_network_settings(int $network_id): array {
        if (!is_multisite()) { return $this->read_site_settings(get_current_blog_id()); }
        $row = $this->row($this->db->prepare("SELECT meta_value FROM `{$this->db->sitemeta}` WHERE site_id=%d AND meta_key=%s ORDER BY meta_id LIMIT 1", $network_id, 'azwp_passkeys_network_settings'));
        $value = $row ? maybe_unserialize($row['meta_value']) : [];
        return is_array($value) ? $value : [];
    }
    /** One pending setup link per account: {hash, expires_at, issued_by, site_id}. Issuing a new link replaces the old one. */
    public function save_setup_link(int $user_id, array $link): array {
        return $this->with_owner_lock($user_id, function () use ($user_id, $link): array {
            $this->invalidate[] = ['user', $user_id];
            $this->query($this->db->prepare("DELETE FROM `{$this->db->usermeta}` WHERE user_id=%d AND meta_key=%s", $user_id, self::SETUP_LINK_KEY));
            if ($this->db->insert($this->db->usermeta, ['user_id' => $user_id, 'meta_key' => self::SETUP_LINK_KEY, 'meta_value' => json_encode($link, JSON_THROW_ON_ERROR)]) === false) { return self::error(); }
            return self::ok();
        });
    }
    public function get_setup_link(int $user_id): ?array {
        $row = $this->row($this->db->prepare("SELECT meta_value FROM `{$this->db->usermeta}` WHERE user_id=%d AND meta_key=%s ORDER BY umeta_id DESC LIMIT 1", $user_id, self::SETUP_LINK_KEY));
        $link = $row ? json_decode((string) $row['meta_value'], true) : null;
        return is_array($link) && is_string($link['hash'] ?? null) && is_int($link['expires_at'] ?? null) && is_int($link['site_id'] ?? null) && is_int($link['issued_by'] ?? null) ? $link : null;
    }
    /** Under the owner lock, removes and returns the link only if the token hash, site and expiry all match. */
    public function consume_setup_link(int $user_id, string $hash, int $site_id): ?array {
        $this->owner($user_id);
        $link = $this->get_setup_link($user_id);
        if (!$link || !hash_equals($link['hash'], $hash) || $link['site_id'] !== $site_id || $link['expires_at'] <= time()) { return null; }
        $this->invalidate[] = ['user', $user_id];
        $this->query($this->db->prepare("DELETE FROM `{$this->db->usermeta}` WHERE user_id=%d AND meta_key=%s", $user_id, self::SETUP_LINK_KEY));
        return $link;
    }
    /** Members of a site with no stored passkey for the given passkey domain. Single-site counts every account, as the Users screen does. */
    public function members_without_passkey(int $site_id, string $rp_id): array {
        $missing = $this->db->prepare("NOT EXISTS (SELECT 1 FROM `{$this->tables['credentials']}` c WHERE c.user_id=u.ID AND c.rp_id=%s)", $rp_id);
        $sql = is_multisite()
            ? $this->db->prepare("SELECT DISTINCT u.ID FROM `{$this->db->users}` u INNER JOIN `{$this->db->usermeta}` m ON m.user_id=u.ID AND m.meta_key=%s WHERE $missing ORDER BY u.ID", $this->db->get_blog_prefix($site_id) . 'capabilities')
            : "SELECT u.ID FROM `{$this->db->users}` u WHERE $missing ORDER BY u.ID";
        return array_map('intval', array_column($this->rows($sql), 'ID'));
    }
    public function password_disabled(int $user_id): bool {
        $rows = $this->rows($this->db->prepare("SELECT meta_value FROM `{$this->db->usermeta}` WHERE user_id=%d AND meta_key=%s", $user_id, 'azwp_passkeys_password_disabled'));
        foreach ($rows as $row) { if ((int) $row['meta_value'] === 1) { return true; } }
        return false;
    }
    public function save_settings(string $scope, int $scope_id, array $values): array {
        if (!in_array($scope, ['site', 'network'], true) || $scope_id <= 0) { return self::error('invalid_request'); }
        return $this->transaction(function () use ($scope, $scope_id, $values): array {
            $this->invalidate[] = [$scope, $scope_id];
            if ($scope === 'site') {
                $table = $this->options_table($scope_id);
                $engine = $this->row($this->db->prepare('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s', $table));
                if (!$engine || strcasecmp($engine['ENGINE'], 'InnoDB') !== 0) { return self::error(); }
                $before = $this->read_site_settings($scope_id);
                $merged = array_replace($before, $values);
                $serialized = maybe_serialize($merged);
                $this->query($this->db->prepare("INSERT INTO `$table` (option_name,option_value,autoload) VALUES (%s,%s,'off') ON DUPLICATE KEY UPDATE option_value=VALUES(option_value),autoload='off'", 'azwp_passkeys_settings', $serialized));
                $after = $this->read_site_settings($scope_id);
            } else {
                $before = $this->read_network_settings($scope_id);
                $merged = array_replace($before, $values);
                $this->query($this->db->prepare("DELETE FROM `{$this->db->sitemeta}` WHERE site_id=%d AND meta_key=%s", $scope_id, 'azwp_passkeys_network_settings'));
                if ($this->db->insert($this->db->sitemeta, ['site_id' => $scope_id, 'meta_key' => 'azwp_passkeys_network_settings', 'meta_value' => maybe_serialize($merged)]) === false) { return self::error(); }
                $after = $this->read_network_settings($scope_id);
            }
            return $after === $merged ? self::ok(['settings' => $after, 'previous' => $before]) : self::error();
        });
    }
    /** A guard runs under the owner lock, only on the change from enabled to disabled, and may veto it. */
    public function save_password_policy(int $user_id, bool $disabled, ?callable $guard = null): array {
        return $this->with_owner_lock($user_id, function () use ($user_id, $disabled, $guard): array {
            if ($disabled && $guard !== null && !$this->password_disabled($user_id) && !$guard($this)) { return self::error('access_required'); }
            $this->invalidate[] = ['user', $user_id];
            $this->query($this->db->prepare("DELETE FROM `{$this->db->usermeta}` WHERE user_id=%d AND meta_key=%s", $user_id, 'azwp_passkeys_password_disabled'));
            if ($this->db->insert($this->db->usermeta, ['user_id' => $user_id, 'meta_key' => 'azwp_passkeys_password_disabled', 'meta_value' => $disabled ? '1' : '0']) === false) { return self::error(); }
            return $this->password_disabled($user_id) === $disabled ? self::ok(['disabled' => $disabled]) : self::error();
        });
    }
    private function invalidate_cache(string $scope, int $id): void {
        if ($scope === 'user') { wp_cache_delete($id, 'user_meta'); return; }
        if ($scope === 'network') {
            wp_cache_delete($id . ':azwp_passkeys_network_settings', 'site-options');
            wp_cache_delete($id . ':notoptions', 'site-options');
            return;
        }
        $switched = $id !== get_current_blog_id();
        if ($switched) { switch_to_blog($id); }
        wp_cache_delete('azwp_passkeys_settings', 'options');
        wp_cache_delete('alloptions', 'options');
        wp_cache_delete('notoptions', 'options');
        if ($switched) { restore_current_blog(); }
    }
    /** Inside an owner transaction the write is skipped, because a rollback would take it with the operation. */
    public function insert_event(array $row): bool {
        if ($this->in_transaction) { return false; }
        $formats = ['site_id'=>'%d','occurred_at'=>'%d','event'=>'%s','ok'=>'%d','code'=>'%s','correlation_id'=>'%s','actor_id'=>'%d','actor_login'=>'%s','target_id'=>'%d','target_login'=>'%s','passkey_id'=>'%d','passkey_name'=>'%s','passkey_aaguid'=>'%s','ip'=>'%s','data'=>'%s'];
        $row = array_intersect_key($row, $formats);
        return $this->db->insert($this->tables['events'], $row, array_map(static fn(string $key): string => $formats[$key], array_keys($row))) !== false;
    }
    /** One page of the site's events, newest first. A page past the end returns the last page. */
    public function read_events(int $site_id, ?array $events, ?bool $ok, int $paged, int $per_page): array {
        try {
            $table = $this->tables['events'];
            $where = $this->db->prepare('site_id=%d', $site_id);
            $total = (int) $this->row("SELECT COUNT(*) AS total FROM `$table` WHERE $where")['total'];
            if ($events !== null) { $where .= $this->db->prepare(' AND event IN (' . implode(',', array_fill(0, count($events), '%s')) . ')', ...$events); }
            if ($ok !== null) { $where .= $this->db->prepare(' AND ok=%d', (int) $ok); }
            $matched = (int) $this->row("SELECT COUNT(*) AS total FROM `$table` WHERE $where")['total'];
            $pages = max(1, (int) ceil($matched / $per_page));
            $paged = min($paged, $pages);
            $rows = $this->rows("SELECT * FROM `$table` WHERE $where ORDER BY id DESC" . $this->db->prepare(' LIMIT %d OFFSET %d', $per_page, ($paged - 1) * $per_page));
            foreach ($rows as &$row) {
                foreach (['id', 'site_id', 'actor_id', 'target_id', 'passkey_id'] as $key) {
                    if ($row[$key] === null) { continue; }
                    $value = (string) $row[$key];
                    if (strlen($value) > strlen((string) PHP_INT_MAX) || (strlen($value) === strlen((string) PHP_INT_MAX) && strcmp($value, (string) PHP_INT_MAX) > 0)) { throw new \RuntimeException('ID out of range'); }
                    $row[$key] = (int) $value;
                }
                $row['occurred_at'] = (int) $row['occurred_at'];
                $row['ok'] = (bool) $row['ok'];
                $data = $row['data'] === null ? [] : json_decode($row['data'], true, 32, JSON_THROW_ON_ERROR);
                $row['data'] = is_array($data) ? $data : [];
            }
            unset($row);
            return self::ok(['total' => $total, 'matched' => $matched, 'paged' => $paged, 'total_pages' => $pages, 'rows' => $rows]);
        } catch (\Throwable $e) { return self::error(); }
    }
    public function clear_events(int $site_id): array {
        try {
            $deleted = $this->query($this->db->prepare("DELETE FROM `{$this->tables['events']}` WHERE site_id=%d", $site_id));
            $rows = $this->row($this->db->prepare("SELECT COUNT(*) AS total FROM `{$this->tables['events']}` WHERE site_id=%d", $site_id));
            return (int) $rows['total'] === 0 ? self::ok(['count' => 0, 'deleted' => $deleted]) : self::error('outcome_unknown');
        } catch (\Throwable $e) { return self::error(); }
    }
    /** Erases the user's logins on every site, and the names of passkeys the user owns. A row without a passkey keeps its NULL name. */
    public function erase_event_logins(int $user_id): array {
        try {
            $table = $this->tables['events'];
            // MySQL counts only rows whose values changed, so an already erased row adds nothing.
            $changed = $this->query($this->db->prepare("UPDATE `$table` SET actor_login='erased', ip=IF(ip IS NULL, NULL, 'erased') WHERE actor_id=%d", $user_id));
            // With no actor, the request came from the target, such as a sign-in, so the address is the target's.
            $changed += $this->query($this->db->prepare("UPDATE `$table` SET target_login='erased', passkey_name=IF(passkey_name IS NULL, NULL, 'erased'), ip=IF(ip IS NULL OR actor_id IS NOT NULL, ip, 'erased') WHERE target_id=%d", $user_id));
            return self::ok(['changed' => $changed]);
        } catch (\Throwable $e) { return self::error(); }
    }
    /**
     * Replaces personal data keys with "erased" in one page of the user's rows.
     * $personal maps each event to its personal keys and whose data each is, "target" or "actor".
     */
    public function erase_event_data(int $user_id, array $personal, int $page, int $per_page): array {
        if ($personal === []) { return self::ok(['rows' => 0, 'changed' => 0]); }
        try {
            $table = $this->tables['events'];
            $clauses = [];
            foreach ($personal as $event => $keys) {
                foreach (array_unique(array_values($keys)) as $owner) {
                    $clauses[] = $this->db->prepare('(event=%s AND ' . ($owner === 'actor' ? 'actor_id' : 'target_id') . '=%d)', $event, $user_id);
                }
            }
            $rows = $this->rows("SELECT id,event,actor_id,target_id,data FROM `$table` WHERE " . implode(' OR ', $clauses) . ' ORDER BY id' . $this->db->prepare(' LIMIT %d OFFSET %d', $per_page, ($page - 1) * $per_page));
            $changed = 0;
            foreach ($rows as $row) {
                $data = $row['data'] === null ? [] : json_decode($row['data'], true, 32, JSON_THROW_ON_ERROR);
                if (!is_array($data)) { continue; }
                $erased = $data;
                foreach ($personal[$row['event']] as $key => $owner) {
                    if (array_key_exists($key, $erased) && (int) $row[$owner . '_id'] === $user_id) { $erased[$key] = 'erased'; }
                }
                if ($erased === $data) { continue; }
                $this->query($this->db->prepare("UPDATE `$table` SET data=%s WHERE id=%d", json_encode($erased, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), $row['id']));
                ++$changed;
            }
            return self::ok(['rows' => count($rows), 'changed' => $changed]);
        } catch (\Throwable $e) { return self::error(); }
    }
    /** Rows on any site where the user acted or was acted on, or null when the count fails. */
    public function count_user_events(int $user_id): ?int {
        try { return (int) $this->row($this->db->prepare("SELECT COUNT(*) AS total FROM `{$this->tables['events']}` WHERE actor_id=%d OR target_id=%d", $user_id, $user_id))['total']; }
        catch (\Throwable $e) { return null; }
    }
    /** Runs $operation under a non-blocking named lock. Returns null when another request holds it. */
    public function with_upgrade_lock(callable $operation): mixed {
        $lock = $this->lock_name . ':upgrade';
        if ((string) $this->db->get_var($this->db->prepare('SELECT GET_LOCK(%s,0)', $lock)) !== '1') { return null; }
        try { return $operation(); }
        finally { $this->db->get_var($this->db->prepare('SELECT RELEASE_LOCK(%s)', $lock)); }
    }
    /** 0.3.0 and earlier logged to this table. Its history is not copied. */
    public function drop_legacy_logs(): bool {
        return $this->db->query("DROP TABLE IF EXISTS `{$this->db->base_prefix}azwp_passkeys_logs`") !== false;
    }
    public function cleanup_user(int $user_id, ?int $site_id = null, bool $require_missing_account = false): array {
        return $this->with_owner_lock($user_id, function () use ($user_id, $site_id, $require_missing_account): array {
            if ($require_missing_account && $this->account_exists($user_id)) { return self::ok(['unchanged' => true]); }
            $where = $this->db->prepare('user_id=%d', $user_id);
            if ($site_id !== null) { $where .= $this->db->prepare(' AND site_id=%d', $site_id); }
            $counts = [];
            foreach ($this->rows("SELECT site_id, COUNT(*) AS total FROM `{$this->tables['credentials']}` WHERE $where GROUP BY site_id") as $row) { $counts[(int) $row['site_id']] = (int) $row['total']; }
            $this->query("DELETE FROM `{$this->tables['credentials']}` WHERE $where");
            if ($site_id === null) {
                $this->query($this->db->prepare("DELETE FROM `{$this->tables['identities']}` WHERE user_id=%d", $user_id));
                $this->query($this->db->prepare("DELETE FROM `{$this->tables['attempts']}` WHERE actor_id=%d OR target_id=%d", $user_id, $user_id));
                $this->query($this->db->prepare("DELETE FROM `{$this->db->usermeta}` WHERE user_id=%d AND meta_key IN (%s,%s)", $user_id, 'azwp_passkeys_password_disabled', self::SETUP_LINK_KEY));
                $this->invalidate[] = ['user', $user_id];
            } elseif (!$this->account_exists($user_id)) {
                // Missing users must not retain a provisional identity from cleanup.
                $this->query($this->db->prepare("DELETE FROM `{$this->tables['identities']}` WHERE user_id=%d", $user_id));
            }
            return self::ok(['counts' => $counts]);
        }, true);
    }
    /** Counts one use of a one-minute transient counter; false at the limit or when the counter cannot be locked. */
    public function consume_rate(string $key, int $limit): bool {
        $lock = $this->lock_name . ':' . substr(hash('sha256', $key), 0, 16);
        $acquired = false;
        try {
            $acquired = (string) $this->db->get_var($this->db->prepare('SELECT GET_LOCK(%s,%d)', $lock, self::LOCK_WAIT_SECONDS)) === '1';
            if (!$acquired) { return false; }
            $count = (int) get_transient($key);
            return $count < $limit && set_transient($key, $count + 1, MINUTE_IN_SECONDS);
        } finally {
            if ($acquired) { $this->db->get_var($this->db->prepare('SELECT RELEASE_LOCK(%s)', $lock)); }
        }
    }
    /** Rate-limit counters are transients; remove any left in this site's options table. */
    public function delete_rate_limits(int $site_id): array {
        try {
            $this->query($this->db->prepare("DELETE FROM `{$this->options_table($site_id)}` WHERE option_name LIKE %s OR option_name LIKE %s", $this->db->esc_like('_transient_azwp_passkeys_rate_') . '%', $this->db->esc_like('_transient_timeout_azwp_passkeys_rate_') . '%'));
            return self::ok();
        } catch (\Throwable $e) { return self::error(); }
    }
    public function uninstall(): array {
        if ($this->in_transaction) { return self::error(); }
        try {
            $users = $this->rows($this->db->prepare("SELECT DISTINCT user_id FROM `{$this->db->usermeta}` WHERE meta_key IN (%s,%s)", 'azwp_passkeys_password_disabled', self::SETUP_LINK_KEY));
            foreach ($this->tables as $table) { $this->query("DROP TABLE IF EXISTS `$table`"); }
            if (!$this->drop_legacy_logs()) { return self::error(); }
            $this->query($this->db->prepare("DELETE FROM `{$this->db->usermeta}` WHERE meta_key IN (%s,%s)", 'azwp_passkeys_password_disabled', self::SETUP_LINK_KEY));
            foreach ($users as $user) { wp_cache_delete((int) $user['user_id'], 'user_meta'); }
            // Lifecycle deletes per-site/network options using WordPress cache-aware APIs.
            return self::ok();
        } catch (\Throwable $e) { return self::error(); }
    }
}
