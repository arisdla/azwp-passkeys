<?php
/** Database persistence and transaction ownership. */
namespace AZWP\Passkeys;

final class Storage {
    public const LOCK_WAIT_SECONDS = 5;
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
        foreach (['identities', 'credentials', 'attempts', 'logs'] as $name) {
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
    private function transactional_tables(array $extra = []): void {
        $names = array_merge(array_values($this->tables), [$this->db->users, $this->db->usermeta, $this->db->options], $extra);
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
            "CREATE TABLE IF NOT EXISTS `{$t['logs']}` (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, site_id BIGINT UNSIGNED NOT NULL, occurred_at BIGINT UNSIGNED NOT NULL, event VARCHAR(48) NOT NULL, actor_id BIGINT UNSIGNED NULL, target_id BIGINT UNSIGNED NULL, result VARCHAR(32) NOT NULL, correlation_id CHAR(32) CHARACTER SET ascii NOT NULL, detail TEXT NOT NULL, PRIMARY KEY (id), KEY site_log (site_id,id)) ENGINE=InnoDB $charset",
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
            $this->transactional_tables($this->network_options_tables());
            return self::ok();
        } catch (\Throwable $e) { return self::error($e->getCode() === self::ENGINE_FAILURE ? 'storage_engine' : 'storage_failed'); }
    }

    private function verify_schema(): void {
        $indexes = [
            'identities' => ['PRIMARY' => ['user_id'], 'handle' => ['handle']],
            'credentials' => ['PRIMARY' => ['id'], 'credential_hash' => ['credential_hash'], 'owner_site_created' => ['user_id','site_id','created_at','id'], 'owner_rp' => ['user_id','rp_id']],
            'attempts' => ['PRIMARY' => ['id'], 'expires_at' => ['expires_at']],
            'logs' => ['PRIMARY' => ['id'], 'site_log' => ['site_id','id']],
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
    public function append_log(int $site_id, array $entry): array {
        if ($this->in_transaction) { return self::error(); }
        try {
            if (empty($this->read_site_settings($site_id)['logging'])) { return self::ok(['logged' => false]); }
            $events = ['log_initialized','settings_saved','registration','setup_link_sent','passkey_setup','authentication','credential_test','credential_renamed','credential_removed','registration_sign_in','storage_error','configuration_error','account_cleanup','membership_cleanup'];
            if (!in_array($entry['event'] ?? null, $events, true)) { return self::error('invalid_request'); }
            $detail = [];
            // Only known non-secret configuration and status fields can reach logs.
            $allowed = ['plugin_version','php_version','wordpress_version','library_version','rp_name','rp_id','passkey_only','remember_login','reset_restriction','logging','setting','previous','value','code','count','initialization'];
            foreach (($entry['detail'] ?? []) as $key => $value) {
                if (!in_array($key, $allowed, true)) { continue; }
                if (is_bool($value) || is_int($value) || $value === null) { $detail[$key] = $value; }
                elseif (is_array($value) && array_is_list($value) && ($entry['detail']['setting'] ?? '') === 'related_origins' && in_array($key, ['previous', 'value'], true)) {
                    $detail[$key] = [];
                    foreach ($value as $origin) {
                        if (!is_string($origin)) { continue; }
                        $parts = parse_url($origin);
                        $detail[$key][] = is_array($parts) && isset($parts['scheme'], $parts['host'])
                            ? strtolower($parts['scheme']) . '://' . strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : '')
                            : '[invalid origin]';
                    }
                } elseif (is_string($value)) {
                    $text = strip_tags($value);
                    // Extension initialization strings cannot bypass central redaction.
                    $text = preg_replace('/(?:bearer\s+\S+|(?:password|cookie|token|challenge|secret|authorization|signature)\s*[:=]\s*\S+|-----BEGIN[\s\S]*?-----END[^-]*-----)/i', '[redacted]', $text);
                    $detail[$key] = $text;
                }
            }
            $correlation = $entry['correlation_id'] ?? bin2hex(random_bytes(16));
            if (!is_string($correlation) || !preg_match('/^[a-f0-9]{32}$/D', $correlation)) { return self::error('invalid_request'); }
            $result = $entry['result'] ?? 'ok';
            if (!is_string($result) || !preg_match('/^[a-z_]{1,32}$/D', $result)) { return self::error('invalid_request'); }
            $data = ['site_id' => $site_id, 'occurred_at' => time(), 'event' => $entry['event'], 'actor_id' => $entry['actor_id'] ?? null, 'target_id' => $entry['target_id'] ?? null, 'result' => $result, 'correlation_id' => $correlation, 'detail' => json_encode($detail, JSON_THROW_ON_ERROR)];
            return $this->db->insert($this->tables['logs'], $data) === false ? self::error() : self::ok(['logged' => true]);
        } catch (\Throwable $e) { return self::error(); }
    }
    public function read_logs(int $site_id): array {
        try {
            $rows = $this->rows($this->db->prepare("SELECT occurred_at,event,actor_id,target_id,result,correlation_id,detail FROM `{$this->tables['logs']}` WHERE site_id=%d ORDER BY id", $site_id));
            foreach ($rows as &$row) {
                $row['detail'] = json_decode($row['detail'], true, 512, JSON_THROW_ON_ERROR);
                foreach (['actor_id','target_id'] as $field) {
                    if ($row[$field] === null) { continue; }
                    $value = (string) $row[$field];
                    if (strlen($value) > strlen((string) PHP_INT_MAX) || (strlen($value) === strlen((string) PHP_INT_MAX) && strcmp($value, (string) PHP_INT_MAX) > 0)) { throw new \RuntimeException('ID out of range'); }
                    $row[$field] = (int) $value;
                }
            }
            unset($row);
            return self::ok(['entries' => $rows, 'count' => count($rows)]);
        } catch (\Throwable $e) { return self::error(); }
    }
    public function clear_logs(int $site_id): array {
        try {
            $this->query($this->db->prepare("DELETE FROM `{$this->tables['logs']}` WHERE site_id=%d", $site_id));
            $rows = $this->row($this->db->prepare("SELECT COUNT(*) AS total FROM `{$this->tables['logs']}` WHERE site_id=%d", $site_id));
            return (int) $rows['total'] === 0 ? self::ok(['count' => 0]) : self::error('outcome_unknown');
        } catch (\Throwable $e) { return self::error(); }
    }
    public function cleanup_user(int $user_id, ?int $site_id = null, bool $require_missing_account = false): array {
        return $this->with_owner_lock($user_id, function () use ($user_id, $site_id, $require_missing_account): array {
            if ($require_missing_account && $this->account_exists($user_id)) { return self::ok(['unchanged' => true]); }
            $sql = $this->db->prepare("DELETE FROM `{$this->tables['credentials']}` WHERE user_id=%d", $user_id);
            if ($site_id !== null) { $sql .= $this->db->prepare(' AND site_id=%d', $site_id); }
            $this->query($sql);
            if ($site_id === null) {
                $this->query($this->db->prepare("DELETE FROM `{$this->tables['identities']}` WHERE user_id=%d", $user_id));
                $this->query($this->db->prepare("DELETE FROM `{$this->tables['attempts']}` WHERE actor_id=%d OR target_id=%d", $user_id, $user_id));
                $this->query($this->db->prepare("DELETE FROM `{$this->db->usermeta}` WHERE user_id=%d AND meta_key IN (%s,%s)", $user_id, 'azwp_passkeys_password_disabled', self::SETUP_LINK_KEY));
                $this->invalidate[] = ['user', $user_id];
            } elseif (!$this->account_exists($user_id)) {
                // Missing users must not retain a provisional identity from cleanup.
                $this->query($this->db->prepare("DELETE FROM `{$this->tables['identities']}` WHERE user_id=%d", $user_id));
            }
            return self::ok();
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
            $this->query($this->db->prepare("DELETE FROM `{$this->db->usermeta}` WHERE meta_key IN (%s,%s)", 'azwp_passkeys_password_disabled', self::SETUP_LINK_KEY));
            foreach ($users as $user) { wp_cache_delete((int) $user['user_id'], 'user_meta'); }
            // Lifecycle deletes per-site/network options using WordPress cache-aware APIs.
            return self::ok();
        } catch (\Throwable $e) { return self::error(); }
    }
}
