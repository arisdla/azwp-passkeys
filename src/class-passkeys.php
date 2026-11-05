<?php
declare(strict_types=1);
namespace AZWP\Passkeys;

final class Passkeys
{
    public const ATTEMPT_TTL_SECONDS = 90;
    public const ANONYMOUS_ATTEMPTS_PER_MINUTE = 30;
    public const SETUP_LINK_TTL_SECONDS = 3600;
    public function __construct(private Settings $settings, private Storage $storage, private WebAuthn $webauthn) {}
    private function ok(array $data = []): array { return ['ok'=>true,'code'=>'ok','data'=>$data,'message'=>'']; }
    private function error(string $code): array { return ['ok'=>false,'code'=>$code,'data'=>[],'message'=>'']; }
    public static function numeric_id(mixed $value): ?int
    {
        if (is_int($value)) { return $value > 0 ? $value : null; }
        if (!is_string($value) || !preg_match('/^[1-9][0-9]*$/D', $value)) { return null; }
        $max = (string) PHP_INT_MAX;
        return strlen($value) < strlen($max) || (strlen($value) === strlen($max) && strcmp($value, $max) <= 0) ? (int) $value : null;
    }
    private function authorized(array $context, int $target_id): bool
    {
        return $context['actor_id'] > 0 && current_user_can('read') && ($context['actor_id'] === $target_id || current_user_can('edit_user', $target_id)) && (bool) get_userdata($target_id);
    }
    /** Resolve WordPress URL/capability-filter inputs before entering a transaction. */
    private function configuration_inputs(int $site_id): array
    {
        $origins = [];
        foreach ([get_site_url($site_id), get_home_url($site_id)] as $url) {
            try { $origins[] = WebAuthn::canonical_origin($url, true); }
            catch (\InvalidArgumentException) { continue; }
        }
        $definitions = $this->settings->definitions();
        $network_id = 0;
        if (is_multisite()) {
            $site = get_site($site_id);
            $network_id = $site ? (int) $site->network_id : (int) get_current_network_id();
        }
        return ['site_id'=>$site_id, 'network_id'=>$network_id,
            'origins'=>array_values(array_unique($origins)),
            'defaults'=>array_map(static fn(array $definition) => $definition['default'], $definitions),
            'network_keys'=>array_filter($definitions, static fn(array $definition): bool => $definition['scope']==='network')];
    }
    private function configuration_values(array $settings, array $inputs): array
    {
        try {
            $rp_id = WebAuthn::canonical_rp_id($settings['rp_id']);
            $origins = array_values(array_filter($inputs['origins'], static fn(string $origin): bool => WebAuthn::rp_matches_origin($rp_id, $origin)));
            if ($origins === [] || $settings['rp_name'] === '' || !extension_loaded('openssl')) { return $this->error('not_configured'); }
            return $this->ok(['settings'=>$settings,'rp_id'=>$rp_id,'rp_name'=>$settings['rp_name'],'origins'=>$origins]);
        } catch (\Throwable) { return $this->error('not_configured'); }
    }
    public function configuration(int $site_id): array
    {
        return $this->configuration_values($this->settings->get_effective($site_id), $this->configuration_inputs($site_id));
    }
    /** Only direct storage reads and pure value checks occur under the coordinator. */
    private function locked_settings(Storage $storage, array $inputs): array
    {
        $settings = array_replace($inputs['defaults'], $storage->site_defaults($inputs['site_id']),
            array_intersect_key($storage->read_site_settings($inputs['site_id']), $inputs['defaults']));
        if ($inputs['network_id']) {
            $network = array_replace(array_intersect_key($inputs['defaults'], $inputs['network_keys']),
                array_intersect_key($storage->read_network_settings($inputs['network_id']), $inputs['network_keys']));
            $settings = array_replace($settings, $network);
        }
        return $settings;
    }
    private function locked_configuration(Storage $storage, array $inputs): array
    {
        return $this->configuration_values($this->locked_settings($storage, $inputs), $inputs);
    }
    private function same_session(array $context): bool
    {
        $actor = (int) get_current_user_id();
        return $actor === (int) $context['actor_id']
            && ($actor === 0 || hash('sha256', wp_get_session_token(), true) === $context['session_hash']);
    }
    private function existing_accounts(Storage $storage, array $context, int $target): bool
    {
        return $storage->account_exists($target)
            && (!$context['actor_id'] || $storage->account_exists((int) $context['actor_id']));
    }
    private function target(array $context, array $input): ?int
    {
        return array_key_exists('target_id', $input) ? self::numeric_id($input['target_id']) : ($context['actor_id'] ?: null);
    }
    private function eligible(array $credential, array $configuration): bool
    {
        return $credential['rp_id'] === $configuration['rp_id'] && (is_multisite() || (int)$credential['site_id'] === (int)get_current_blog_id());
    }
    private function descriptors(array $credentials): array
    {
        return array_map(static fn(array $row): array => ['credential_id'=>$row['credential_id'],'transports'=>$row['transports']], $credentials);
    }
    private function store_issued(array $issued): array
    {
        foreach (['user_handle'] as $key) { if (isset($issued[$key])) { $issued[$key] = WebAuthn::encode($issued[$key]); } }
        foreach (['allow_credentials','exclude_credentials'] as $key) {
            if (isset($issued[$key])) {
                foreach ($issued[$key] as &$descriptor) { $descriptor['credential_id'] = WebAuthn::encode($descriptor['credential_id']); } unset($descriptor);
            }
        }
        return $issued;
    }
    private function decode_attempt(array $attempt): array
    {
        $issued = $attempt['issued'];
        foreach (['user_handle'] as $key) { if (isset($issued[$key])) { $issued[$key] = WebAuthn::decode($issued[$key]); } }
        foreach (['allow_credentials','exclude_credentials'] as $key) {
            if (isset($issued[$key])) {
                foreach ($issued[$key] as &$descriptor) { $descriptor['credential_id'] = WebAuthn::decode($descriptor['credential_id']); } unset($descriptor);
            }
        }
        $attempt['issued'] = $issued;
        return $attempt;
    }
    private function issue(array $context, ?int $target_id, array $issued, bool $registration): array
    {
        $challenge = random_bytes(32);
        $issued['challenge'] = $challenge;
        $options = $registration ? $this->webauthn->creation_options($issued) : $this->webauthn->request_options($issued);
        if (!$options['ok']) { return $options; }
        unset($issued['challenge']);
        $id = random_bytes(32);
        $result = $this->storage->create_attempt([
            'id'=>$id,'site_id'=>$context['site_id'],'purpose'=>$context['purpose'],'actor_id'=>$context['actor_id'] ?: null,
            'target_id'=>$target_id,'browser_hash'=>$context['browser_hash'],'session_hash'=>$context['session_hash'],
            'challenge'=>$challenge,'issued'=>$this->store_issued($issued),'status'=>'pending','created_at'=>time(),'expires_at'=>time()+self::ATTEMPT_TTL_SECONDS,
        ]);
        if (!$result['ok']) { return $result; }
        $data = ['attempt_id'=>WebAuthn::encode($id),'publicKey'=>$options['data']];
        if ($context['purpose'] === 'login') { $data += ['completion_url'=>admin_url('admin-ajax.php'),'completion_mode'=>'ajax']; }
        return $this->ok($data);
    }
    public function registration_options(array $context, array $input): array
    {
        $target = $this->target($context, $input);
        if (!$target || !$this->authorized($context, $target)) { return $this->error('forbidden'); }
        $context['purpose'] = 'register';
        return $this->issue_registration($context, $target);
    }
    private function issue_registration(array $context, int $target): array
    {
        $config = $this->configuration($context['site_id']);
        if (!$config['ok']) { return $config; }
        $config = $config['data'];
        $identity = $this->storage->with_owner_lock($target, fn(Storage $storage): array => $storage->initialize_identity($target));
        if (!$identity['ok']) { return $identity; }
        $credentials = $this->storage->get_credentials($target);
        if (!$credentials['ok']) { return $credentials; }
        $user = get_userdata($target);
        if (!$user) { return $this->error('forbidden'); }
        return $this->issue($context, $target, [
            'rp_id'=>$config['rp_id'],'rp_name'=>$config['rp_name'],'origins'=>$config['origins'],'user_verification'=>'required',
            'user_handle'=>$identity['data']['identity']['handle'],'user_name'=>$user->user_login,'user_display_name'=>$user->display_name,
            'name'=>$this->default_name($credentials['data']['credentials']),
            'exclude_credentials'=>$this->descriptors($credentials['data']['credentials']),
        ], true);
    }
    /** The lowest "passkey_N" the account is not already using; the owner can rename it later. */
    private function default_name(array $credentials): string
    {
        $taken = array_flip(array_column($credentials, 'name'));
        $number = 1;
        while (isset($taken['passkey_'.$number])) { $number++; }
        return 'passkey_'.$number;
    }
    private function bound_attempt(array $context, string $id): array
    {
        $result = $this->storage->read_attempt($id);
        if (!$result['ok']) { return $result; }
        $attempt = $result['data']['attempt'];
        if (!$attempt || (int)$attempt['expires_at'] <= time() || $attempt['status'] !== 'pending' || (int)$attempt['site_id'] !== $context['site_id'] || $attempt['purpose'] !== $context['purpose'] || (int)($attempt['actor_id'] ?? 0) !== $context['actor_id'] || !is_string($context['browser_hash']) || !hash_equals($attempt['browser_hash'], $context['browser_hash']) || ($attempt['session_hash'] ?? null) !== $context['session_hash']) { return $this->error('attempt_unavailable'); }
        if ($context['actor_id'] && !get_userdata($context['actor_id'])) { return $this->error('forbidden'); }
        try { return $this->ok(['attempt'=>$this->decode_attempt($attempt)]); }
        catch (\Throwable) { return $this->error('attempt_unavailable'); }
    }
    public function registration_target(array $context, string $attempt_id): array
    {
        $context['purpose'] = 'register';
        $result = $this->bound_attempt($context, $attempt_id);
        if (!$result['ok']) { return $result; }
        $target = (int)$result['data']['attempt']['target_id'];
        return $this->authorized($context, $target) ? $this->ok(['target_id'=>$target]) : $this->error('forbidden');
    }
    private function current_configuration(array $attempt): array
    {
        $config = $this->configuration((int)$attempt['site_id']);
        if (!$config['ok']) { return $config; }
        return $this->check_issued_configuration($config, $attempt['issued']);
    }
    private function check_issued_configuration(array $config, array $issued): array
    {
        if (!$config['ok']) { return $config; }
        if ($config['data']['rp_id'] !== $issued['rp_id'] || $config['data']['origins'] !== $issued['origins']) { return $this->error('state_changed'); }
        if (!empty($issued['remember']) && !$config['data']['settings']['remember_login']) { return $this->error('invalid_request'); }
        return $config;
    }
    private function claim(array $context, string $id): array
    {
        return $this->storage->claim_attempt($id, ['site_id'=>$context['site_id'],'purpose'=>$context['purpose'],'actor_id'=>$context['actor_id'],'browser_hash'=>$context['browser_hash'],'session_hash'=>$context['session_hash']]);
    }
    public function complete_registration(array $context, array $input): array
    {
        $context['purpose'] = 'register';
        if (!is_string($input['attempt_id'] ?? null) || !is_array($input['credential'] ?? null)) { return $this->error('invalid_request'); }
        $bound = $this->bound_attempt($context, $input['attempt_id']);
        if (!$bound['ok']) { return $bound; }
        $attempt = $bound['data']['attempt']; $target = (int)$attempt['target_id'];
        if (!$this->authorized($context, $target)) { return $this->error('forbidden'); }
        $claim = $this->claim($context, $input['attempt_id']);
        if (!$claim['ok']) { return $claim; }
        try {
            $config = $this->current_configuration($attempt);
            if (!$config['ok']) { return $config; }
            $verified = $this->webauthn->verify_registration($attempt, $input['credential']);
            if (!$verified['ok']) { return $verified; }
            $record = $verified['data'] + ['user_id'=>$target,'site_id'=>$context['site_id'],'name'=>$attempt['issued']['name'],'created_at'=>time(),'created_local'=>current_time('mysql'),'last_used_local'=>null];
            $inputs = $this->configuration_inputs($context['site_id']);
            if (!$this->authorized($context, $target) || !$this->same_session($context)) { return $this->error('forbidden'); }
            $result = $this->storage->with_owner_lock($target, function(Storage $storage) use ($attempt,$record,$inputs,$context,$target,&$config): array {
                if (!$this->existing_accounts($storage, $context, $target)) { return $this->error('forbidden'); }
                $config = $this->check_issued_configuration($this->locked_configuration($storage, $inputs), $attempt['issued']);
                if (!$config['ok']) { return $config; }
                return $storage->insert_credential($record);
            });
            if (!$result['ok']) { return $result; }
            $this->notify_added($target, (int) $context['actor_id'], $attempt['issued']['name']);
            return $this->ok(['credential'=>$this->summary($result['data']['credential'], $config['data'], true)]);
        } finally { $this->storage->delete_attempt($input['attempt_id']); }
    }
    /** Emails the owner a one-time link that can only add a passkey. The admin never sees the link, so the admin cannot add their own device to the account. */
    public function send_setup_link(array $context, int $target): array
    {
        if (!$this->authorized($context, $target) || $target === (int) $context['actor_id'] || !$this->same_session($context)) { return $this->error('forbidden'); }
        if (!$this->configuration($context['site_id'])['ok']) { return $this->error('not_configured'); }
        $owner = get_userdata($target);
        if (!$owner || !is_email($owner->user_email)) { return $this->error('invalid_request'); }
        $token = random_bytes(32);
        $url = add_query_arg(['action'=>'azwp_passkeys_setup', 'user'=>$target, 'token'=>WebAuthn::encode($token)], wp_login_url());
        $switched = switch_to_user_locale($target);
        try {
            $site = wp_specialchars_decode((string) get_option('blogname'), ENT_QUOTES);
            $actor = get_userdata((int) $context['actor_id']);
            $lines = [
                sprintf(__('%1$s sent you a link to add a passkey to your account on %2$s.', 'azwp-passkeys'), $actor ? $actor->display_name : $site, $site),
                __('Open it on the device that will store the passkey. It works once and expires in one hour.', 'azwp-passkeys'),
                $url,
                __('If you did not expect this, ignore this email. Nothing changes until the link is used.', 'azwp-passkeys'),
            ];
            $sent = wp_mail($owner->user_email, sprintf(__('[%s] Add a passkey to your account', 'azwp-passkeys'), $site), implode("\n\n", $lines));
        } finally {
            if ($switched) { restore_previous_locale(); }
        }
        // Only a delivered link replaces the pending one, so a failed send leaves the owner's earlier link working.
        if (!$sent) { return $this->error('mail_failed'); }
        $saved = $this->storage->save_setup_link($target, ['hash'=>hash('sha256', $token), 'expires_at'=>time()+self::SETUP_LINK_TTL_SECONDS, 'issued_by'=>(int) $context['actor_id'], 'site_id'=>$context['site_id']]);
        return $saved['ok'] ? $this->ok(['sent'=>true]) : $saved;
    }
    private static function setup_hash(mixed $token): ?string
    {
        if (!is_string($token)) { return null; }
        try { $bytes = WebAuthn::decode($token); } catch (\Throwable) { return null; }
        return strlen($bytes) === 32 ? hash('sha256', $bytes) : null;
    }
    /** Checks a setup link without using it up, because mail scanners open links before people do. */
    public function setup_link_valid(int $target, mixed $token, int $site_id): bool
    {
        $hash = self::setup_hash($token);
        try { $link = $hash === null ? null : $this->storage->get_setup_link($target); } catch (\Throwable) { return false; }
        return $link !== null && hash_equals($link['hash'], $hash) && $link['site_id'] === $site_id && $link['expires_at'] > time() && (bool) get_userdata($target);
    }
    public function setup_options(array $context, array $input): array
    {
        if (!$context['actor_id'] && !$this->anonymous_allowed()) { return $this->error('rate_limited'); }
        $target = self::numeric_id($input['user_id'] ?? null);
        if (!$target || ($context['actor_id'] && (int) $context['actor_id'] !== $target)) { return $this->error('forbidden'); }
        if (!$this->setup_link_valid($target, $input['token'] ?? null, $context['site_id'])) { return $this->error('attempt_unavailable'); }
        $context['purpose'] = 'setup';
        return $this->issue_registration($context, $target);
    }
    /** Consuming the link and saving the passkey share one owner transaction, so a link is used up only when a passkey is saved. */
    public function complete_setup(array $context, array $input): array
    {
        $context['purpose'] = 'setup';
        $hash = self::setup_hash($input['token'] ?? null);
        if ($hash === null || !is_string($input['attempt_id'] ?? null) || !is_array($input['credential'] ?? null)) { return $this->error('invalid_request'); }
        $bound = $this->bound_attempt($context, $input['attempt_id']);
        if (!$bound['ok']) { return $bound; }
        $attempt = $bound['data']['attempt']; $target = (int) $attempt['target_id'];
        if ($context['actor_id'] && (int) $context['actor_id'] !== $target) { return $this->error('forbidden'); }
        $claim = $this->claim($context, $input['attempt_id']);
        if (!$claim['ok']) { return $claim; }
        try {
            $config = $this->current_configuration($attempt);
            if (!$config['ok']) { return $config; }
            $verified = $this->webauthn->verify_registration($attempt, $input['credential']);
            if (!$verified['ok']) { return $verified; }
            $record = $verified['data'] + ['user_id'=>$target,'site_id'=>$context['site_id'],'name'=>$attempt['issued']['name'],'created_at'=>time(),'created_local'=>current_time('mysql'),'last_used_local'=>null];
            $inputs = $this->configuration_inputs($context['site_id']);
            $link = null;
            $result = $this->storage->with_owner_lock($target, function(Storage $storage) use ($attempt,$record,$inputs,$context,$target,$hash,&$config,&$link): array {
                if (!$storage->account_exists($target)) { return $this->error('forbidden'); }
                $link = $storage->consume_setup_link($target, $hash, $context['site_id']);
                if (!$link) { return $this->error('attempt_unavailable'); }
                $config = $this->check_issued_configuration($this->locked_configuration($storage, $inputs), $attempt['issued']);
                if (!$config['ok']) { return $config; }
                return $storage->insert_credential($record);
            });
            if (!$result['ok']) { return $result; }
            $this->notify_added($target, (int) $link['issued_by'], $attempt['issued']['name'], true);
            return ['ok'=>true,'code'=>'ok','message'=>'','subject_id'=>$target,'data'=>['redirect_to'=>add_query_arg('azwp_passkeys_setup', 'done', wp_login_url())]];
        } finally { $this->storage->delete_attempt($input['attempt_id']); }
    }
    /** Tells the owner about every confirmed new passkey. Mail failure never changes the registration result. */
    private function notify_added(int $owner_id, int $actor_id, string $name, bool $setup_link = false): void
    {
        $owner = get_userdata($owner_id);
        if (!$owner || !is_email($owner->user_email)) { return; }
        $switched = switch_to_user_locale($owner_id);
        try {
            $site = wp_specialchars_decode((string) get_option('blogname'), ENT_QUOTES);
            $actor = $actor_id !== $owner_id ? get_userdata($actor_id) : false;
            $lines = [
                sprintf(__('A passkey named “%1$s” was added to your account on %2$s.', 'azwp-passkeys'), $name, $site),
                $setup_link ? sprintf(__('It was added with a setup link sent by %s.', 'azwp-passkeys'), get_userdata($actor_id) ? get_userdata($actor_id)->display_name : $site) : ($actor ? sprintf(__('It was added by %s.', 'azwp-passkeys'), $actor->display_name) : __('It was added while you were signed in.', 'azwp-passkeys')),
                __('If you did not expect this, remove the passkey and change your password:', 'azwp-passkeys'),
                admin_url('profile.php#azwp-passkeys'),
            ];
            wp_mail($owner->user_email, sprintf(__('[%s] A passkey was added to your account', 'azwp-passkeys'), $site), implode("\n\n", $lines));
        } catch (\Throwable) {
            // The credential is already saved; the email is best effort.
        } finally {
            if ($switched) { restore_previous_locale(); }
        }
    }
    /** Counts anonymous sign-in requests per client address. Reverse proxies must supply the real REMOTE_ADDR. */
    private function anonymous_allowed(): bool
    {
        $address = is_string($_SERVER['REMOTE_ADDR'] ?? null) ? $_SERVER['REMOTE_ADDR'] : '';
        $key = 'azwp_passkeys_rate_' . substr(hash_hmac('sha256', $address, wp_salt('auth')), 0, 32);
        $count = (int) get_transient($key);
        if ($count >= self::ANONYMOUS_ATTEMPTS_PER_MINUTE) { return false; }
        set_transient($key, $count + 1, MINUTE_IN_SECONDS);
        return true;
    }
    public function assertion_options(array $context, array $input): array
    {
        if ($context['purpose'] === 'login' && !$context['actor_id'] && !$this->anonymous_allowed()) { return $this->error('rate_limited'); }
        $config = $this->configuration($context['site_id']);
        if (!$config['ok']) { return $config; } $config=$config['data'];
        $issued=['rp_id'=>$config['rp_id'],'rp_name'=>$config['rp_name'],'origins'=>$config['origins'],'user_verification'=>'required'];
        // Sign-in is always usernameless: the browser picks the account and no target is bound.
        if ($context['purpose'] === 'login') {
            if (!is_bool($input['remember'] ?? null) || !is_string($input['redirect_to'] ?? null) || !in_array($input['surface'] ?? null,['native','frontend'],true)) { return $this->error('invalid_request'); }
            if ($input['remember'] && !$config['settings']['remember_login']) { return $this->error('invalid_request'); }
            return $this->issue($context,null,$issued+['remember'=>$input['remember'],'redirect_to'=>$input['redirect_to'],'surface'=>$input['surface']],false);
        }
        $target = $this->target($context,$input);
        if (!$target || !$this->authorized($context,$target)) { return $this->error('forbidden'); }
        $identity=$this->storage->get_identity($target); if (!$identity['ok']) { return $identity; }
        $rows=$this->storage->get_credentials($target); if (!$rows['ok']) { return $rows; }
        $credentials=!empty($identity['data']['identity']['enrollment_initialized']) ? array_values(array_filter($rows['data']['credentials'],fn($row)=>$this->eligible($row,$config))) : [];
        if (!$credentials) { return $this->error('no_credentials'); }
        return $this->issue($context,$target,$issued+['allow_credentials'=>$this->descriptors($credentials),'user_handle'=>$identity['data']['identity']['handle']],false);
    }
    public function verify_assertion(array $context, array $input): array
    {
        if (!is_string($input['attempt_id'] ?? null) || !is_array($input['credential'] ?? null)) { return $this->error('invalid_request'); }
        $bound=$this->bound_attempt($context,$input['attempt_id']); if (!$bound['ok']) { return $bound; }
        $attempt=$bound['data']['attempt'];
        if ($context['purpose']==='test' && !$this->authorized($context,(int)$attempt['target_id'])) { return $this->error('forbidden'); }
        $claim=$this->claim($context,$input['attempt_id']); if (!$claim['ok']) { return $claim; }
        try {
            $config=$this->current_configuration($attempt); if (!$config['ok']) { return $config; }
            // Only tests may carry an allow-list; anything else is not a state this plugin issued.
            if (($attempt['purpose']==='test') !== isset($attempt['issued']['allow_credentials'])) { return $this->error('attempt_unavailable'); }
            try { $credential_id=WebAuthn::decode($input['credential']['rawId'] ?? null); } catch (\Throwable) { return $this->error('invalid_request'); }
            $row=$this->storage->find_credential($credential_id); if (!$row['ok']) { return $row; }
            $credential=$row['data']['credential'];
            if (!$credential || !$this->eligible($credential,$config['data']) || !get_userdata((int)$credential['user_id'])) { return $this->error('authentication_failed'); }
            if ($attempt['target_id'] && (int)$attempt['target_id'] !== (int)$credential['user_id']) { return $this->error('authentication_failed'); }
            $identity=$this->storage->get_identity((int)$credential['user_id']);
            if (!$identity['ok'] || !$identity['data']['identity']) { return $this->error('authentication_failed'); }
            $credential['user_handle']=$identity['data']['identity']['handle'];
            $verified=$this->webauthn->verify_assertion($attempt,$credential,$input['credential']); if (!$verified['ok']) { return $verified; }
            $proof=['attempt_id'=>$input['attempt_id'],'site_id'=>$context['site_id'],'purpose'=>$context['purpose'],'actor_id'=>$context['actor_id'],'target_id'=>$attempt['target_id'],'browser_hash'=>$context['browser_hash'],'session_hash'=>$context['session_hash'],'issued_options'=>$attempt['issued'],'record_id'=>(int)$credential['id'],'name'=>(string)$credential['name'],'credential_id'=>$credential['credential_id'],'owner_id'=>(int)$credential['user_id'],'rp_id'=>$credential['rp_id'],'public_key_cose'=>$credential['public_key_cose'],'public_key_pem'=>$credential['public_key_pem'],'sign_count'=>$verified['data']['sign_count'],'backup_eligible'=>$verified['data']['backup_eligible'],'backed_up'=>$verified['data']['backed_up']];
            return $this->ok(['proof'=>$proof]);
        } finally { $this->storage->delete_attempt($input['attempt_id']); }
    }
    public function accept_assertion(array $proof): array
    {
        $inputs = $this->configuration_inputs((int) $proof['site_id']);
        if ($proof['purpose']==='test' && !$this->authorized($proof, (int) $proof['target_id'])) { return $this->error('forbidden'); }
        if (!$this->same_session($proof)) { return $this->error('forbidden'); }
        $result=$this->storage->with_owner_lock($proof['owner_id'],function(Storage $storage) use($proof,$inputs): array {
            if (!$this->existing_accounts($storage, $proof, (int) $proof['owner_id'])) { return $this->error('authentication_failed'); }
            $config=$this->check_issued_configuration($this->locked_configuration($storage, $inputs), $proof['issued_options']); if (!$config['ok']) { return $config; }
            $rows=$storage->get_locked_credentials($proof['owner_id']); if (!$rows['ok']) { return $rows; }
            $row=null; foreach($rows['data']['credentials'] as $candidate) { if ((int)$candidate['id']===$proof['record_id']) { $row=$candidate; break; } }
            if (!$row) { return $this->error('authentication_failed'); }
            foreach(['credential_id','rp_id','public_key_cose','public_key_pem'] as $key) { if ($row[$key] !== $proof[$key]) { return $this->error('authentication_failed'); } }
            if ((int)$row['user_id']!==$proof['owner_id'] || !$this->eligible($row,$config['data']) || (bool)$row['backup_eligible'] !== (bool)$proof['backup_eligible'] || ($proof['backed_up'] && !$proof['backup_eligible'])) { return $this->error('authentication_failed'); }
            if (($row['sign_count']!==0 || $proof['sign_count']!==0) && $proof['sign_count']<=$row['sign_count']) { return $this->error('authentication_failed'); }
            return $storage->update_credential($proof['record_id'],['sign_count'=>$proof['sign_count'],'backed_up'=>$proof['backed_up']]);
        });
        if (!$result['ok']) { return $result; }
        $saved=$this->storage->save_last_used($proof['record_id'],current_time('mysql'));
        return $this->ok(['verified'=>true,'last_used_local'=>$saved['ok']?($saved['data']['last_used_local']??null):null]);
    }
    public function complete_test(array $context, array $input): array
    {
        $context['purpose']='test'; $verified=$this->verify_assertion($context,$input);
        if (!$verified['ok']) { return $verified; }
        $result = $this->accept_assertion($verified['data']['proof']);
        if ($result['ok']) {
            $result['subject_id'] = (int) $verified['data']['proof']['owner_id'];
            $result['data']['name'] = $verified['data']['proof']['name'];
        }
        return $result;
    }
    private function summary(array $row,array $configuration,bool $can_remove): array
    {
        $available=$this->eligible($row,$configuration);
        return ['record_id'=>(string)$row['id'],'name'=>$row['name'],'authenticator'=>Authenticators::name((string)$row['aaguid']),'synced'=>(bool)$row['backed_up'],'created_local'=>$row['created_local'],'last_used_local'=>$row['last_used_local'],'available'=>$available,'unavailable_reason'=>$available?'':__('This passkey is unavailable under the current site settings.','azwp-passkeys'),'can_rename'=>true,'can_remove'=>$can_remove];
    }
    private function usable_after_removal(int $target,int $record_id,array $rows,array $configuration): bool
    {
        foreach($rows as $row) { if ((int)$row['id']!==$record_id && $this->eligible($row,$configuration)) { return true; } }
        return empty($configuration['settings']['passkey_only']) && !$this->storage->password_disabled($target) && $this->storage->get_account_password($target)!=='';
    }
    /** Site members who could not sign in under Passkey only mode, or null when passkeys are not configured. */
    public function members_without_passkey(int $site_id): ?array
    {
        $config=$this->configuration($site_id); if (!$config['ok']) { return null; }
        try { return $this->storage->members_without_passkey($site_id,$config['data']['rp_id']); } catch (\Throwable) { return null; }
    }
    /** Whether the account holds a passkey that works under the site's current settings. */
    public function has_usable_credential(int $user_id,int $site_id): bool
    {
        $config=$this->configuration($site_id); $rows=$this->storage->get_credentials($user_id);
        if (!$config['ok'] || !$rows['ok']) { return false; }
        foreach($rows['data']['credentials'] as $row) { if ($this->eligible($row,$config['data'])) { return true; } }
        return false;
    }
    /** Turning password sign-in off needs a working passkey, checked under the same lock as the write. */
    public function set_password_disabled(int $target_id,bool $disabled): array
    {
        $inputs=$this->configuration_inputs((int) get_current_blog_id());
        return $this->storage->save_password_policy($target_id,$disabled,function(Storage $storage) use($target_id,$inputs): bool {
            $config=$this->locked_configuration($storage,$inputs); $rows=$storage->get_locked_credentials($target_id);
            if (!$config['ok'] || !$rows['ok']) { return false; }
            foreach($rows['data']['credentials'] as $row) { if ($this->eligible($row,$config['data'])) { return true; } }
            return false;
        });
    }
    public function list_credentials(array $context,int $target_id): array
    {
        if (!$this->authorized($context,$target_id)) { return $this->error('forbidden'); }
        $rows=$this->storage->get_credentials($target_id); if (!$rows['ok']) { return $rows; }
        $config=$this->configuration($context['site_id']);
        $configuration=$config['ok']?$config['data']:['rp_id'=>'','origins'=>[],'settings'=>$this->settings->get_effective($context['site_id'])];
        $out=[]; foreach($rows['data']['credentials'] as $row) { if ((int)$row['site_id']===$context['site_id']) { $out[]=$this->summary($row,$configuration,$this->usable_after_removal($target_id,(int)$row['id'],$rows['data']['credentials'],$configuration)); } }
        return $this->ok(['credentials'=>$out]);
    }
    public function rename_credential(array $context,int $target_id,int $record_id,string $name): array
    {
        $name = sanitize_text_field($name);
        if (!$this->authorized($context,$target_id) || !$this->same_session($context)) { return $this->error('forbidden'); }
        $result = $this->storage->with_owner_lock($target_id,function(Storage $storage) use($context,$target_id,$record_id,$name): array {
            if (!$this->existing_accounts($storage, $context, $target_id)) { return $this->error('forbidden'); }
            $rows=$storage->get_locked_credentials($target_id); if (!$rows['ok']) { return $rows; }
            foreach($rows['data']['credentials'] as $row) {
                if ((int)$row['id']!==$record_id || (int)$row['site_id']!==$context['site_id']) { continue; }
                $unchanged=$name===$row['name'];
                $updated=$storage->update_credential($record_id,['name'=>$name]); if (!$updated['ok']) { return $updated; }
                return $this->ok(['credential'=>$updated['data']['credential'],'unchanged'=>$unchanged]);
            }
            return $this->error('forbidden');
        });
        if (!$result['ok']) { return $result; }
        $config=$this->configuration($context['site_id']);
        $configuration=$config['ok']?$config['data']:['rp_id'=>'','settings'=>$this->settings->get_effective($context['site_id'])];
        $result['data']['credential']=$this->summary($result['data']['credential'],$configuration,true);
        return $result;
    }
    public function remove_credential(array $context,int $target_id,int $record_id): array
    {
        $inputs = $this->configuration_inputs($context['site_id']);
        if (!$this->authorized($context,$target_id) || !$this->same_session($context)) { return $this->error('forbidden'); }
        return $this->storage->with_owner_lock($target_id,function(Storage $storage) use($context,$target_id,$record_id,$inputs): array {
            if (!$this->existing_accounts($storage, $context, $target_id)) { return $this->error('forbidden'); }
            $rows=$storage->get_locked_credentials($target_id); if (!$rows['ok']) { return $rows; }
            $row_result=$storage->get_credential($record_id); if (!$row_result['ok']) { return $row_result; } $row=$row_result['data']['credential'];
            if (!$row) { return $this->ok(['removed'=>false,'already_absent'=>true]); }
            if ((int)$row['user_id']!==$target_id || (int)$row['site_id']!==$context['site_id']) { return $this->error('forbidden'); }
            $config=$this->locked_configuration($storage, $inputs);
            if ($config['ok']) { $configuration=$config['data']; }
            else {
                // Configuration failure never makes a passkey usable. Password policy is still read under the lock.
                $settings=$this->locked_settings($storage, $inputs);
                $configuration=['rp_id'=>'','settings'=>$settings];
            }
            if (!$this->usable_after_removal($target_id,$record_id,$rows['data']['credentials'],$configuration)) { return $this->error('access_required'); }
            $deleted=$storage->delete_credential($record_id); return $deleted['ok']?$this->ok(['removed'=>true,'already_absent'=>false]):$deleted;
        });
    }
}
