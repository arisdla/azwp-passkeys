<?php
declare(strict_types=1);
namespace AZWP\Passkeys;
final class Ajax
{
    private const ACTIONS = ['login_options','login_complete','register_options','register_complete','test_options','test_complete','list','rename','remove','log_read','log_clear','send_setup','setup_options','setup_complete'];
    public const EVENTS = ['login_complete'=>'signin.passkey','register_complete'=>'passkey.added','setup_complete'=>'passkey.added_by_link','test_complete'=>'passkey.tested','rename'=>'passkey.renamed','remove'=>'passkey.deleted','send_setup'=>'admin.setup_link'];
    public function __construct(private Settings $settings, private Passkeys $passkeys, private Authentication $authentication, private Logs $logs) {}
    public function register_hooks(): void
    {
        foreach(self::ACTIONS as $action) {
            add_action('wp_ajax_azwp_passkeys_'.$action, [$this,'handle_'.$action]);
            add_action('wp_ajax_nopriv_azwp_passkeys_'.$action, [$this,'handle_'.$action]);
        }
    }
    public function handle_login_options(): void { $this->dispatch('login_options'); }
    public function handle_login_complete(): void { $this->dispatch('login_complete'); }
    public function handle_register_options(): void { $this->dispatch('register_options'); }
    public function handle_register_complete(): void { $this->dispatch('register_complete'); }
    public function handle_test_options(): void { $this->dispatch('test_options'); }
    public function handle_test_complete(): void { $this->dispatch('test_complete'); }
    public function handle_list(): void { $this->dispatch('list'); }
    public function handle_rename(): void { $this->dispatch('rename'); }
    public function handle_remove(): void { $this->dispatch('remove'); }
    public function handle_log_read(): void { $this->dispatch('log_read'); }
    public function handle_log_clear(): void { $this->dispatch('log_clear'); }
    public function handle_send_setup(): void { $this->dispatch('send_setup'); }
    public function handle_setup_options(): void { $this->dispatch('setup_options'); }
    public function handle_setup_complete(): void { $this->dispatch('setup_complete'); }
    private function failure(string $code): array { return ['ok'=>false,'code'=>$code,'data'=>[],'message'=>'']; }
    private function context(string $action): array
    {
        $purpose = str_starts_with($action,'register_')?'register':(str_starts_with($action,'test_')?'test':(str_starts_with($action,'setup_')?'setup':'login'));
        $actor = get_current_user_id();
        if (str_ends_with($action, '_options') || str_ends_with($action, '_complete')) {
            if (!is_ssl() && (wp_parse_url(site_url(), PHP_URL_HOST) !== 'localhost' || strtolower(explode(':', (string) ($_SERVER['HTTP_HOST'] ?? ''))[0]) !== 'localhost')) { throw new \InvalidArgumentException('HTTPS is required'); }
        }
        $cookie = $_COOKIE['azwp_passkeys_browser'] ?? null;
        $bytes = null;
        try { if (is_string($cookie)) { $decoded=WebAuthn::decode($cookie); if(strlen($decoded)===32){$bytes=$decoded;} } } catch(\Throwable) {}
        if ($bytes===null && str_ends_with($action,'_options')) {
            $bytes=random_bytes(32);
            if (headers_sent() || !setcookie('azwp_passkeys_browser',WebAuthn::encode($bytes),['expires'=>0,'path'=>'/','secure'=>is_ssl(),'httponly'=>true,'samesite'=>'Lax'])) { throw new \RuntimeException('Browser binding unavailable'); }
        }
        return ['site_id'=>(int)get_current_blog_id(),'network_id'=>is_multisite()?(int)get_current_network_id():0,'actor_id'=>$actor,'browser_hash'=>$bytes===null?null:hash('sha256',$bytes,true),'session_hash'=>$actor?hash('sha256',wp_get_session_token(),true):null,'purpose'=>$purpose,'user_agent'=>is_string($_SERVER['HTTP_USER_AGENT'] ?? null)?$_SERVER['HTTP_USER_AGENT']:''];
    }
    private function dispatch(string $action): void
    {
        nocache_headers();
        $correlation_id=bin2hex(random_bytes(16));
        $context=['site_id'=>(int)get_current_blog_id(),'actor_id'=>get_current_user_id()];
        try {
            if (($_SERVER['REQUEST_METHOD']??'')!=='POST' || !is_string($_POST['payload']??null)) { $this->respond($this->failure('invalid_request'),$correlation_id); }
            $payload=json_decode(wp_unslash($_POST['payload']),true,32,JSON_THROW_ON_ERROR);
            if (!is_array($payload) || (array_is_list($payload) && $payload!==[])) { $this->respond($this->failure('invalid_request'),$correlation_id); }
            if (!str_starts_with($action,'login_') && !str_starts_with($action,'setup_') && !is_user_logged_in()) { $this->respond($this->failure('forbidden'),$correlation_id); }
            // Verify presentation-level authority before issuing a browser-binding cookie or mutating attempts.
            $site_id=$context['site_id'];
            $target=array_key_exists('target_id',$payload)?Passkeys::numeric_id($payload['target_id']):($context['actor_id']?:null);
            if (in_array($action,['register_options','list','rename','remove','send_setup'],true)) {
                if (!$target) { $this->respond($this->failure('invalid_request'),$correlation_id); }
                if (!current_user_can('read') || ($target!==$context['actor_id']&&!current_user_can('edit_user',$target))) { $this->respond($this->failure('forbidden'),$correlation_id); }
                if (!$this->nonce('azwp_passkeys_manage_'.$target.'_'.$site_id)) { $this->respond($this->failure('invalid_nonce'),$correlation_id); }
            }
            if (str_starts_with($action,'log_')) {
                if (!current_user_can('manage_options')) { $this->respond($this->failure('forbidden'),$correlation_id); }
                if (!$this->nonce('azwp_passkeys_logs_'.$site_id)) { $this->respond($this->failure('invalid_nonce'),$correlation_id); }
            }
            if (str_starts_with($action,'test_') && !current_user_can('read')) { $this->respond($this->failure('forbidden'),$correlation_id); }
            $context=$this->context($action);
            if ($action==='register_complete') {
                if (!is_string($payload['attempt_id']??null)) { $this->respond($this->failure('invalid_request'),$correlation_id); }
                $bound=$this->passkeys->registration_target($context,$payload['attempt_id']);
                if (!$bound['ok']) { $this->respond($bound,$correlation_id); }
                $target=$bound['data']['target_id'];
                if (!$this->nonce('azwp_passkeys_manage_'.$target.'_'.$site_id)) { $this->respond($this->failure('invalid_nonce'),$correlation_id); }
            }
            $record_id=in_array($action,['rename','remove'],true)?Passkeys::numeric_id($payload['record_id']??null):null;
            if (in_array($action,['rename','remove'],true) && !$record_id) { $this->respond($this->failure('invalid_request'),$correlation_id); }
            if ($action==='rename' && !is_string($payload['name']??null)) { $this->respond($this->failure('invalid_request'),$correlation_id); }
            $result=match($action) {
                'login_options','test_options'=>$this->passkeys->assertion_options($context,$payload),
                'login_complete'=>$this->authentication->complete_login($context,$payload),
                'register_options'=>$this->passkeys->registration_options($context,$payload),
                'register_complete'=>$this->passkeys->complete_registration($context,$payload),
                'test_complete'=>$this->passkeys->complete_test($context,$payload),
                'list'=>$this->passkeys->list_credentials($context,$target),
                'rename'=>$this->passkeys->rename_credential($context,$target,$record_id,$payload['name']),
                'remove'=>$this->passkeys->remove_credential($context,$target,$record_id),
                'log_read'=>$this->logs->read($site_id,$payload),
                'log_clear'=>$this->logs->clear($site_id,(int)$context['actor_id']),
                'send_setup'=>$this->passkeys->send_setup_link($context,$target),
                'setup_options'=>$this->passkeys->setup_options($context,$payload),
                'setup_complete'=>$this->passkeys->complete_setup($context,$payload),
            };
            if (isset(self::EVENTS[$action]) && ($result['log'] ?? null) !== false) { $this->logs->record(self::EVENTS[$action], self::log_fields($action,$result,(int)$context['actor_id'],$target,$correlation_id)); }
        } catch(\JsonException|\InvalidArgumentException) { $result=$this->failure('invalid_request'); }
        catch(\Throwable) { $result=$this->failure('storage_failed'); }
        $this->respond($result,$correlation_id);
    }
    /** The record() fields for an operation result. The browser never receives the result's top-level log. */
    public static function log_fields(string $action, array $result, int $actor_id, ?int $target, string $correlation_id): array
    {
        $log=is_array($result['log']??null)?$result['log']:[];
        // Authentication subjects come only from accepted server proof, never client targets.
        $subject=in_array($action,['login_complete','test_complete','setup_complete'],true)
            ?(!empty($result['ok'])?($result['subject_id']??null):null)
            :$target;
        // A logged passkey names its owner, so the eraser finds the row even when the operation failed.
        if (is_int($log['passkey']['user_id']??null)) { $subject=$log['passkey']['user_id']; }
        return ['ok'=>!empty($result['ok']),'code'=>(string)$result['code'],'actor_id'=>$actor_id?:null,'target_id'=>$subject,'correlation_id'=>$correlation_id,'passkey'=>$log['passkey']??null,'data'=>$log['data']??[]];
    }
    private function nonce(string $action): bool
    {
        return is_string($_POST['_ajax_nonce']??null) && (bool)wp_verify_nonce(wp_unslash($_POST['_ajax_nonce']),$action);
    }
    private function respond(array $result,string $correlation_id): never
    {
        if($result['ok']) { wp_send_json_success(['code'=>'ok','message'=>$result['message']??'']+$result['data'],200); }
        $code=$result['code'];
        $status=match($code){'invalid_request'=>400,'authentication_failed'=>401,'forbidden','invalid_nonce'=>403,'attempt_unavailable','credential_exists','access_required','state_changed','no_credentials'=>409,'rate_limited'=>429,default=>503};
        $message=match($code){
            'invalid_request'=>__('Check the fields and try again.','azwp-passkeys'),
            'forbidden'=>__('You do not have permission to do this.','azwp-passkeys'),
            'invalid_nonce'=>__('The request could not be accepted. Refresh the page and try again.','azwp-passkeys'),
            'attempt_unavailable'=>__('This passkey request expired or was already used. Start again.','azwp-passkeys'),
            'credential_exists'=>__('This passkey has already been added. Nothing was replaced.','azwp-passkeys'),
            'access_required'=>__('Add another usable passkey or restore another sign-in method before removing this passkey.','azwp-passkeys'),
            'state_changed'=>__('Your sign-in session or site settings changed. Start again.','azwp-passkeys'),
            'no_credentials'=>__('No passkey is available for this account.','azwp-passkeys'),
            'rate_limited'=>__('Too many sign-in attempts. Wait a minute and try again.','azwp-passkeys'),
            'not_configured'=>__('Passkeys are unavailable. Contact the site administrator.','azwp-passkeys'),
            'mail_failed'=>__('The email could not be sent. Try again.','azwp-passkeys'),
            'outcome_unknown'=>__('The result could not be confirmed. Refresh to check.','azwp-passkeys'),
            'storage_failed'=>__('The change could not be saved. Try again.','azwp-passkeys'),
            default=>__('The passkey could not be verified. Try again.','azwp-passkeys'),
        };
        $retry=match($code){'outcome_unknown'=>'uncertain','invalid_nonce','storage_failed'=>'refresh','forbidden','access_required','not_configured'=>'none',default=>'fresh_attempt'};
        wp_send_json_error(['code'=>$code,'message'=>$message,'retry'=>$retry,'correlation_id'=>$correlation_id],$status);
        exit;
    }
}
