<?php
namespace AZWP\Passkeys;

final class Screens {
    public const LOG_POLL_INTERVAL_MS = 5000;
    private array $page_hooks = [];
    public function __construct(private Settings $settings, private Passkeys $passkeys, private Storage $storage) {}
    public function register_hooks(): void {
        add_action('init', [$this, 'register_blocks']);
        add_action('admin_menu', [$this, 'register_menus']);
        add_action('network_admin_menu', [$this, 'register_network_menu']);
        add_action('admin_enqueue_scripts', [$this, 'admin_assets']);
        add_action('login_enqueue_scripts', fn() => $this->enqueue('login'));
        add_action('login_form', [$this, 'render_login']);
        add_action('login_form_azwp_passkeys_setup', [$this, 'render_setup']);
        add_filter('login_message', fn($message) => ($_GET['azwp_passkeys_setup']??'')==='done' ? $message.'<p class="message">'.esc_html__('Passkey added. Sign in with it now.','azwp-passkeys').'</p>' : $message);
        add_filter('login_body_class', fn(array $classes): array => empty($this->settings->get_effective(get_current_blog_id())['passkey_only']) ? $classes : [...$classes, 'azwp-passkeys-only']);
        add_action('show_user_profile', [$this, 'render_profile']);
        add_action('edit_user_profile', function(\WP_User $user): void { if (current_user_can('edit_users')) $this->render_profile($user); });
        add_action('admin_notices', [$this, 'account_notice']);
        add_action('user_profile_update_errors', function(\WP_Error $errors, bool $update, object $user): void {
            if ($update && !$errors->has_errors()) $this->save_profile((int)$user->ID, $errors);
        }, 10, 3);
        foreach (['login','register','test','list'] as $name) add_shortcode('azwp_pk_'.$name, [$this, 'render_shortcode']);
        add_action('admin_post_azwp_passkeys_save_site', fn() => $this->save_form('site'));
        add_action('network_admin_edit_azwp_passkeys_save_network', fn() => $this->save_form('network'));
        add_action('admin_post_azwp_passkeys_save_logs', fn() => $this->save_form('logs'));
        add_filter('users_list_table_query_args', [$this, 'filter_missing_passkey_users']);
        add_filter('plugin_action_links_'.plugin_basename(AZWP_PASSKEYS_FILE), [$this, 'plugin_links']);
        add_filter('network_admin_plugin_action_links_'.plugin_basename(AZWP_PASSKEYS_FILE), [$this, 'plugin_links']);
    }
    public function register_menus(): void {
        $this->page_hooks[] = add_options_page(__("AZ's WP Passkeys", 'azwp-passkeys'), __("AZ's WP Passkeys", 'azwp-passkeys'), 'manage_options', 'azwp-passkeys', [$this, 'render_site_settings']);
        $this->page_hooks[] = add_management_page(__('Passkey Logs','azwp-passkeys'), __('Passkey Logs','azwp-passkeys'), 'manage_options', 'azwp-passkeys-logs', [$this,'render_logs']);
    }
    public function register_network_menu(): void {
        $this->page_hooks[] = add_submenu_page('settings.php', __("AZ's WP Passkeys",'azwp-passkeys'), __("AZ's WP Passkeys",'azwp-passkeys'), 'manage_network_options', 'azwp-passkeys', [$this,'render_network_settings']);
    }
    public function filter_missing_passkey_users(array $args): array {
        if (($_GET['azwp_passkeys_missing']??'')!=='1'||!current_user_can('list_users')) return $args;
        $args['include']=$this->passkeys->members_without_passkey(get_current_blog_id())?:[0];
        return $args;
    }
    /** Members without a working passkey, keyed by site, for every site the Passkey only switch on this page affects. */
    private function readiness(bool $network): array {
        $sites=$network?array_map('intval',get_sites(['fields'=>'ids','network_id'=>get_current_network_id(),'number'=>0])):[get_current_blog_id()];
        $readiness=[];
        foreach ($sites as $site_id) { $ids=$this->passkeys->members_without_passkey($site_id); if ($ids) $readiness[$site_id]=$ids; }
        return $readiness;
    }
    private static function readiness_total(array $readiness): int {
        return count(array_unique(array_merge([],...array_values($readiness))));
    }
    /** Identifies the exact set of accounts, so a confirmation cannot approve a different set with the same size. */
    private static function readiness_token(array $readiness): string {
        $ids=array_unique(array_merge([],...array_values($readiness))); sort($ids);
        return $ids?substr(hash('sha256',implode(',',$ids)),0,32):'';
    }
    private function readiness_notice(bool $network,bool $editable,bool $on): void {
        $readiness=$this->readiness($network); if (!$readiness) return;
        $total=self::readiness_total($readiness);
        $text=$network
            ?sprintf(_n('%d account has no working passkey on at least one site and cannot sign in there while Passkey only mode is on.','%d accounts have no working passkey on at least one site and cannot sign in there while Passkey only mode is on.',$total,'azwp-passkeys'),$total)
            :sprintf(_n('%d member has no working passkey for this site and cannot sign in while Passkey only mode is on.','%d members have no working passkey for this site and cannot sign in while Passkey only mode is on.',$total,'azwp-passkeys'),$total);
        $token=self::readiness_token($readiness);
        echo '<div class="notice notice-warning inline" data-passkey-only-readiness="'.esc_attr((string)$total).'" data-passkey-only-token="'.esc_attr($token).'"><p>'.esc_html($text).'</p><ul>';
        foreach ($readiness as $site_id=>$ids) {
            $label=$network?sprintf(__('%1$s: %2$d','azwp-passkeys'),get_blog_option($site_id,'blogname'),count($ids)):__('View these members','azwp-passkeys');
            echo '<li><a href="'.esc_url(get_admin_url($site_id,'users.php?azwp_passkeys_missing=1')).'">'.esc_html($label).'</a></li>';
        }
        echo '</ul>';
        if ($editable&&!$on) echo '<input type="hidden" name="passkey_only_confirmed" value=""><noscript><label><input type="checkbox" name="passkey_only_confirmed" value="'.esc_attr($token).'"> '.esc_html__('I understand these accounts cannot sign in.','azwp-passkeys').'</label></noscript>';
        echo '</div>';
    }
    public function plugin_links(array $links): array {
        $url = is_network_admin() ? network_admin_url('settings.php?page=azwp-passkeys') : admin_url('options-general.php?page=azwp-passkeys');
        array_unshift($links, '<a href="'.esc_url($url).'">'.esc_html__('Settings','azwp-passkeys').'</a>');
        return $links;
    }
    public function admin_assets(string $hook): void {
        if (in_array($hook, ['profile.php','user-edit.php'], true)) $this->enqueue('profile');
        elseif (in_array($hook,$this->page_hooks,true)) $this->enqueue('settings');
    }
    private function asset_version(string $path): string {
        $file=AZWP_PASSKEYS_DIR.'assets/'.$path;
        return wp_get_environment_type()==='local'&&is_file($file)?(string)filemtime($file):AZWP_PASSKEYS_VERSION;
    }
    private function enqueue(string $page): void {
        $base=AZWP_PASSKEYS_URL.'assets/';
        wp_enqueue_script('azwp-passkeys-client',$base.'js/client.js',['wp-i18n'],$this->asset_version('js/client.js'),true);
        wp_enqueue_script('azwp-passkeys-'.$page,$base.'js/'.$page.'.js',['azwp-passkeys-client','wp-i18n'],$this->asset_version('js/'.$page.'.js'),true);
        foreach (['client',$page] as $handle) wp_set_script_translations('azwp-passkeys-'.$handle,'azwp-passkeys',AZWP_PASSKEYS_DIR.'languages');
        $style=in_array($page,['profile','settings'],true)?'admin':$page;
        wp_enqueue_style('azwp-passkeys-'.$style,$base.'css/'.$style.'.css',[],$this->asset_version('css/'.$style.'.css'));
        $config=$this->settings->get_effective(get_current_blog_id());
        $public=array_intersect_key($config,array_flip(['passkey_only','remember_login']));
        wp_localize_script('azwp-passkeys-client','azwpPasskeysConfig',[
            'ajax_url'=>admin_url('admin-ajax.php'), 'policy'=>$public,'log_poll_interval_ms'=>self::LOG_POLL_INTERVAL_MS,
            'server_ready'=>$this->server_ready(), 'logged_in'=>is_user_logged_in(),
        ]);
    }
    public function register_blocks(): void {
        wp_register_script('azwp-passkeys-blocks',AZWP_PASSKEYS_URL.'assets/js/blocks.js',['wp-blocks','wp-element','wp-block-editor','wp-components','wp-i18n'],$this->asset_version('js/blocks.js'),true);
        wp_set_script_translations('azwp-passkeys-blocks','azwp-passkeys',AZWP_PASSKEYS_DIR.'languages');
        foreach (['login','register','test','list'] as $name) register_block_type('azwp-passkeys/'.$name,['editor_script'=>'azwp-passkeys-blocks']);
    }
    private function server_ready(): bool {
        $host=wp_parse_url(site_url(),PHP_URL_HOST);
        return (is_ssl()||$host==='localhost') && extension_loaded('openssl') && in_array('prime256v1',openssl_get_curve_names(),true) && in_array('sha256',openssl_get_md_methods(),true);
    }
    private function view(string $name,array $data=[]): string {
        extract($data,EXTR_SKIP);
        ob_start(); require AZWP_PASSKEYS_DIR.'views/'.$name.'.php'; return (string)ob_get_clean();
    }
    private function component_data(int $target_id=0): array {
        $target_id=$target_id?:get_current_user_id();
        return ['policy'=>$this->settings->get_effective(get_current_blog_id()),'target_id'=>$target_id,
            'can_manage'=>is_user_logged_in()&&current_user_can('read')&&($target_id===get_current_user_id()||current_user_can('edit_user',$target_id)),
            'nonce'=>is_user_logged_in()?wp_create_nonce('azwp_passkeys_manage_'.$target_id.'_'.get_current_blog_id()):'',
            'instance'=>wp_unique_id('azwp-passkeys-component-'),'ready'=>$this->server_ready()];
    }
    public function render_profile(\WP_User $user): void {
        if (!current_user_can('read')||!current_user_can('edit_user',$user->ID)) return;
        $this->environment_notice();
        // The marker is a UI hint for one's own profile; it grants nothing.
        $registered=$user->ID===get_current_user_id()&&isset($_GET['azwp_passkeys_registered'])&&$_GET['azwp_passkeys_registered']==='1';
        echo $this->view('profile',$this->component_data($user->ID)+['user'=>$user,'password_disabled'=>(bool)get_user_meta($user->ID,'azwp_passkeys_password_disabled',true),'registered'=>$registered]);
    }
    public function account_notice(): void {
        if (is_network_admin() || !is_user_logged_in() || !current_user_can('read')) return;
        $targets=[get_current_user_id()];
        if (($GLOBALS['pagenow']??'')==='user-edit.php' && current_user_can('edit_users')) {
            $target_id=isset($_GET['user_id'])?absint($_GET['user_id']):0;
            if ($target_id && current_user_can('edit_user',$target_id) && !in_array($target_id,$targets,true)) $targets[]=$target_id;
        }
        $policy=$this->settings->get_effective(get_current_blog_id());
        foreach ($targets as $target_id) {
            if (empty($policy['passkey_only'])&&!get_user_meta($target_id,'azwp_passkeys_password_disabled',true)) continue;
            $rows=$this->storage->get_credentials($target_id,get_current_blog_id());
            if (!$rows['ok']||!empty($rows['data']['credentials'])) continue;
            $user=get_userdata($target_id); if (!$user) continue;
            $url=$target_id===get_current_user_id()?admin_url('profile.php#azwp-passkeys'):get_edit_user_link($target_id).'#azwp-passkeys';
            echo '<div class="notice notice-warning"><p>'.sprintf(esc_html__('Password sign-in is disabled for %s and no passkey has been added on this site.','azwp-passkeys'),esc_html($user->display_name)).' <a href="'.esc_url($url).'">'.esc_html__('Add passkey','azwp-passkeys').'</a></p>';
            if (is_multisite()&&!is_subdomain_install()) echo '<p>'.esc_html__('Passkeys from other sites in this network may still work.','azwp-passkeys').'</p>';
            echo '</div>';
        }
    }
    private function environment_notice(): void {
        if (!$this->server_ready()) echo '<div class="notice notice-error"><p>'.esc_html__('Passkeys are unavailable. Check that this site uses HTTPS and that the server supports OpenSSL, P-256 and SHA-256. HTTP is supported only on localhost.','azwp-passkeys').'</p></div>';
    }
    public function save_profile(int $target_id, ?\WP_Error $errors=null): void {
        if (($target_id!==get_current_user_id()&&!current_user_can('edit_users'))||!current_user_can('edit_user',$target_id)||!isset($_POST['_wpnonce'])||!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['_wpnonce'])),'update-user_'.$target_id)) return;
        $policy=$this->settings->get_effective(get_current_blog_id());
        if (!$this->server_ready()||!empty($policy['passkey_only'])||!isset($_POST['azwp_passkeys_profile_present'])) return;
        $result=$this->passkeys->set_password_disabled($target_id,isset($_POST['azwp_passkeys_password_disabled']));
        if (!$result['ok'] && $errors) $errors->add('azwp_passkeys_save_failed',$result['code']==='access_required'?__('Add a working passkey before turning on Passkey only mode for this account.','azwp-passkeys'):__('The change could not be saved. Try again.','azwp-passkeys'));
    }
    public function render_setup(): void {
        $user_id=absint($_GET['user']??0);
        $token=is_string($_GET['token']??null)?sanitize_text_field(wp_unslash($_GET['token'])):'';
        $valid=$user_id&&$this->passkeys->setup_link_valid($user_id,$token,get_current_blog_id());
        login_header(__('Add a passkey','azwp-passkeys'));
        echo $this->view('setup',['valid'=>$valid,'user_id'=>$user_id,'token'=>$token,'user'=>$valid?get_userdata($user_id):null,'instance'=>wp_unique_id('azwp-passkeys-component-')]);
        login_footer();
        exit;
    }
    public function render_login(): void {
        if (isset($_REQUEST['action'])&&!in_array($_REQUEST['action'],['login'],true)) return;
        echo $this->view('login',$this->component_data()+['native'=>true,'redirect_to'=>isset($_REQUEST['redirect_to'])?esc_url_raw(wp_unslash($_REQUEST['redirect_to'])):'']);
    }
    public function render_shortcode(array|string $attributes,?string $content=null,string $tag=''): string {
        $kind=substr($tag,strlen('azwp_pk_')); if (!in_array($kind,['login','register','test','list'],true)) return '';
        $attributes=shortcode_atts($kind==='login'?['traditional'=>'true','username'=>'','auto_hide'=>'true','to'=>'']:['display'=>'true'],(array)$attributes,$tag);
        if ($kind==='login'&&$attributes['auto_hide']==='true'&&is_user_logged_in()&&current_user_can('read')) return '';
        if ($kind!=='login'&&!is_user_logged_in()&&$attributes['display']!=='true') return '';
        $this->enqueue('frontend'); $data=$this->component_data();
        if ($kind==='login') {
            $identifier=html_entity_decode((string)$attributes['username'],ENT_QUOTES,'UTF-8');
            $data+=['native'=>false,'username'=>sanitize_text_field($identifier),
                'redirect_to'=>esc_url_raw(html_entity_decode((string)$attributes['to'],ENT_QUOTES,'UTF-8')),'traditional'=>$attributes['traditional']==='true'];
            if (!$data['redirect_to']) {
                $home=wp_parse_url(home_url('/'));
                $origin=$home['scheme'].'://'.$home['host'].(isset($home['port'])?':'.$home['port']:'');
                $request=wp_unslash($_SERVER['REQUEST_URI']??'/');
                $data['redirect_to']=esc_url_raw($origin.(str_starts_with($request,'/')?$request:'/'));
            }
        }
        return $this->view($kind==='list'?'credential-list':'frontend-'.$kind,$data);
    }
    public function render_site_settings(): void {$this->render_settings(false);}
    public function render_network_settings(): void {$this->render_settings(true);}
    private function render_settings(bool $network): void {
        if (!current_user_can($network?'manage_network_options':'manage_options')) wp_die(esc_html__('You do not have permission to manage these settings.','azwp-passkeys'));
        $policy=$this->settings->get_effective(get_current_blog_id());
        $this->environment_notice();
        $values=$network?$this->settings->get_network(get_current_network_id()):$policy;
        echo $this->view($network?'settings-network':'settings-site',['values'=>$values,'network'=>$network,'ready'=>$this->server_ready()]);
    }
    public function render_logs(): void {
        if (!current_user_can('manage_options')) wp_die(esc_html__('You do not have permission to view logs.','azwp-passkeys'));
        $this->environment_notice();
        if (!$this->passkeys->configuration(get_current_blog_id())['ok']) echo '<div class="notice notice-error"><p>'.esc_html__('Check Website name and Passkey domain in settings. The passkey domain must match this site.','azwp-passkeys').'</p></div>';
        echo $this->view('logs',['values'=>$this->settings->get_effective(get_current_blog_id()),'nonce'=>wp_create_nonce('azwp_passkeys_logs_'.get_current_blog_id()),'ready'=>$this->server_ready()]);
    }
    private function save_form(string $scope): void {
        $network=$scope==='network'; $id=$network?get_current_network_id():get_current_blog_id();
        if (!current_user_can($network?'manage_network_options':'manage_options')) wp_die(esc_html__('You do not have permission to manage these settings.','azwp-passkeys'));
        check_admin_referer('azwp_passkeys_save_'.$scope.'_'.$id);
        $input=wp_unslash($_POST); $method='save_'.$scope;
        $url=$network?network_admin_url('settings.php?page=azwp-passkeys'):admin_url($scope==='logs'?'tools.php?page=azwp-passkeys-logs':'options-general.php?page=azwp-passkeys');
        $effective=$this->settings->get_effective(get_current_blog_id());
        // Passkey only mode removes the password form, so the saving administrator must be able to get back in.
        $sets_only=$scope!=='logs'&&($network||!is_multisite())&&($input['passkey_only']??null)==='1'&&empty($effective['passkey_only']);
        // The checks below use the stored passkey domain, so a save that leaves the mode on must keep that domain and a usable configuration.
        $only_after=$scope==='site'&&(is_multisite()?!empty($effective['passkey_only']):($input['passkey_only']??null)==='1');
        $locked=$only_after?array_keys(array_filter([
            'rp_id'=>strtolower(trim((string)($input['rp_id']??'')))!==$effective['rp_id'],
            'rp_name'=>trim((string)($input['rp_name']??''))==='',
        ])):[];
        if ($locked) {
            $result=['ok'=>false,'data'=>['invalid'=>[...$locked,'passkey_only_locked']]];
        } elseif ($sets_only&&!$this->passkeys->has_usable_credential(get_current_user_id(),get_current_blog_id())) {
            $result=['ok'=>false,'data'=>['invalid'=>['passkey_only']]];
        } elseif ($sets_only&&($token=self::readiness_token($this->readiness($network)))!==''&&!hash_equals($token,(string)($input['passkey_only_confirmed']??''))) {
            $result=['ok'=>false,'data'=>['invalid'=>['passkey_only_confirm']]];
        } else {
            $result=$this->settings->$method($input);
        }
        $query=['status'=>!empty($result['ok'])?'settings_saved':'settings_failed'];
        if (empty($result['ok']) && !empty($result['data']['invalid'])) $query['invalid']=implode(',',array_intersect($result['data']['invalid'],[...array_keys($this->settings->definitions()),'passkey_only_confirm','passkey_only_locked']));
        wp_safe_redirect(add_query_arg($query,$url)); exit;
    }
    private function field_invalid(string $key): bool {
        $invalid=isset($_GET['invalid'])&&is_string($_GET['invalid'])?explode(',',sanitize_text_field(wp_unslash($_GET['invalid']))):[];
        return in_array($key,$invalid,true);
    }
    private function invalid_field_notice(string $key): void {
        if (!$this->field_invalid($key)) return;
        $message=in_array($key,['rp_id','rp_name'],true)&&$this->field_invalid('passkey_only_locked')?__('Passkey only mode is on, and changing this would stop every passkey from working. Turn Passkey only mode off first.','azwp-passkeys'):($key==='passkey_only_confirm'?__('Confirm that the accounts listed above will not be able to sign in, then save again.','azwp-passkeys'):($key==='passkey_only'?__('Add a working passkey to your own account before turning on Passkey only mode.','azwp-passkeys'):__('Check this field and save again.','azwp-passkeys')));
        echo '<p class="description azwp-passkeys-error">'.esc_html($message).'</p>';
    }
    private function status_notice(): void {
        $status=isset($_GET['status'])?sanitize_key($_GET['status']):'';
        if ($status==='settings_saved') echo '<div class="notice notice-success"><p>'.esc_html__('Settings saved','azwp-passkeys').'</p></div>';
        if ($status==='settings_failed') echo '<div class="notice notice-error"><p>'.esc_html__('Settings could not be saved.','azwp-passkeys').'</p></div>';
    }
    private function setting_control(string $key,array $values,bool $network,bool $ready): void {
        $labels=Settings::labels();
        $help=[
            'passkey_only'=>__('Turns off password sign-in for every account. Sign-in pages show only the passkey button. Make sure each account has a working passkey first. On a network, users need a passkey for each site domain.','azwp-passkeys'),
            'remember_login'=>__('Lets passkey sign-in keep people signed in when they tick Remember me. The box starts unchecked.','azwp-passkeys'),
            'reset_restriction'=>__('Both blocking options close public password-reset pages, including for administrators. The administrator exception allows authorized reset operations. Passwords can still be changed in WordPress profiles.','azwp-passkeys'),
            'after_registration'=>__('New accounts are signed in right after registering and asked to add a passkey. WordPress still sends its welcome email, but the email address is not verified before sign-in.','azwp-passkeys'),
            'logging'=>__('Save log entries for troubleshooting. Entries remain until you clear them.','azwp-passkeys'),
        ][$key];
        $label=$labels['settings'][$key]; $choices=$labels['choices'][$key]??null; $value=$values[$key];
        echo '<tr><th scope="row"><label for="azwp-passkeys-'.$key.'">'.esc_html($label).'</label></th><td>';
        if (!$network&&is_multisite()&&$key==='passkey_only') {
            echo '<p>'.esc_html__('Set in network settings:','azwp-passkeys').' '.esc_html($value?__('Enabled','azwp-passkeys'):__('Disabled','azwp-passkeys')).'</p><a href="'.esc_url(network_admin_url('settings.php?page=azwp-passkeys')).'">'.esc_html__('Network settings','azwp-passkeys').'</a>';
        } elseif ($choices===null) {
            echo '<fieldset><legend class="screen-reader-text">'.esc_html($label).'</legend>';
            foreach (['1'=>__('Enable','azwp-passkeys'),'0'=>__('Disable','azwp-passkeys')] as $option=>$text) echo '<label class="azwp-passkeys-choice"><input type="radio" name="'.esc_attr($key).'" value="'.esc_attr($option).'" '.checked((string)(int)(bool)$value,(string)$option,false).' '.disabled($key==='passkey_only'&&$option==='1'&&!$ready&&!$value,true,false).'> '.esc_html($text).'</label>';
            echo '</fieldset>';
        } else {
            echo '<select id="azwp-passkeys-'.esc_attr($key).'" name="'.esc_attr($key).'">';
            foreach ($choices as $option=>$text) echo '<option value="'.esc_attr($option).'" '.selected($value,$option,false).'>'.esc_html($text).'</option>';
            echo '</select>';
        }
        echo '<p class="description">'.esc_html($help).'</p>';
        if ($key==='passkey_only') { $this->readiness_notice($network,$network||!is_multisite(),(bool)$value); $this->invalid_field_notice('passkey_only_confirm'); }
        if ($key==='reset_restriction'&&!empty($values['passkey_only'])) echo '<p class="description">'.esc_html__('Passkey only mode is on, so password resets are blocked for everyone.','azwp-passkeys').'</p>';
        if ($key==='after_registration'&&!get_option('users_can_register')) echo '<p class="description">'.esc_html__('This has no effect until Anyone can register is turned on in General settings.','azwp-passkeys').'</p>';
        $this->invalid_field_notice($key);
        echo '</td></tr>';
    }
}
