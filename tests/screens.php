<?php
/** Rendering integration checks; run only with a disposable WordPress database. */
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true) throw new RuntimeException('A disposable WordPress test bootstrap is required.');
require_once dirname(__DIR__).'/autoload.php';
require_once ABSPATH.'wp-admin/includes/user.php';
require_once ABSPATH.'wp-admin/includes/template.php';
$checks=0;
$assert=static function(bool $condition,string $label)use(&$checks):void { if (!$condition) throw new RuntimeException($label); ++$checks; };
$storage=new \AZWP\Passkeys\Storage($GLOBALS['wpdb']);
$settings=new \AZWP\Passkeys\Settings($storage,new \AZWP\Passkeys\Logs($storage));
$screens=new \AZWP\Passkeys\Screens($settings,new \AZWP\Passkeys\Passkeys($settings,$storage,new \AZWP\Passkeys\WebAuthn()),$storage);
$original=get_option('azwp_passkeys_settings',null);
$actor=get_current_user_id();
$id=wp_insert_user(['user_login'=>'azwp_ui_'.bin2hex(random_bytes(6)),'user_pass'=>wp_generate_password(),'role'=>'administrator']);
if (is_wp_error($id)) throw new RuntimeException('Cannot create disposable UI account.');
$render=static function(callable $callback):string { ob_start();$callback();return (string)ob_get_clean(); };
try {
    wp_set_current_user(0);
    foreach (['register','test','list'] as $kind) {
        $assert($screens->render_shortcode(['display'=>'false'],null,'azwp_pk_'.$kind)==='', 'Signed-out hidden '.$kind);
        $html=$screens->render_shortcode([],null,'azwp_pk_'.$kind);
        $assert(str_contains($html,'Sign in to manage your passkeys.')||str_contains($html,'Sign in to test your passkeys.')||str_contains($html,'Sign in to view your passkeys.'),'Signed-out prompt '.$kind);
    }
    $html=$screens->render_shortcode(['traditional'=>'false','username'=>'<script>bad</script>'],null,'azwp_pk_login');
    $assert(!str_contains($html,'<script>bad</script>')&&!str_contains($html,'name="pwd"'),'Login attribute escaped and password form omitted');
    $html=$screens->render_shortcode([],null,'azwp_pk_login');
    $assert(str_contains($html,'name="pwd"')&&str_contains($html,'data-action="login"')&&!str_contains($html,'switch-login'),'Default frontend login shows the password form and a passkey button, with no switch');
    $policy_scope=is_multisite()?['network',(int)get_current_network_id()]:['site',(int)get_current_blog_id()];
    $storage->save_settings($policy_scope[0],$policy_scope[1],['passkey_only'=>true]);
    try {
        $html=$screens->render_shortcode([],null,'azwp_pk_login');
        $assert(!str_contains($html,'name="pwd"')&&str_contains($html,'data-action="login"'),'Passkey only mode shows only the passkey button');
        $assert(in_array('azwp-passkeys-only',apply_filters('login_body_class',[],'login'),true),'Passkey only mode marks the native login page');
    } finally { $storage->save_settings($policy_scope[0],$policy_scope[1],['passkey_only'=>false]); }
    wp_set_current_user($id);
    $assert($screens->render_shortcode([],null,'azwp_pk_login')==='','Login hidden for signed-in reader');
    $assert($screens->render_shortcode(['auto_hide'=>'false'],null,'azwp_pk_login')!=='','Explicit signed-in login remains visible');
    $html=$screens->render_shortcode([],null,'azwp_pk_register');
    $assert(!str_contains($html,'data-field="name"')&&str_contains($html,'data-action="register"'),'Enrollment has an action and no name field');
    $assert(!str_contains($html,'authenticator')&&!str_contains($html,'attachment'),'Enrollment has no removed category controls');
    $profile=$render(fn()=> $screens->render_profile(get_userdata($id)));
    $assert(!str_contains($profile,'<form'),'Profile fragment does not nest a form');
    $assert(str_contains($profile,'Passkey only mode'),'Profile has exact mode label');
    $assert(!str_contains($profile,'data-open="add"'),'Profile panels start closed');
    $_GET['azwp_passkeys_registered']='1';
    $profile_registered=$render(fn()=> $screens->render_profile(get_userdata($id)));
    unset($_GET['azwp_passkeys_registered']);
    $assert(str_contains($profile_registered,'data-open="add"')&&str_contains($profile_registered,'Your account is ready.'),'After-registration marker opens Add passkey on own profile');
    $site=$render(fn()=> $screens->render_site_settings());
    foreach (['require_user_verification','authenticator_attachment','name="logging"','name="terminology"','name="login_identifier"','name="username_free"'] as $removed) $assert(!str_contains($site,$removed),'Site settings excludes '.$removed);
    $assert(str_contains($site,'Passkey Logs'),'Site settings links the Passkey Logs page');
    $assert(str_contains($site,'name="passkey_only"')===!is_multisite()&&!str_contains($site,'Prefer password'),'Passkey only mode is an on/off switch with no sign-in preference');
    $assert(str_contains($site,'name="after_registration"')===!is_multisite(),'After registration is offered only on single-site');
    $logs_page=$render(fn()=> $screens->render_logs());
    $assert(str_contains($logs_page,'name="logging"')&&str_contains($logs_page,'Clear logs'),'The log page owns the logging control and clear action');
    $assert(str_contains($logs_page,'<h1>Passkey Logs</h1>')&&str_contains($logs_page,'scope="col"')&&str_contains($logs_page,'data-log-filter="category"')&&!str_contains($logs_page,'<pre'),'The log page shows a filtered table, not raw entries');
    if (!WP_Block_Type_Registry::get_instance()->is_registered('azwp-passkeys/login')) $screens->register_blocks();
    foreach (['login','register','test','list'] as $kind) $assert(\WP_Block_Type_Registry::get_instance()->is_registered('azwp-passkeys/'.$kind),'Registered block '.$kind);
    $assert(!preg_match('/\b(authenticator|Terminology)\b/',$site.$profile.$logs_page),'No removed jargon in visible generated screens');
    echo "Screens integration: {$checks} checks passed.\n";
} finally {
    wp_set_current_user($actor);
    wp_delete_user($id);
    if ($original===null) delete_option('azwp_passkeys_settings'); else update_option('azwp_passkeys_settings',$original);
}
