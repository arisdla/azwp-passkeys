<?php
/** Real concurrent storage/coordinator checks; disposable database only. */
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true) { throw new RuntimeException('A disposable WordPress test bootstrap is required.'); }
if (!function_exists('pcntl_fork') || !function_exists('posix_kill')) { throw new RuntimeException('Concurrency tests require test-only pcntl and posix support.'); }
require_once dirname(__DIR__) . '/autoload.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
if (is_multisite()) { require_once ABSPATH . 'wp-admin/includes/ms.php'; }
use AZWP\Passkeys\{Storage,Settings,Passkeys,WebAuthn,Logs};
$checks=0;
$assert=static function(bool $ok,string $label) use (&$checks):void { if(!$ok){throw new RuntimeException($label);} ++$checks; };
$wait=static function(string $path):void { $end=microtime(true)+8; while(!is_file($path)){if(microtime(true)>$end){throw new RuntimeException('Worker barrier timed out');} usleep(10000);} };
$directory=sys_get_temp_dir().'/azwp-concurrency-'.bin2hex(random_bytes(8));
if(!mkdir($directory,0700)){throw new RuntimeException('Cannot create test barriers');}
$wpdb=$GLOBALS['wpdb']; $site=get_current_blog_id(); $base=$wpdb->base_prefix;
$storage=new Storage($wpdb); $settings=new Settings($storage,new Logs($storage)); $passkeys=new Passkeys($settings,$storage,new WebAuthn());
$storage->install_schema();
$user=wp_insert_user(['user_login'=>'azwp_race_'.bin2hex(random_bytes(6)),'user_pass'=>wp_generate_password(),'role'=>'administrator']);
if(is_wp_error($user)){throw new RuntimeException('Test account creation failed');}
$original_user=get_current_user_id(); wp_set_current_user($user);
$original_site_settings=get_option('azwp_passkeys_settings',null);
$original_network_settings=is_multisite()?get_network_option(get_current_network_id(),'azwp_passkeys_network_settings',null):null;
$context=['site_id'=>$site,'actor_id'=>$user,'session_hash'=>hash('sha256',wp_get_session_token(),true)];
$config=$passkeys->configuration($site);
if(!$config['ok']){wp_delete_user($user);rmdir($directory);throw new RuntimeException('Concurrency fixture requires a valid site RP/origin configuration');}
$row=['user_id'=>$user,'site_id'=>$site,'credential_id'=>random_bytes(64),'rp_id'=>$config['data']['rp_id'],'public_key_pem'=>'validated fixture','public_key_cose'=>"\xa1\x01\x02",'credential_type'=>'public-key','attestation_type'=>'none','trust_path'=>[],'aaguid'=>random_bytes(16),'other_ui'=>null,'algorithm'=>-7,'sign_count'=>0,'backup_eligible'=>false,'backed_up'=>false,'transports'=>[],'name'=>'Concurrency fixture','created_at'=>time(),'created_local'=>current_time('mysql'),'last_used_local'=>null];
$insert=static function()use($storage,$row,$user):array { $record=$row; $record['credential_id']=random_bytes(64);$result=$storage->with_owner_lock($user,static fn(Storage $s):array=>$s->insert_credential($record));if(!$result['ok']){throw new RuntimeException('Fixture insertion failed');}return $result['data']['credential']; };
// Close before fork: neither child inherits a live database socket. Each child
// creates a separate wpdb; parent reconnects its original object after joining.
$pair=static function(string $name,array $jobs)use($wpdb,$base,$site,$directory,$wait):array {
    $run=$directory.'/'.$name;mkdir($run,0700);$pids=[];$wpdb->close();
    try {
        foreach($jobs as $index=>$job){
            $pid=pcntl_fork();if($pid<0){throw new RuntimeException('fork failed');}
            if($pid===0){
                // Discard inherited output buffers; workers report only result metadata.
                while (ob_get_level() > 0) { ob_end_clean(); }
                try {
                    $db=new wpdb(DB_USER,DB_PASSWORD,DB_NAME,DB_HOST);$db->set_prefix($base);$db->set_blog_id($site);$GLOBALS['wpdb']=$db;
                    $s=new Storage($db);$p=new Passkeys(new Settings($s,new Logs($s)),$s,new WebAuthn());
                    touch($run.'/ready'.$index);$wait($run.'/ready'.(1-$index));
                    $result=$job($s,$p,$db,$run,$wait);
                    file_put_contents($run.'/result'.$index,json_encode(['ok'=>(bool)($result['ok']??false),'code'=>(string)($result['code']??'invalid_result'),'invalid'=>$result['data']['invalid']??[]],JSON_THROW_ON_ERROR));exit(0);
                }catch(Throwable $e){file_put_contents($run.'/result'.$index,json_encode(['worker_error'=>$e->getMessage()]));exit(1);}
            }
            $pids[]=$pid;
        }
        $end=microtime(true)+12;$statuses=[];
        while(count($statuses)<count($pids)){
            foreach($pids as $pid){if(isset($statuses[$pid])){continue;}$done=pcntl_waitpid($pid,$status,WNOHANG);if($done===$pid){$statuses[$pid]=$status;}}
            if(microtime(true)>$end){throw new RuntimeException('Concurrent workers timed out');}usleep(10000);
        }
        $results=[];foreach([0,1] as $index){$results[]=json_decode(file_get_contents($run.'/result'.$index),true,512,JSON_THROW_ON_ERROR);}
        foreach($results as $result){if(isset($result['worker_error'])){throw new RuntimeException($result['worker_error']);}}
        foreach($statuses as $status){if(!pcntl_wifexited($status)||pcntl_wexitstatus($status)!==0){throw new RuntimeException('Worker failed');}}
        return $results;
    }finally{
        foreach($pids as $pid){if(pcntl_waitpid($pid,$status,WNOHANG)===0){posix_kill($pid,SIGKILL);pcntl_waitpid($pid,$status);}}
        $wpdb->db_connect();$GLOBALS['wpdb']=$wpdb;
        foreach(glob($run.'/*')?:[] as $file){unlink($file);}rmdir($run);
    }
};
$proof=static function(array $record)use($context,$config,$user):array {return $context+['purpose'=>'test','target_id'=>$user,'owner_id'=>$user,'record_id'=>$record['id'],'issued_options'=>['rp_id'=>$config['data']['rp_id'],'origins'=>$config['data']['origins'],'remember'=>false],'credential_id'=>$record['credential_id'],'rp_id'=>$record['rp_id'],'public_key_cose'=>$record['public_key_cose'],'public_key_pem'=>$record['public_key_pem'],'sign_count'=>1,'backup_eligible'=>false,'backed_up'=>false];};
// A test-only outer advisory-lock acquisition fixes the ordering while both
// real coordinator calls run on independent connections. Reentrant GET_LOCK
// preserves production transaction behavior; the outer reference is released.
$ordered=static function(callable $first,callable $second)use($base):array {
    $lock='azwp-passkeys:'.substr(hash('sha256',DB_NAME.':'.$base),0,32);
    return [static function($s,$p,$db,$run,$wait)use($first,$lock){
        if((string)$db->get_var($db->prepare('SELECT GET_LOCK(%s,2)',$lock))!=='1'){throw new RuntimeException('Test ordering lock unavailable');}
        try{touch($run.'/held');$wait($run.'/second');usleep(100000);return $first($s,$p);}finally{$db->get_var($db->prepare('SELECT RELEASE_LOCK(%s)',$lock));}
    },static function($s,$p,$db,$run,$wait)use($second){$wait($run.'/held');touch($run.'/second');return $second($s,$p);}];
};
try {
    $bytes=random_bytes(32);$attempt=WebAuthn::encode($bytes);$binding=['site_id'=>$site,'purpose'=>'login','actor_id'=>0,'browser_hash'=>random_bytes(32),'session_hash'=>null];
    $created=$storage->create_attempt(['id'=>$bytes,'site_id'=>$site,'purpose'=>'login','actor_id'=>null,'target_id'=>$user,'browser_hash'=>$binding['browser_hash'],'session_hash'=>null,'challenge'=>random_bytes(32),'issued'=>[],'created_at'=>time(),'expires_at'=>time()+90]);$assert($created['ok'],'Attempt fixture created');
    $job=static fn(Storage $s):array=>$s->claim_attempt($attempt,$binding);
    $results=$pair('claim',[$job,$job]);$assert(count(array_filter($results,static fn($r)=>$r['ok']))===1,'Exactly one simultaneous claim succeeds');
    $assert(count(array_filter($results,static fn($r)=>$r['code']==='attempt_unavailable'))===1,'Other claim rejects replay');$storage->delete_attempt($attempt);
    // Proof fixtures represent the already-verified private boundary, not a
    // browser/signature test. Real accept_assertion performs final checks/writes.
    $record=$insert();$verified=$proof($record);
    $remove=static fn($s,$p)=>$p->remove_credential($context,$user,$record['id']);$accept=static fn($s,$p)=>$p->accept_assertion($verified);
    $results=$pair('revoke-first',$ordered($remove,$accept));
    $assert($results[0]['ok']&&!$results[1]['ok']&&$results[1]['code']==='authentication_failed','Revocation before final acceptance rejects assertion');
    $record=$insert();$verified=$proof($record);
    $remove=static fn($s,$p)=>$p->remove_credential($context,$user,$record['id']);$accept=static fn($s,$p)=>$p->accept_assertion($verified);
    $results=$pair('accept-first',$ordered($accept,$remove));
    $assert($results[0]['ok']&&$results[1]['ok'],'Acceptance before revocation remains successful');
    $assert($storage->get_credential($record['id'])['data']['credential']===null,'Later revocation removes stored credential');
    $one=$insert();$two=$insert();$assert($storage->save_password_policy($user,true)['ok'],'Passkey-only account fixture saved');
    $results=$pair('last-method',[static fn($s,$p)=>$p->remove_credential($context,$user,$one['id']),static fn($s,$p)=>$p->remove_credential($context,$user,$two['id'])]);
    $assert(count(array_filter($results,static fn($r)=>$r['ok']))===1,'Only one of two concurrent removals succeeds');
    $assert(count(array_filter($results,static fn($r)=>$r['code']==='access_required'))===1,'Second removal protects remaining sign-in method');
    $remaining=$storage->get_credentials($user)['data']['credentials'];
    $assert(count($remaining)===1,'One usable credential remains stored');

    $network=is_multisite();
    if ($network) { $assert(grant_super_admin($user),'Grant network options to the disposable administrator'); }
    $form=$network?'network':'site';
    $scope_id=$network?get_current_network_id():$site;
    $assert($storage->save_password_policy($user,false)['ok'],'Allow password sign-in for the settings races');
    $assert($storage->save_settings($form,$scope_id,['passkey_only'=>false])['ok'],'Start settings races with the mode off');
    $site_fields=['rp_id'=>$config['data']['rp_id'],'rp_name'=>$config['data']['rp_name'],'remember_login'=>'0','reset_restriction'=>'off','after_registration'=>'default'];
    $enable_input=($network?[]:$site_fields)+['passkey_only'=>'1','passkey_only_confirmed'=>Passkeys::readiness_token($passkeys->readiness($network))];
    $enable=static fn($s,$p)=>$p->save_settings_form($form,$enable_input);
    $remove=static fn($s,$p)=>$p->remove_credential($context,$user,$remaining[0]['id']);
    $results=$pair('settings-remove-first',$ordered($remove,$enable));
    $assert($results[0]['ok']&&!$results[1]['ok']&&$results[1]['invalid']===['passkey_only'],'Removing the last key first rejects concurrent mode enable');
    $assert(!$settings->get_effective($site)['passkey_only'],'Mode remains off after the failed enable');

    $replacement=$insert();
    $remove=static fn($s,$p)=>$p->remove_credential($context,$user,$replacement['id']);
    $results=$pair('settings-enable-first',$ordered($enable,$remove));
    $assert($results[0]['ok']&&!$results[1]['ok']&&$results[1]['code']==='access_required','Enabling the mode first protects the last key from concurrent removal');
    $assert($storage->save_settings($form,$scope_id,['passkey_only'=>false])['ok'],'Restore passwords before the domain race');

    $new_rp=$site_fields['rp_id']==='example.org'?'example.net':'example.org';
    $change_rp=static fn($s,$p)=>$p->save_settings_form('site',array_replace($site_fields,['rp_id'=>$new_rp,'passkey_only'=>'0']));
    $results=$pair('settings-domain-first',$ordered($change_rp,$enable));
    $after=$settings->get_effective($site);
    $expected_invalid=$network?['passkey_only']:['rp_id','passkey_only_locked'];
    $assert($results[0]['ok']&&!$results[1]['ok']&&$results[1]['invalid']===$expected_invalid,'Changing the domain first rejects concurrent mode enable using the stale domain');
    $assert(!$after['passkey_only']&&$after['rp_id']===$new_rp,'The mode stays off with the changed domain');
    $assert($storage->save_settings('site',$site,['rp_id'=>$site_fields['rp_id']])['ok'],'Restore domain for the rate test');

    $original_address=$_SERVER['REMOTE_ADDR']??null;$_SERVER['REMOTE_ADDR']='203.0.113.'.random_int(1,254);
    $anonymous=['site_id'=>$site,'actor_id'=>0,'browser_hash'=>random_bytes(32),'session_hash'=>null,'purpose'=>'login'];$login=['remember'=>false,'redirect_to'=>'','surface'=>'native'];
    try {
        for($i=1;$i<Passkeys::ANONYMOUS_ATTEMPTS_PER_MINUTE;$i++){$issued=$passkeys->assertion_options($anonymous,$login);$assert($issued['ok'],'Rate fixture below the limit');$storage->delete_attempt($issued['data']['attempt_id']);}
        // Forked workers inherit this process's object cache; each must read the counter from the database.
        // The delay holds both workers between reading and writing the counter, so an unlocked counter always races.
        $job=static function($s,$p)use($anonymous,$login):array{
            wp_cache_flush();
            add_filter('pre_option',static function($pre,$option){if(str_starts_with($option,'_transient_azwp_passkeys_rate_')){usleep(200000);}return $pre;},10,2);
            return $p->assertion_options($anonymous,$login);
        };
        $results=$pair('rate',[$job,$job]);
        $assert(count(array_filter($results,static fn($r)=>$r['ok']))===1,'Only one concurrent request takes the last anonymous slot');
        $assert(count(array_filter($results,static fn($r)=>$r['code']==='rate_limited'))===1,'Other concurrent request is rate limited');
    } finally {
        if($original_address===null){unset($_SERVER['REMOTE_ADDR']);}else{$_SERVER['REMOTE_ADDR']=$original_address;}
        $storage->delete_rate_limits($site);
    }
    echo "Concurrency integration: $checks checks passed.\n";
}finally{
    if ($original_site_settings===null) { delete_option('azwp_passkeys_settings'); }
    else { update_option('azwp_passkeys_settings',$original_site_settings); }
    if (is_multisite()) {
        if ($original_network_settings===null) { delete_network_option(get_current_network_id(),'azwp_passkeys_network_settings'); }
        else { update_network_option(get_current_network_id(),'azwp_passkeys_network_settings',$original_network_settings); }
        revoke_super_admin($user);
    }
    $storage->cleanup_user($user);
    if (is_multisite()) { wpmu_delete_user($user); } else { wp_delete_user($user); }
    wp_set_current_user($original_user);
    foreach(glob($directory.'/*')?:[] as $file){if(is_file($file)){unlink($file);}}rmdir($directory);
}
