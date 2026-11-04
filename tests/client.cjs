/* Pure serialization/transport checks. No browser, server or real credentials. */
'use strict';
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
let options,fetchArgs,fail=false;
const bytes=Uint8Array.from([0,255,128]);
const registration={id:'AP-A',rawId:bytes.buffer,type:'public-key',response:{clientDataJSON:bytes.buffer,attestationObject:bytes.buffer,getTransports:()=>['internal','hybrid']},getClientExtensionResults:()=>({credProps:{rk:true}})};
const assertion={...registration,response:{clientDataJSON:bytes.buffer,authenticatorData:bytes.buffer,signature:bytes.buffer,userHandle:null}};
const context={window:{azwpPasskeysConfig:{ajax_url:'/wp-admin/admin-ajax.php',server_ready:true},isSecureContext:true,PublicKeyCredential:function(){}},document:{readyState:'loading',addEventListener:()=>{},querySelectorAll:()=>[],querySelector:()=>null},navigator:{credentials:{create:async x=>(options=x,registration),get:async x=>(options=x,assertion)}},wp:{i18n:{__:s=>s,sprintf:(s,x)=>s.replace('%s',x)}},Uint8Array,URLSearchParams,AbortController,atob,btoa,fetch:async(...args)=>{fetchArgs=args;if(fail)throw new Error('offline');return{json:async()=>({success:true,data:{saved:true}})}}};
vm.runInNewContext(fs.readFileSync(require('node:path').join(__dirname,'../assets/js/client.js'),'utf8'),context);
(async()=>{
 const api=context.window.azwpPasskeys;
 const created=await api.createCredential({challenge:'AP-A',user:{id:'AP-A'},excludeCredentials:[{type:'public-key',id:'AP-A'}],authenticatorSelection:{userVerification:'required'}});
 assert.deepEqual(Array.from(options.publicKey.challenge),[0,255,128]);assert.deepEqual(Array.from(options.publicKey.user.id),[0,255,128]);assert.equal(options.publicKey.authenticatorSelection.userVerification,'required');assert.equal(created.rawId,'AP-A');assert.equal(created.response.attestationObject,'AP-A');assert.deepEqual(created.response.transports,['internal','hybrid']);
 const response=await api.getAssertion({challenge:'AP-A',allowCredentials:[]});
 assert.equal(Object.hasOwn(options,'mediation'),false);assert.equal(options.publicKey.allowCredentials.length,0);assert.equal(options.publicKey.userVerification,'required');assert.equal(response.response.userHandle,null);assert.equal(response.response.signature,'AP-A');
 await api.getAssertion({challenge:'AP-A'});assert.equal(Object.hasOwn(options.publicKey,'allowCredentials'),false);
 await api.requestAction('rename',{record_id:'123'},'nonce');assert.equal(fetchArgs[1].credentials,'same-origin');assert.equal(fetchArgs[1].body.get('_ajax_nonce'),'nonce');assert.equal(fetchArgs[1].body.get('action'),'azwp_passkeys_rename');assert.equal(JSON.parse(fetchArgs[1].body.get('payload')).record_id,'123');
 fail=true;await assert.rejects(api.requestAction('register_finish',{},'',true),e=>e.retry==='uncertain');await assert.rejects(api.requestAction('register_start'),e=>e.retry==='fresh_attempt');
 console.log('Client: binary registration/assertion, UV, omitted/empty allowlist, nonce, and uncertain-network checks passed.');
})().catch(error=>{console.error(error);process.exitCode=1});
