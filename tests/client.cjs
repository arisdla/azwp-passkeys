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

const nodes=[];
class Node {
 constructor(tag='div'){this.tagName=tag;this.dataset={};this.children=[];this.disabled=false;this.value='';this.rows=[];this.tBodies=[];this.tHead={rows:[],replaceChildren(){this.rows=[];},append(n){this.rows.push(n);}};this.tFoot={rows:[],replaceChildren(){this.rows=[];},append(n){this.rows.push(n);}};nodes.push(this);}
 append(...nodes){this.children.push(...nodes);} appendChild(n){this.append(n);return n;}
 replaceChildren(...nodes){this.children=nodes;this.rows=[];}
 insertRow(){const r=new Node('tr');r.cells=[];r.insertCell=()=>{const c=new Node('td');r.cells.push(c);return c;};this.rows.push(r);return r;}
 setAttribute(){} classList={toggle(){}};
}
const roots=[];
const domDocument={readyState:'loading',addEventListener(){},querySelectorAll(selector){return selector==='[data-azwp-passkeys="list"]'?roots:selector.includes('[data-action=')?nodes.filter(node=>node.dataset.action):[];},querySelector(selector){return selector==='[data-field="redirect_to"]'?{value:'https://front.example/after'}:null;},createElement(tag){return new Node(tag);},createTextNode(text){const n=new Node('#text');n.textContent=text;return n;}};
let loginPayload;
const domContext={...context,window:{azwpPasskeysConfig:context.window.azwpPasskeysConfig,isSecureContext:true,PublicKeyCredential:function(){},location:{assign(){}},setTimeout(fn){fn();}},document:domDocument,navigator:{credentials:{get:async()=>assertion,create:async()=>registration}},fetch:async(_url,init)=>{const body=init.body;const action=body.get('action');if(action.endsWith('_options'))loginPayload=JSON.parse(body.get('payload'));return{json:async()=>({success:true,data:action.endsWith('_options')?{attempt_id:'a',publicKey:{challenge:'AP-A'}}:{redirect_to:'https://front.example/after'}})};}};
vm.runInNewContext(fs.readFileSync(require('node:path').join(__dirname,'../assets/js/client.js'),'utf8'),domContext);
(async()=>{
 const api=domContext.window.azwpPasskeys;
 const loginRoot={dataset:{surface:'frontend'},querySelector(selector){if(selector==='[data-field="redirect_to"]')return{value:'https://front.example/second'};return new Node();},closest(){return null;}};
 await api.ceremony(loginRoot,'login');
 assert.equal(loginPayload.redirect_to,'https://front.example/second','frontend login uses the clicked component destination');
 const table=new Node('table');table.tBodies=[new Node('tbody')];
 const listRoot={dataset:{canManage:'1',target:'1',nonce:''},querySelector(){return table;}};roots.push(listRoot);
 domContext.fetch=async()=>({json:async()=>({success:true,data:{credentials:[{record_id:1,name:'policy-locked',can_rename:true,can_remove:false,authenticator:'Key',created_local:'today'}]}})});
 await api.refreshCredentialList(listRoot);
 let remove=table.tBodies[0].rows[0].cells[4].children[0];
 assert.equal(remove.disabled,true,'can_remove=false disables Remove');
 api.setPagePending(true);
 await api.refreshCredentialList(listRoot);
 remove=table.tBodies[0].rows[0].cells[4].children[0];
 assert.equal(remove.disabled,true,'refresh during pending preserves policy-disabled Remove');
 api.setPagePending(false);
 assert.equal(remove.disabled,true,'pending restoration preserves policy-disabled Remove');
 assert.equal(table.tBodies[0].rows[0].cells[0].children[1].children[0].disabled,false,'pending restoration re-enables a newly rendered permitted Rename');
 console.log('Client: frontend redirect and policy-disabled Remove behavior passed.');
})().catch(error=>{console.error(error);process.exitCode=1});
