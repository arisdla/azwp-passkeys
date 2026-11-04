/** HTTP boundaries against an explicitly configured disposable localhost installation. */
'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const post = (url,body) => new Promise((resolve,reject)=>{const request=http.request(url,{method:'POST',headers:{Host:'example.test',Cookie:'azwp_passkeys_browser='+'A'.repeat(43),'Content-Type':'application/x-www-form-urlencoded'}},response=>{let text='';response.on('data',chunk=>text+=chunk);response.on('end',()=>{try{resolve(JSON.parse(text))}catch(error){reject(error)}})});request.on('error',reject);request.end(body.toString());});
if (process.env.AZWP_PASSKEYS_TESTS !== '1' || !process.env.TEST_URL || new URL(process.env.TEST_URL).hostname !== 'localhost') throw Error('Disposable localhost test target required');
(async () => {
    const url = process.env.TEST_URL + '/wp-admin/admin-ajax.php';
    for (const action of ['login_options', 'login_complete']) {
        const payload = action === 'login_options' ? { remember: false, redirect_to: '', surface: 'native' } : { attempt_id: 'A'.repeat(43), credential: {} };
        const result = await post(url,new URLSearchParams({ action: 'azwp_passkeys_' + action, payload: JSON.stringify(payload) }));
        assert.equal(result.success, false);
        assert.equal(result.data.code, 'invalid_request', 'Insecure non-local ceremony rejected even with existing cookie');
    }
    const response = await fetch(url + '?action=azwp_passkeys_login_options');
    assert.equal((await response.json()).data.code, 'invalid_request', 'Options require POST');
    console.log('HTTP: 3 transport/method boundary checks passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
