/** HTTP boundaries against an explicitly configured disposable localhost installation. */
'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawn } = require('node:child_process');
const post = (url,body) => new Promise((resolve,reject)=>{const request=http.request(url,{method:'POST',headers:{Host:'example.test',Cookie:'azwp_passkeys_browser='+'A'.repeat(43),'Content-Type':'application/x-www-form-urlencoded'}},response=>{let text='';response.on('data',chunk=>text+=chunk);response.on('end',()=>{try{resolve(JSON.parse(text))}catch(error){reject(error)}})});request.on('error',reject);request.end(body.toString());});
const wpEval = code => new Promise((resolve, reject) => { const child = spawn('npx', ['wp-env', 'run', 'tests-cli', 'wp', '--url=' + process.env.TEST_URL, 'eval', code], { stdio: ['ignore', 'pipe', 'pipe'] }); let out = ''; child.stdout.on('data', data => out += data); child.on('close', status => status === 0 ? resolve(out) : reject(Error('wp eval failed'))); });
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
    const events = async () => Number((await wpEval(`global $wpdb; echo 'COUNT '.(int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->base_prefix}azwp_passkeys_events WHERE site_id=%d", get_current_blog_id()));`)).match(/COUNT (\d+)/)[1]);
    const ajax = (action, payload, cookie) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(cookie ? { Cookie: cookie } : {}) }, body: new URLSearchParams({ action: 'azwp_passkeys_' + action, payload: JSON.stringify(payload) }) });
    const before = await events();
    const unmatched = { attempt_id: 'A'.repeat(43), credential: {} };
    for (const [action, payload] of [['login_complete', {}], ['login_complete', unmatched], ['setup_complete', { token: 'A'.repeat(43), ...unmatched }]]) {
        const response = await ajax(action, payload);
        assert.ok(response.status >= 400, action + ' with no issued attempt fails');
    }
    assert.equal(await events(), before, 'Completions that match no issued attempt write no log row');
    const options = await ajax('login_options', { remember: false, redirect_to: '', surface: 'native' });
    const browser = options.headers.get('set-cookie').match(/azwp_passkeys_browser=[^;]+/)[0];
    const { data: issued } = await options.json();
    assert.equal((await ajax('login_complete', { attempt_id: issued.attempt_id, credential: { rawId: '!' } }, browser)).status, 400);
    assert.equal(await events(), before + 1, 'A failure on an issued attempt is still logged');
    console.log('HTTP: unmatched completions are not logged.');
    const seeded = (await wpEval(`
        global $wpdb; $table = $wpdb->base_prefix.'azwp_passkeys_events'; $site = get_current_blog_id();
        $wpdb->delete($table, ['site_id'=>$site]);
        $storage = new AZWP\\Passkeys\\Storage($wpdb);
        for ($i = 0; $i < 21; $i++) {
            $ok = $i % 7 !== 0 && $i < 18;
            $storage->insert_event(['site_id'=>$site,'occurred_at'=>time(),'event'=>$ok ? 'passkey.tested' : 'signin.passkey','ok'=>(int) $ok,'code'=>$ok ? 'ok' : 'authentication_failed','correlation_id'=>bin2hex(random_bytes(16)),'actor_id'=>$ok ? 1 : null,'actor_login'=>$ok ? 'admin' : null,'passkey_id'=>$ok ? 5 : null,'passkey_name'=>$ok ? 'Work phone' : null,'passkey_aaguid'=>$ok ? str_repeat("\\0", 16) : null,'data'=>null]);
        }
        $token = WP_Session_Tokens::get_instance(1)->create(time() + 600);
        $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie(1, time() + 600, 'logged_in', $token);
        wp_set_current_user(1);
        echo 'SEED '.json_encode(['cookie'=>AUTH_COOKIE.'='.rawurlencode(wp_generate_auth_cookie(1, time() + 600, 'auth', $token)).'; '.LOGGED_IN_COOKIE.'='.rawurlencode($_COOKIE[LOGGED_IN_COOKIE]),'nonce'=>wp_create_nonce('azwp_passkeys_logs_'.$site)]);
    `)).match(/SEED (\{.*\})/);
    assert.ok(seeded, 'Seeded 21 log entries and an administrator session');
    const { cookie, nonce } = JSON.parse(seeded[1]);
    const read = async (payload, signedIn = true) => {
        const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(signedIn ? { Cookie: cookie } : {}) }, body: new URLSearchParams({ action: 'azwp_passkeys_log_read', payload: JSON.stringify(payload), _ajax_nonce: nonce }) });
        return { status: response.status, body: await response.json() };
    };
    try {
        const all = (await read({})).body.data;
        assert.equal(all.total, 21, 'Every entry is counted');
        assert.equal(all.matched, 21);
        assert.equal(all.per_page, 20);
        assert.equal(all.total_pages, 2, '21 entries give 2 pages');
        assert.equal(all.entries.length, 20, 'A page holds 20 entries');
        assert.ok(all.entries.every((entry, index) => index === 0 || entry.id < all.entries[index - 1].id), 'Entries are newest first');
        const tested = all.entries.find(entry => entry.event === 'passkey.tested');
        assert.deepEqual([tested.category, tested.action, tested.user, tested.details], ['Passkey', 'Tested', 'admin', 'Work phone: tested']);
        assert.equal(typeof tested.time, 'string');
        assert.equal(tested.ip, '—', 'An entry with no IP address shows —');
        for (const hidden of ['data', 'passkey_aaguid', 'actor_login', 'target_login', 'passkey_name']) assert.ok(!(hidden in tested), 'No raw ' + hidden + ' in the response');
        const second = (await read({ paged: 2 })).body.data;
        assert.equal(second.paged, 2);
        assert.equal(second.entries.length, 1, 'Page 2 holds the oldest entry');
        assert.ok(second.entries[0].id < all.entries.at(-1).id);
        const past = (await read({ paged: 9 })).body.data;
        assert.equal(past.paged, 2, 'A page past the end returns the last page');
        const signin = (await read({ category: 'signin' })).body.data;
        assert.equal(signin.matched, 6, 'Category filter matches its events');
        assert.ok(signin.entries.every(entry => entry.event === 'signin.passkey' && entry.user === '—' && entry.details === 'Sign-in failed: passkey not recognized'));
        assert.equal((await read({ ok: true })).body.data.matched, 15, 'Result filter matches successes');
        assert.equal((await read({ ok: false })).body.data.matched, 6, 'Result filter matches failures');
        const none = (await read({ category: 'passkey', ok: false })).body.data;
        assert.deepEqual([none.matched, none.total, none.total_pages, none.paged, none.entries.length], [0, 21, 1, 1, 0], 'No match gives one empty page');
        const unknown = await read({ category: 'password' });
        assert.equal(unknown.status, 400, 'An unknown category is rejected');
        assert.equal(unknown.body.data.code, 'invalid_request');
        assert.equal((await read({}, false)).status, 403, 'Signed-out readers are refused');
        console.log('HTTP: log_read paging, filters and access checks passed.');
    } finally {
        await wpEval(`global $wpdb; $wpdb->delete($wpdb->base_prefix.'azwp_passkeys_events', ['site_id'=>get_current_blog_id()]);`);
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
