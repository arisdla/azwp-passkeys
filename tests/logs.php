<?php
/** Event registry, log writer, reader and eraser. Only for a disposable WordPress database. */
if (!defined('ABSPATH') || !defined('AZWP_PASSKEYS_TESTS') || AZWP_PASSKEYS_TESTS !== true) {
    throw new RuntimeException('A disposable WordPress test bootstrap is required.');
}
require_once dirname(__DIR__) . '/autoload.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
use AZWP\Passkeys\{Storage, Settings, Logs, Events};

$checks = 0;
$assert = static function (bool $condition, string $label) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($label); }
    ++$checks;
};
$wpdb = $GLOBALS['wpdb'];
$storage = new Storage($wpdb);
$logs = new Logs($storage);
$settings = new Settings($storage, $logs);
$assert($storage->install_schema()['ok'], 'Schema installs');
$table = $wpdb->base_prefix . 'azwp_passkeys_events';
$site = (int) get_current_blog_id();
$original_settings = get_option('azwp_passkeys_settings', null);
$users = [];
$correlations = [];
$by_correlation = static fn(string $correlation): ?array => $wpdb->get_row($wpdb->prepare("SELECT * FROM `$table` WHERE correlation_id=%s", $correlation), ARRAY_A);
$record = static function (string $event, array $fields) use ($logs, &$correlations): string {
    $correlations[] = $correlation = bin2hex(random_bytes(16));
    $logs->record($event, ['enabled' => true, 'correlation_id' => $correlation] + $fields);
    return $correlation;
};
try {
    $sample = ['ok' => true, 'code' => 'ok', 'actor_id' => 1, 'actor_login' => 'admin', 'target_id' => 2, 'target_login' => 'marie', 'passkey_id' => 3, 'passkey_name' => 'Phone', 'passkey_aaguid' => null, 'data' => []];
    $categories = Events::categories();
    foreach (Events::all() as $key => $definition) {
        $assert(isset($categories[$definition['category']]) && str_starts_with($key, $definition['category'] . '.'), "$key has a defined category");
        $assert(in_array($definition['user'], ['actor', 'verified', 'system'], true), "$key has a user rule");
        foreach ($definition['personal'] as $field => $owner) {
            $assert(isset($definition['data'][$field]) && in_array($owner, ['target', 'actor'], true), "$key personal key $field is declared with an owner");
        }
        foreach ([$sample, ['ok' => false, 'code' => 'forbidden'] + $sample, ['passkey_name' => null, 'target_id' => null] + $sample, ['ok' => false, 'code' => 'mail_failed', 'passkey_name' => null, 'target_login' => null] + $sample] as $row) {
            $assert(is_string(($definition['details'])($row)), "$key details is a string for every row shape");
        }
    }
    $details = static fn(string $event, array $row = []): string => (Events::all()[$event]['details'])($row + $sample);
    $assert($details('passkey.tested', ['actor_id' => 1, 'target_id' => 2]) === 'Phone: tested for marie', 'Acting on another account follows the action');
    $assert($details('passkey.deleted', ['ok' => false, 'code' => 'access_required']) === 'Phone deletion failed for marie: would leave the account without a way to sign in', 'A failure for another account follows the verb');
    $assert($details('passkey.deleted', ['ok' => false, 'code' => 'odd_new_code', 'target_id' => 1]) === 'Phone deletion failed: odd new code', 'An unknown code reads as words');
    $assert($details('passkey.renamed', ['target_id' => 1, 'data' => ['previous_name' => 'Old']]) === 'Old: renamed to Phone', 'Rename reads previous name to new name');
    $assert($details('passkey.account_deleted', ['data' => ['count' => 1]]) === 'User #2 (marie) deleted with 1 passkey', 'One passkey is singular');
    $assert($details('passkey.account_deleted', ['target_login' => null, 'data' => ['count' => 2]]) === 'User #2 deleted with 2 passkeys', 'A missing login shows the ID alone');
    $assert($details('settings.changed', ['data' => ['setting' => 'logging', 'previous' => false, 'value' => true]]) === 'Logging turned on', 'Boolean settings turn on or off');
    $assert($details('settings.changed', ['data' => ['setting' => 'reset_restriction', 'previous' => 'off', 'value' => 'everyone']]) === 'Block password resets changed: No → For everyone', 'Choice settings show their labels');
    $assert($details('settings.changed', ['data' => ['setting' => 'related_origins', 'previous' => [], 'value' => ['https://a.test', 'https://b.test']]]) === 'Related origins changed: — → https://a.test, https://b.test', 'List settings join their items');
    $assert($details('signin.passkey', ['ok' => false, 'code' => 'authentication_failed', 'passkey_name' => null]) === 'Sign-in failed: passkey not recognized', 'Unknown passkey sign-in failure');

    $settings->save_logs(['logging' => '0']);
    $start = (int) $wpdb->get_var("SELECT COALESCE(MAX(id),0) FROM `$table`");
    $since = static fn(): array => $wpdb->get_results($wpdb->prepare("SELECT * FROM `$table` WHERE id>%d ORDER BY id", $start), ARRAY_A);
    $logs->record('passkey.tested', ['actor_id' => 1]);
    $assert($since() === [], 'Nothing is written while logging is off');
    $settings->save_logs(['logging' => '1']);
    $rows = $since();
    $assert(count($rows) === 1 && $rows[0]['event'] === 'settings.changed' && json_decode($rows[0]['data'], true) === ['setting' => 'logging', 'previous' => false, 'value' => true], 'Turning logging on writes one row');
    $settings->save_logs(['logging' => '1']);
    $assert(count($since()) === 1, 'A save that changes nothing writes no row');
    $settings->save_logs(['logging' => '0']);
    $rows = $since();
    $assert(count($rows) === 2 && json_decode($rows[1]['data'], true)['value'] === false, 'Turning logging off writes one row, because logging was on before the save');
    $wpdb->query($wpdb->prepare("DELETE FROM `$table` WHERE id>%d", $start));
    $stored = get_option('azwp_passkeys_settings', []);
    unset($stored['logging']);
    update_option('azwp_passkeys_settings', $stored, false);
    $assert($settings->get_site($site)['logging'] === true, 'Logging is on by default');
    $logs->record('passkey.tested', ['actor_id' => 1]);
    $assert(count($since()) === 1, 'A site with no stored Logging value logs');
    $wpdb->query($wpdb->prepare("DELETE FROM `$table` WHERE id>%d", $start));

    $unknown = $record('password.signin', ['actor_id' => 1]);
    $assert($by_correlation($unknown) === null, 'An unknown event is dropped');
    $typed = $record('passkey.renamed', ['actor_id' => 1, 'target_id' => 1, 'passkey' => ['id' => 5, 'name' => 'token=abc', 'aaguid' => str_repeat("\1", 16)], 'data' => ['previous_name' => 42, 'password' => 'secret']]);
    $row = $by_correlation($typed);
    $assert($row !== null && $row['data'] === null, 'An undeclared data key and a wrong-typed value are dropped');
    $assert($row['passkey_name'] === '[redacted]', 'A secret-looking passkey name is redacted');
    $original_address = $_SERVER['REMOTE_ADDR'] ?? null;
    $_SERVER['REMOTE_ADDR'] = '2001:db8::7';
    $with_ip = $record('passkey.tested', ['actor_id' => 1]);
    $_SERVER['REMOTE_ADDR'] = 'not an address';
    $bad_ip = $record('passkey.tested', ['actor_id' => 1]);
    if ($original_address === null) { unset($_SERVER['REMOTE_ADDR']); } else { $_SERVER['REMOTE_ADDR'] = $original_address; }
    $assert($by_correlation($with_ip)['ip'] === '2001:db8::7' && $by_correlation($bad_ip)['ip'] === null, 'The request IP address is stored, and an invalid one is not');
    $no_passkey = $record('admin.setup_link', ['actor_id' => 1, 'target_id' => 1, 'passkey' => ['id' => 5, 'name' => 'Phone']]);
    $assert($by_correlation($no_passkey)['passkey_name'] === null, 'Events without passkey columns store none');
    $long = $record('passkey.renamed', ['actor_id' => 1, 'passkey' => ['id' => 5, 'name' => str_repeat('n', 300)], 'data' => ['previous_name' => str_repeat('p', 600)]]);
    $row = $by_correlation($long);
    $assert(strlen($row['passkey_name']) === 255 && strlen(json_decode($row['data'], true)['previous_name']) === 500, 'Names are cut at 255 and data strings at 500');

    $retired = bin2hex(random_bytes(16));
    $correlations[] = $retired;
    $storage->insert_event(['site_id' => $site, 'occurred_at' => time(), 'event' => 'legacy.gone', 'ok' => 0, 'code' => 'storage_failed', 'correlation_id' => $retired, 'actor_id' => null, 'target_id' => 7, 'target_login' => 'kept']);
    $read = $logs->read($site, []);
    $entry = null;
    foreach ($read['data']['entries'] ?? [] as $candidate) { if ($candidate['correlation_id'] === $retired) { $entry = $candidate; } }
    $assert($entry !== null && $entry['category'] === '' && $entry['action'] === 'legacy.gone' && $entry['details'] === 'storage_failed' && $entry['user'] === 'kept', 'A retired key reads with its raw key, stored code and stored login');
    $assert($entry['ip'] === '-', 'An entry with no IP address reads as -');
    $assert(!array_key_exists('data', $entry) && !array_key_exists('passkey_aaguid', $entry) && is_string($entry['time']) && $read['data']['per_page'] === 20, 'Read returns presentation fields only');
    foreach ([['category' => 'nope'], ['ok' => 'yes'], ['paged' => 0], ['paged' => 'x']] as $bad) {
        $assert($logs->read($site, $bad)['code'] === 'invalid_request', 'Invalid read request rejected: ' . json_encode($bad));
    }

    foreach (['marie', 'admin'] as $name) {
        $login = 'azwp_logs_' . $name . '_' . bin2hex(random_bytes(4));
        $id = wp_insert_user(['user_login' => $login, 'user_email' => $login . '@example.test', 'user_pass' => wp_generate_password(), 'role' => $name === 'admin' ? 'administrator' : 'subscriber']);
        if (is_wp_error($id)) { throw new RuntimeException('Test user creation failed'); }
        $users[$name] = (int) $id;
    }
    ['marie' => $marie, 'admin' => $admin] = $users;
    $_SERVER['REMOTE_ADDR'] = '192.0.2.10';
    $signin = $record('signin.passkey', ['target_id' => $marie, 'passkey' => ['id' => 9, 'name' => 'Marie phone']]);
    $own = $record('passkey.renamed', ['actor_id' => $marie, 'target_id' => $marie, 'passkey' => ['id' => 9, 'name' => 'Marie phone'], 'data' => ['previous_name' => 'Old phone']]);
    $other_site = $record('passkey.tested', ['site_id' => 99, 'actor_id' => $marie, 'target_id' => $marie, 'passkey' => ['id' => 9, 'name' => 'Marie phone']]);
    $by_admin = $record('passkey.deleted', ['actor_id' => $admin, 'target_id' => $marie, 'passkey' => ['id' => 10, 'name' => 'Marie key']]);
    $admin_own = $record('passkey.tested', ['actor_id' => $admin, 'target_id' => $admin, 'passkey' => ['id' => 11, 'name' => 'Admin key']]);
    $link = $record('admin.setup_link', ['actor_id' => $admin, 'target_id' => $marie]);
    if ($original_address === null) { unset($_SERVER['REMOTE_ADDR']); } else { $_SERVER['REMOTE_ADDR'] = $original_address; }
    $renamed_rows = [];
    for ($i = 0; $i < 101; $i++) { $renamed_rows[] = $record('passkey.renamed', ['actor_id' => $marie, 'target_id' => $marie, 'passkey' => ['id' => 9, 'name' => 'Phone'], 'data' => ['previous_name' => 'Name ' . $i]]); }

    $erased_admin = $logs->erase(get_userdata($admin)->user_email, 1);
    $assert($erased_admin['items_removed'] && $erased_admin['items_retained'] && $erased_admin['done'], 'Erasing the administrator finishes in one page and keeps rows');
    $assert($by_correlation($by_admin)['ip'] === 'erased' && $by_correlation($signin)['ip'] === '192.0.2.10', "Erasing the administrator erases the administrator's IP address and keeps the member's");
    $assert($by_correlation($by_admin)['actor_login'] === 'erased' && $by_correlation($by_admin)['passkey_name'] === 'Marie key', "An administrator's rows keep other people's passkey names");
    $assert($by_correlation($admin_own)['passkey_name'] === 'erased' && $by_correlation($admin_own)['target_login'] === 'erased', "The administrator's own passkey name is erased");
    $page = $logs->erase(get_userdata($marie)->user_email, 1);
    $assert(!$page['done'] && $page['items_removed'] && $page['items_retained'] && $page['messages'] === ['Passkey log entries are kept with usernames and passkey names erased.'], 'More than 100 renamed rows need a second eraser page');
    $last = $logs->erase(get_userdata($marie)->user_email, 2);
    $assert($last['done'], 'The last eraser page is done');
    $row = $by_correlation($own);
    $assert($row['actor_login'] === 'erased' && $row['target_login'] === 'erased' && $row['passkey_name'] === 'erased' && json_decode($row['data'], true) === ['previous_name' => 'erased'], 'Logins, owned passkey names and previous_name are erased');
    $assert($by_correlation($other_site)['passkey_name'] === 'erased', 'Rows on every site are erased');
    $assert($row['ip'] === 'erased' && $by_correlation($signin)['ip'] === 'erased', "The user's IP address is erased where the user acted or signed in");
    $assert($by_correlation($by_admin)['passkey_name'] === 'erased', "The owner's passkey name is erased from an administrator's row");
    $assert($by_correlation($link)['passkey_name'] === null && $by_correlation($link)['target_login'] === 'erased', 'A row with no passkey keeps a NULL passkey name');
    $assert(json_decode($by_correlation(end($renamed_rows))['data'], true) === ['previous_name' => 'erased'], 'Rows past the first eraser page are erased');
    $assert((int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `$table` WHERE target_id=%d", $marie)) === 106, 'The eraser keeps every row');
    $nobody = $logs->erase('nobody-' . bin2hex(random_bytes(4)) . '@example.test', 1);
    $assert($nobody['done'] && !$nobody['items_removed'] && !$nobody['items_retained'], 'An unknown email erases nothing');
    $erasers = apply_filters('wp_privacy_personal_data_erasers', []);
    $assert(isset($erasers['azwp-passkeys-logs']) && is_callable($erasers['azwp-passkeys-logs']['callback']), 'The eraser is registered with WordPress');

    $assert($details('admin.logs_cleared', ['data' => ['count' => 1]]) === '1 entry deleted', 'One cleared entry is singular');
    $assert($details('admin.logs_cleared', ['data' => ['count' => 3]]) === '3 entries deleted', 'A clear counts the entries it deleted');
    $assert($details('admin.logs_cleared', ['ok' => false, 'code' => 'storage_failed']) === 'Clearing failed: database error', 'A failed clear reads its reason');
    $settings->save_logs(['logging' => '0']);
    $before_clear = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `$table` WHERE site_id=%d", $site));
    $cleared = $logs->clear($site, $admin);
    $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM `$table` WHERE site_id=%d", $site), ARRAY_A);
    $assert($cleared['ok'] && $before_clear > 0 && count($rows) === 1 && $rows[0]['event'] === 'admin.logs_cleared' && (int) $rows[0]['actor_id'] === $admin && json_decode($rows[0]['data'], true) === ['count' => $before_clear], 'Clearing leaves one row naming who cleared how many entries, even with logging off');
    $entry = $logs->read($site, [])['data']['entries'][0];
    $assert([$entry['category'], $entry['action'], $entry['user']] === ['Admin', 'Logs cleared', get_userdata($admin)->user_login], 'The clear row reads as Admin: Logs cleared by the administrator');
    echo "Logs integration: $checks checks passed.\n";
} finally {
    foreach (array_chunk($correlations, 100) as $chunk) {
        $wpdb->query($wpdb->prepare("DELETE FROM `$table` WHERE correlation_id IN (" . implode(',', array_fill(0, count($chunk), '%s')) . ')', ...$chunk));
    }
    $wpdb->delete($table, ['site_id' => $site, 'event' => 'admin.logs_cleared']);
    foreach ($users as $user) { wp_delete_user($user); }
    if ($original_settings === null) { delete_option('azwp_passkeys_settings'); }
    else { update_option('azwp_passkeys_settings', $original_settings, false); }
}
