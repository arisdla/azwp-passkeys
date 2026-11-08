<?php
/** Synthetic protocol fixtures. No WordPress, real accounts or real passkeys. */
require_once dirname(__DIR__) . '/autoload.php';
use AZWP\Passkeys\WebAuthn;

require_once __DIR__ . '/fixtures.php';
$adapter = new WebAuthn();
check('default HTTPS port canonicalized', WebAuthn::canonical_origin('https://EXAMPLE.test:443') === 'https://example.test');
check('configured paths discarded', WebAuthn::canonical_origin('https://example.test/wp/?x=1#fragment', true) === 'https://example.test');
check('explicit nondefault port retained', WebAuthn::canonical_origin('https://example.test:8443') === 'https://example.test:8443');
check('dot-boundary parent accepted', WebAuthn::rp_matches_origin('example.test', 'https://login.example.test'));
check('suffix lookalike rejected', !WebAuthn::rp_matches_origin('example.test', 'https://badexample.test'));
check('single-label parent rejected', !WebAuthn::rp_matches_origin('test', 'https://example.test'));
foreach (['https://example.test/', 'http://example.test', 'http://127.0.0.1', 'null', 'https://evil.test@example.test', 'https://example.test#x', 'https://example.test?x', 'https://example.test\\evil'] as $origin) {
	$rejected = false; try { WebAuthn::canonical_origin($origin); } catch (InvalidArgumentException) { $rejected = true; }
	check('invalid client origin rejected: ' . $origin, $rejected);
}
foreach (['AA=', 'AA==', '+A', '/A', 'A', 'AB', "AA\n"] as $encoded) {
	$rejected = false; try { WebAuthn::decode($encoded); } catch (InvalidArgumentException) { $rejected = true; }
	check('noncanonical binary rejected ' . json_encode($encoded), $rejected);
}
foreach ([random_bytes(64), str_repeat('0123456789abcdef', 4), str_repeat("\0", 64)] as $user_handle) {
	foreach ([-7, -257] as $algorithm) {
		$key = openssl_pkey_new($algorithm === -7 ? ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'] : ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
		if (!$key) { throw new RuntimeException('Fixture key generation unavailable'); }
		$details = openssl_pkey_get_details($key);
		$cose = $algorithm === -7 ? es256_cose($key) : cose_fixture([1 => 3, 3 => -257, -1 => $details['rsa']['n'], -2 => $details['rsa']['e']]);
		foreach (['https://example.test:8443' => 'example.test', 'http://localhost' => 'localhost'] as $origin => $rp) {
			$issued = ['rp_id' => $rp, 'rp_name' => 'Test', 'challenge' => random_bytes(32), 'origins' => [$origin], 'user_handle' => $user_handle, 'user_name' => 'alice', 'user_display_name' => 'Alice', 'exclude_credentials' => [], 'allow_credentials' => []];
			$id = random_bytes(32); $aaguid = random_bytes(16); $tag = "$algorithm $origin ";
			$options = $adapter->creation_options($issued);
			check($tag . 'create options available', $options['ok']);
			check($tag . 'required verification, direct attestation, exact algorithms', $options['data']['authenticatorSelection']['userVerification'] === 'required' && $options['data']['attestation'] === 'direct' && array_column($options['data']['pubKeyCredParams'], 'alg') === [-7, -257]);
			check($tag . 'creation always requires resident key', $options['data']['authenticatorSelection']['residentKey'] === 'required');
			check($tag . 'no attachment restriction', !isset($options['data']['authenticatorSelection']['authenticatorAttachment']));
			check($tag . 'issued challenge retained', $options['data']['challenge'] === WebAuthn::encode($issued['challenge']));
			check($tag . 'exact 64 handle bytes sent to browser', WebAuthn::decode($options['data']['user']['id']) === $user_handle);
			$register = registration_fixture($issued, $id, $cose, $aaguid);
			$result = $adapter->verify_registration($issued, $register);
			check($tag . 'valid registration', $result['ok']);
			foreach ([null, '', str_repeat('x', 32), str_repeat('x', 63), str_repeat('x', 65)] as $invalid_handle) {
				$invalid = array_replace($issued, ['user_handle'=>$invalid_handle]);
				check($tag . 'invalid handle options rejected', !$adapter->creation_options($invalid)['ok']);
				check($tag . 'invalid registration handle rejected', !$adapter->verify_registration($invalid, $register)['ok']);
			}
			$stored = $result['data'] + ['user_id' => 7, 'user_handle' => $issued['user_handle']];
			check($tag . 'raw COSE, AAGUID and PEM retained', $stored['public_key_cose'] === $cose && $stored['aaguid'] === $aaguid && $stored['public_key_pem'] === $details['key']);
			check($tag . 'transport metadata deduplicated', $stored['transports'] === ['internal', 'hybrid']);
			$zero = $adapter->verify_registration($issued, registration_fixture($issued, $id, $cose, str_repeat("\0", 16)));
			check($tag . 'zero AAGUID retained without invalidating passkey', $zero['ok'] && $zero['data']['aaguid'] === str_repeat("\0", 16));
			check($tag . 'none attestation recorded as its format', $result['data']['attestation_type'] === 'none');
			$packed = $adapter->verify_registration($issued, registration_fixture($issued, $id, $cose, $aaguid, 0x45, null, 'packed', $key, $algorithm));
			check($tag . 'packed self-attestation accepted with its real AAGUID', $packed['ok'] && $packed['data']['aaguid'] === $aaguid && $packed['data']['attestation_type'] === 'packed');
			$forged = registration_fixture($issued, $id, $cose, $aaguid, 0x45, null, 'packed', $key, $algorithm); $raw = WebAuthn::decode($forged['response']['attestationObject']);
			$forged['response']['attestationObject'] = WebAuthn::encode(substr($raw, 0, -1) . chr(ord($raw[strlen($raw) - 1]) ^ 1));
			check($tag . 'packed attestation with a bad signature rejected', !$adapter->verify_registration($issued, $forged)['ok']);
			check($tag . 'unknown attestation format rejected', !$adapter->verify_registration($issued, registration_fixture($issued, $id, $cose, $aaguid, 0x45, null, 'made-up'))['ok']);
			check($tag . 'missing UV rejected', !$adapter->verify_registration($issued, registration_fixture($issued, $id, $cose, $aaguid, 0x41))['ok']);
			check($tag . 'backup without eligibility rejected', !$adapter->verify_registration($issued, registration_fixture($issued, $id, $cose, $aaguid, 0x55))['ok']);
			$bad = $register; $bad['rawId'] = WebAuthn::encode('other');
			check($tag . 'rawId mismatch rejected', !$adapter->verify_registration($issued, $bad)['ok']);
			$bad = $register; $bad['response']['transports'] = 'internal';
			check($tag . 'invalid transports rejected', !$adapter->verify_registration($issued, $bad)['ok'] && $adapter->verify_registration($issued, $bad)['code'] === 'invalid_request');
			$bad = $register; $raw = WebAuthn::decode($bad['response']['attestationObject']);
			$bad['response']['attestationObject'] = WebAuthn::encode(substr($raw, 0, -1) . chr(0x80));
			check($tag . 'none attestation statement must be a map', !$adapter->verify_registration($issued, $bad)['ok']);
			$duplicate_cose = chr(ord($cose[0]) + 1) . substr($cose, 1) . cbor_head(0, 3) . cbor_head(1, -1 - $algorithm);
			check($tag . 'duplicate COSE map keys rejected', !$adapter->verify_registration($issued, registration_fixture($issued, $id, $duplicate_cose, $aaguid))['ok']);
			$wrong_challenge = $issued; $wrong_challenge['challenge'] = random_bytes(32);
			check($tag . 'challenge mismatch rejected', !$adapter->verify_registration($wrong_challenge, $register)['ok']);
			check($tag . 'unsupported algorithm rejected', !$adapter->verify_registration($issued, registration_fixture($issued, $id, cose_fixture([1 => 1, 3 => -8, -1 => 6, -2 => random_bytes(32)]), $aaguid))['ok']);
			check($tag . 'unsupported RSA modulus rejected', !$adapter->verify_registration($issued, registration_fixture($issued, $id, cose_fixture([1 => 3, 3 => -257, -1 => random_bytes(257), -2 => "\x01\x00\x01"]), $aaguid))['ok']);
			check($tag . 'exact origin required', !$adapter->verify_registration($issued, registration_fixture($issued, $id, $cose, $aaguid, 0x45, 'https://other.' . $rp))['ok']);
			$issued['allow_credentials'] = [['credential_id' => $id, 'transports' => ['internal', 'hybrid']]];
			$assertion = assertion_fixture($issued, $stored, $key);
			check($tag . 'zero counters accepted and returned', ($result = $adapter->verify_assertion($issued, $stored, $assertion))['ok'] && $result['data']['sign_count'] === 0);
			$empty = $issued; $empty['allow_credentials'] = [];
			check($tag . 'test empty allow-list rejects all', !$adapter->verify_assertion($empty, $stored, $assertion)['ok']);
			check($tag . 'test empty allow-list remains explicit', $adapter->request_options($empty)['data']['allowCredentials'] === []);
			check($tag . 'assertion without UV rejected', !$adapter->verify_assertion($issued, $stored, assertion_fixture($issued, $stored, $key, 1))['ok']);
			check($tag . 'counter advance accepted', $adapter->verify_assertion($issued, $stored, assertion_fixture($issued, $stored, $key, 5, 1))['ok']);
			$previous = $stored; $previous['sign_count'] = 1;
			check($tag . 'counter replay rejected', !$adapter->verify_assertion($issued, $previous, assertion_fixture($issued, $stored, $key, 5, 1))['ok']);
			check($tag . 'counter rollback to zero rejected', !$adapter->verify_assertion($issued, $previous, $assertion)['ok']);
			check($tag . 'backup eligibility cannot change', !$adapter->verify_assertion($issued, $stored, assertion_fixture($issued, $stored, $key, 13))['ok']);
			$bad = $assertion; $bad['response']['signature'] = WebAuthn::encode('bad signature');
			check($tag . 'tampered signature rejected', !$adapter->verify_assertion($issued, $stored, $bad)['ok']);
			check($tag . 'wrong supplied handle rejected', !$adapter->verify_assertion($issued, $stored, assertion_fixture($issued, $stored, $key, 5, 0, random_bytes(64)))['ok']);
			$login = $issued; unset($login['allow_credentials']);
			check($tag . 'login request has no allow-list', !array_key_exists('allowCredentials', $adapter->request_options($login)['data']));
			check($tag . 'login missing handle rejected', !$adapter->verify_assertion($login, $stored, $assertion)['ok']);
			check($tag . 'login wrong handle rejected', !$adapter->verify_assertion($login, $stored, assertion_fixture($login, $stored, $key, 5, 0, random_bytes(64)))['ok']);
			check($tag . 'login matching handle accepted', $adapter->verify_assertion($login, $stored, assertion_fixture($login, $stored, $key, 5, 0, $stored['user_handle']))['ok']);
			foreach (['', str_repeat('x', 32), str_repeat('x', 63), str_repeat('x', 65)] as $invalid_handle) {
				check($tag . 'invalid returned handle size rejected', !$adapter->verify_assertion($login, $stored, assertion_fixture($login, $stored, $key, 5, 0, $invalid_handle))['ok']);
				$invalid = array_replace($stored, ['user_handle'=>$invalid_handle]);
				check($tag . 'invalid stored handle rejected even with null test handle', !$adapter->verify_assertion($issued, $invalid, $assertion)['ok']);
			}
			$bad = $assertion; $client = json_decode(WebAuthn::decode($bad['response']['clientDataJSON']), true); $client['crossOrigin'] = true; $bad['response']['clientDataJSON'] = WebAuthn::encode(json_encode($client));
			check($tag . 'cross-origin context rejected', !$adapter->verify_assertion($issued, $stored, $bad)['ok']);
		}
	}
}
echo "Protocol tests complete.\n";
