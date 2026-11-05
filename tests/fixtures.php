<?php
/** Synthetic signed WebAuthn fixtures; no tests execute on inclusion. */
use AZWP\Passkeys\WebAuthn;

function check(string $name, bool $condition): void {
	if (!$condition) { throw new RuntimeException('FAIL: ' . $name); }
	echo 'PASS: ' . $name . "\n";
}
function cbor_head(int $major, int $number): string {
	return $number < 24 ? chr(($major << 5) | $number) : ($number < 256 ? chr(($major << 5) | 24) . chr($number) : chr(($major << 5) | 25) . pack('n', $number));
}
function cbor_bytes(string $value): string { return cbor_head(2, strlen($value)) . $value; }
function cbor_text(string $value): string { return cbor_head(3, strlen($value)) . $value; }
/** OpenSSL drops leading zero bytes from P-256 coordinates; COSE requires each to be exactly 32 bytes. */
function es256_cose(OpenSSLAsymmetricKey $key): string {
	$ec = openssl_pkey_get_details($key)['ec'];
	return cose_fixture([1 => 2, 3 => -7, -1 => 1, -2 => str_pad($ec['x'], 32, "\0", STR_PAD_LEFT), -3 => str_pad($ec['y'], 32, "\0", STR_PAD_LEFT)]);
}
function cose_fixture(array $fields): string {
	$encoded = cbor_head(5, count($fields));
	foreach ($fields as $key => $value) {
		$encoded .= $key >= 0 ? cbor_head(0, $key) : cbor_head(1, -1 - $key);
		$encoded .= is_string($value) ? cbor_bytes($value) : ($value >= 0 ? cbor_head(0, $value) : cbor_head(1, -1 - $value));
	}
	return $encoded;
}
/** $format 'packed' signs a self-attestation with $key; any other value is written as the format name with an empty statement. */
function registration_fixture(array $issued, string $id, string $cose, string $aaguid, int $flags = 0x45, ?string $origin = null, string $format = 'none', ?OpenSSLAsymmetricKey $key = null, int $alg = -7): array {
	$client = json_encode(['type' => 'webauthn.create', 'challenge' => WebAuthn::encode($issued['challenge']), 'origin' => $origin ?? $issued['origins'][0]], JSON_THROW_ON_ERROR);
	$data = hash('sha256', $issued['rp_id'], true) . chr($flags) . pack('N', 0) . $aaguid . pack('n', strlen($id)) . $id . $cose;
	$statement = cbor_head(5, 0);
	if ($format === 'packed') {
		openssl_sign($data . hash('sha256', $client, true), $signature, $key, OPENSSL_ALGO_SHA256);
		$statement = cbor_head(5, 2) . cbor_text('alg') . cbor_head(1, -1 - $alg) . cbor_text('sig') . cbor_bytes($signature);
	}
	$attestation = cbor_head(5, 3) . cbor_text('fmt') . cbor_text($format) . cbor_text('authData') . cbor_bytes($data) . cbor_text('attStmt') . $statement;
	return ['type' => 'public-key', 'id' => WebAuthn::encode($id), 'rawId' => WebAuthn::encode($id), 'response' => ['clientDataJSON' => WebAuthn::encode($client), 'attestationObject' => WebAuthn::encode($attestation), 'transports' => ['internal', 'hybrid', 'internal']], 'clientExtensionResults' => []];
}
function assertion_fixture(array $issued, array $stored, OpenSSLAsymmetricKey $key, int $flags = 5, int $counter = 0, ?string $handle = null, ?string $origin = null): array {
	$client = json_encode(['type' => 'webauthn.get', 'challenge' => WebAuthn::encode($issued['challenge']), 'origin' => $origin ?? $issued['origins'][0]], JSON_THROW_ON_ERROR);
	$data = hash('sha256', $issued['rp_id'], true) . chr($flags) . pack('N', $counter);
	if (!openssl_sign($data . hash('sha256', $client, true), $signature, $key, OPENSSL_ALGO_SHA256)) { throw new RuntimeException('Fixture signing failed'); }
	return ['type' => 'public-key', 'id' => WebAuthn::encode($stored['credential_id']), 'rawId' => WebAuthn::encode($stored['credential_id']), 'response' => ['clientDataJSON' => WebAuthn::encode($client), 'authenticatorData' => WebAuthn::encode($data), 'signature' => WebAuthn::encode($signature), 'userHandle' => $handle === null ? null : WebAuthn::encode($handle)], 'clientExtensionResults' => []];
}
