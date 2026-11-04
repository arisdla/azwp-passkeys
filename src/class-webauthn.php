<?php
/** WebAuthn protocol boundary. */
namespace AZWP\Passkeys;

use lbuchs\WebAuthn\WebAuthn as Library;
use lbuchs\WebAuthn\CBOR\CborDecoder;
use lbuchs\WebAuthn\Binary\ByteBuffer;

final class WebAuthn {
	public const BROWSER_TIMEOUT_MS = 60000;
	public const ALGORITHMS = [-7, -257];
	/** Direct attestation returns the authenticator's real AAGUID, used only to name its model; it grants no trust. */
	public const ATTESTATION = 'direct';
	public const ATTESTATION_FORMATS = ['android-key', 'android-safetynet', 'apple', 'fido-u2f', 'none', 'packed', 'tpm'];
	public const LIBRARY_VERSION = '2.2.0';

	/** Inputs use raw binary challenge/handle/credential_id; output uses browser JSON encodings. */
	public function creation_options(array $issued): array {
		return $this->guard(function () use ($issued): array {
			$library = $this->library($issued);
			$this->require(strlen($issued['challenge']) === 32 && strlen($issued['user_handle']) === 32);
			$args = $library->getCreateArgs($issued['user_handle'], $issued['user_name'], $issued['user_display_name'], 60, true, 'required', null);
			$options = json_decode(json_encode($args->publicKey, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
			$options['challenge'] = self::encode($issued['challenge']);
			$options['pubKeyCredParams'] = array_map(static fn(int $alg): array => ['type' => 'public-key', 'alg' => $alg], self::ALGORITHMS);
			$options['excludeCredentials'] = $this->descriptors($issued['exclude_credentials'] ?? []);
			unset($options['authenticatorSelection']['authenticatorAttachment']);
			$options['attestation'] = self::ATTESTATION;
			return $options;
		}, 'not_configured');
	}

	public function request_options(array $issued): array {
		return $this->guard(function () use ($issued): array {
			$this->require(strlen($issued['challenge']) === 32);
			$args = $this->library($issued)->getGetArgs([], 60, true, true, true, true, true, 'required');
			$options = json_decode(json_encode($args->publicKey, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
			$options['challenge'] = self::encode($issued['challenge']);
			// Tests carry the target's allow-list; usernameless sign-in has none.
			if (isset($issued['allow_credentials'])) {
				$this->require(is_array($issued['allow_credentials']));
				$options['allowCredentials'] = $this->descriptors($issued['allow_credentials']);
			} else {
				unset($options['allowCredentials']);
			}
			return $options;
		}, 'not_configured');
	}

	public function verify_registration(array $attempt, array $response): array {
		return $this->guard(function () use ($attempt, $response): array {
			$issued = $this->issued($attempt);
			[$credential_id, $body] = $this->envelope($response);
			$client = $this->client_data($issued, $body, 'webauthn.create');
			$attestation = self::decode($body['attestationObject'] ?? null);
			$object = CborDecoder::decode($attestation);
			$fields = $this->map_fields($attestation, 0, strlen($attestation));
			$this->require(isset($fields['attStmt']) && (ord($attestation[$fields['attStmt']]) >> 5) === 5);
			$this->require(is_array($object) && in_array($object['fmt'] ?? null, self::ATTESTATION_FORMATS, true) && is_array($object['attStmt'] ?? null));
			$this->require($object['fmt'] !== 'none' || $object['attStmt'] === []);
			$this->require(($object['authData'] ?? null) instanceof ByteBuffer);
			$auth_data = $object['authData']->getBinaryString();
			$flags = $this->auth_data($auth_data, $issued['rp_id'], true);
			$length = unpack('n', substr($auth_data, 53, 2))[1];
			$this->require($length > 0 && $length <= 1023 && strlen($auth_data) > 55 + $length);
			$this->require(hash_equals($credential_id, substr($auth_data, 55, $length)));
			$key_start = 55 + $length;
			$key_end = null;
			$key = CborDecoder::decodeInPlace($auth_data, $key_start, $key_end);
			$this->map_fields($auth_data, $key_start, $key_end);
			$algorithm = $this->validate_key($key);
			$this->extension_end($auth_data, $key_end, $flags['extensions']);
			foreach ($issued['exclude_credentials'] ?? [] as $excluded) {
				$this->require(!hash_equals($excluded['credential_id'], $credential_id));
			}
			$transports = $body['transports'] ?? [];
			if (!is_array($transports) || !array_is_list($transports)) { throw new \UnexpectedValueException('Invalid transports', 400); }
			foreach ($transports as $transport) { if (!is_string($transport)) { throw new \UnexpectedValueException('Invalid transports', 400); } }
			$data = $this->library($issued)->processCreate($client, $attestation, $issued['challenge'], true, true);
			$this->require(is_string($data->AAGUID) && strlen($data->AAGUID) === 16);
			return [
				'credential_id' => $credential_id, 'public_key_pem' => $data->credentialPublicKey,
				'public_key_cose' => substr($auth_data, $key_start, $key_end - $key_start),
				'credential_type' => 'public-key', 'attestation_type' => $object['fmt'], 'trust_path' => [],
				'aaguid' => $data->AAGUID, 'other_ui' => null, 'transports' => array_values(array_unique($transports)),
				'algorithm' => $algorithm, 'sign_count' => $flags['sign_count'],
				'backup_eligible' => $flags['backup_eligible'], 'backed_up' => $flags['backed_up'], 'rp_id' => $issued['rp_id'],
			];
		});
	}

	/** Stored credential includes its identity's raw user_handle, not a client-supplied owner. */
	public function verify_assertion(array $attempt, array $credential, array $response): array {
		return $this->guard(function () use ($attempt, $credential, $response): array {
			$issued = $this->issued($attempt);
			[$credential_id, $body] = $this->envelope($response);
			$this->require(hash_equals($credential['credential_id'], $credential_id) && $credential['rp_id'] === $issued['rp_id']);
			$this->require(isset($credential['user_id']) && (int) $credential['user_id'] > 0);
			$listed = isset($issued['allow_credentials']);
			if ($listed) {
				$this->require(is_array($issued['allow_credentials']));
				$allowed = false;
				foreach ($issued['allow_credentials'] as $item) { $allowed = $allowed || hash_equals($item['credential_id'], $credential_id); }
				$this->require($allowed);
				if (isset($attempt['target_id'])) { $this->require((string) $attempt['target_id'] === (string) $credential['user_id']); }
			}
			// Without an allow-list the owner is proven only by the credential's user handle.
			$handle = $body['userHandle'] ?? null;
			if (!$listed || $handle !== null) {
				$handle = self::decode($handle);
				$this->require($handle !== '' && hash_equals($credential['user_handle'], $handle));
			}
			$client = $this->client_data($issued, $body, 'webauthn.get');
			$auth_data = self::decode($body['authenticatorData'] ?? null);
			$signature = self::decode($body['signature'] ?? null);
			$this->require($signature !== '');
			$flags = $this->auth_data($auth_data, $issued['rp_id'], false);
			$this->extension_end($auth_data, 37, $flags['extensions']);
			$this->require($flags['backup_eligible'] === (bool) $credential['backup_eligible']);
			$key = CborDecoder::decode($credential['public_key_cose']);
			$this->map_fields($credential['public_key_cose'], 0, strlen($credential['public_key_cose']));
			$this->require($this->validate_key($key) === (int) $credential['algorithm']);
			// Compare persisted COSE to PEM before trusting a stored verification representation.
			$synthetic = hash('sha256', $issued['rp_id'], true) . chr(0x45) . pack('N', 0) . str_repeat("\0", 16) . pack('n', strlen($credential_id)) . $credential_id . $credential['public_key_cose'];
			$parsed = new \lbuchs\WebAuthn\Attestation\AuthenticatorData($synthetic);
			$this->require(hash_equals($parsed->getPublicKeyPem(), $credential['public_key_pem']));
			$this->library($issued)->processGet($client, $auth_data, $signature, $credential['public_key_pem'], $issued['challenge'], (int) $credential['sign_count'], true, true);
			return ['credential_id' => $credential_id, 'owner_id' => $credential['user_id'], 'sign_count' => $flags['sign_count'], 'backup_eligible' => $flags['backup_eligible'], 'backed_up' => $flags['backed_up']];
		});
	}

	public static function encode(string $bytes): string { return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='); }

	/** Strict, canonical unpadded base64url. Empty bytes are valid only where the caller allows them. */
	public static function decode(mixed $value): string {
		if (!is_string($value) || preg_match('/[^A-Za-z0-9_-]/D', $value) || strlen($value) % 4 === 1) { throw new \InvalidArgumentException('Invalid encoding'); }
		$decoded = base64_decode(strtr($value, '-_', '+/'), true);
		if ($decoded === false || self::encode($decoded) !== $value) { throw new \InvalidArgumentException('Invalid encoding'); }
		return $decoded;
	}

	/** Configuration host only. Unicode conversion uses the WordPress-bundled Requests implementation when loaded. */
	public static function canonical_rp_id(string $host): string {
		if ($host === '' || preg_match('/[\s\/\\\\:@?#%]/', $host)) { throw new \InvalidArgumentException('Invalid domain'); }
		if (preg_match('/[^\x00-\x7f]/', $host)) {
			if (!class_exists('WpOrg\\Requests\\IdnaEncoder')) { throw new \InvalidArgumentException('IDNA unavailable'); }
			$host = \WpOrg\Requests\IdnaEncoder::encode($host);
		}
		$host = strtolower($host);
		if (strlen($host) > 253 || !preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/D', $host) || ctype_digit(substr($host, (int) strrpos('.' . $host, '.')))) { throw new \InvalidArgumentException('Invalid domain'); }
		return $host;
	}

	/** Configured URLs may have a path; clientData origins must already be origin-only. */
	public static function canonical_origin(string $url, bool $configured = false): string {
		if (preg_match('/[\x00-\x20\x7f\\\\]/', $url)) { throw new \InvalidArgumentException('Invalid origin'); }
		$parts = parse_url($url);
		if (!is_array($parts) || !isset($parts['scheme'], $parts['host']) || isset($parts['user']) || isset($parts['pass']) || (!$configured && (isset($parts['path']) || isset($parts['query']) || isset($parts['fragment'])))) { throw new \InvalidArgumentException('Invalid origin'); }
		$scheme = strtolower($parts['scheme']);
		$host = self::canonical_rp_id($parts['host']);
		if (!in_array($scheme, ['http', 'https'], true) || ($scheme === 'http' && $host !== 'localhost')) { throw new \InvalidArgumentException('Invalid origin'); }
		$port = $parts['port'] ?? null;
		if ($port !== null && ($port < 1 || $port > 65535)) { throw new \InvalidArgumentException('Invalid port'); }
		return $scheme . '://' . $host . ($port !== null && $port !== ($scheme === 'https' ? 443 : 80) ? ':' . $port : '');
	}

	public static function rp_matches_origin(string $rp_id, string $origin): bool {
		try {
			$rp_id = self::canonical_rp_id($rp_id);
			$origin = self::canonical_origin($origin);
			$host = parse_url($origin, PHP_URL_HOST);
			return $host === $rp_id || (!filter_var($host, FILTER_VALIDATE_IP) && str_contains($rp_id, '.') && str_ends_with($host, '.' . $rp_id));
		} catch (\Throwable) { return false; }
	}

	private function library(array $issued): Library {
		$this->require(isset($issued['rp_id']) && self::canonical_rp_id($issued['rp_id']) === $issued['rp_id']);
		return new Library($issued['rp_name'] ?? 'Passkeys', $issued['rp_id'], self::ATTESTATION_FORMATS, true);
	}

	private function issued(array $attempt): array {
		$issued = $attempt['issued'] ?? $attempt;
		if (isset($attempt['challenge'])) { $issued['challenge'] = $attempt['challenge']; }
		return $issued;
	}

	private function descriptors(array $credentials): array {
		return array_map(function (array $credential): array {
			$this->require(isset($credential['credential_id']) && is_string($credential['credential_id']) && strlen($credential['credential_id']) > 0 && strlen($credential['credential_id']) <= 1023);
			$result = ['type' => 'public-key', 'id' => self::encode($credential['credential_id'])];
			if (!empty($credential['transports'])) { $result['transports'] = array_values(array_unique($credential['transports'])); }
			return $result;
		}, $credentials);
	}

	private function envelope(array $response): array {
		$this->require(($response['type'] ?? null) === 'public-key' && isset($response['response']) && is_array($response['response']));
		$this->require(array_key_exists('clientExtensionResults', $response) && is_array($response['clientExtensionResults']));
		$credential_id = self::decode($response['id'] ?? null);
		$this->require(strlen($credential_id) > 0 && strlen($credential_id) <= 1023 && hash_equals($credential_id, self::decode($response['rawId'] ?? null)));
		return [$credential_id, $response['response']];
	}

	private function client_data(array $issued, array $body, string $type): string {
		$json = self::decode($body['clientDataJSON'] ?? null);
		$data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
		$this->require(is_array($data) && ($data['type'] ?? null) === $type && is_string($data['origin'] ?? null));
		$this->require(!array_key_exists('crossOrigin', $data) || $data['crossOrigin'] === false);
		$this->require(!array_key_exists('topOrigin', $data));
		$this->require(strlen($issued['challenge']) === 32 && hash_equals($issued['challenge'], self::decode($data['challenge'] ?? null)));
		$origin = self::canonical_origin($data['origin']);
		$this->require(self::rp_matches_origin($issued['rp_id'], $origin));
		$this->require(in_array($origin, $issued['origins'] ?? [], true));
		return $json;
	}

	private function auth_data(string $data, string $rp_id, bool $registration): array {
		$this->require(strlen($data) >= ($registration ? 56 : 37));
		$this->require(hash_equals(hash('sha256', $rp_id, true), substr($data, 0, 32)));
		$flags = ord($data[32]);
		$this->require(($flags & 1) !== 0 && ($flags & 4) !== 0 && (bool) ($flags & 64) === $registration);
		$eligible = (bool) ($flags & 8); $backup = (bool) ($flags & 16);
		$this->require(!$backup || $eligible);
		return ['sign_count' => unpack('N', substr($data, 33, 4))[1], 'backup_eligible' => $eligible, 'backed_up' => $backup, 'extensions' => (bool) ($flags & 128)];
	}

	private function extension_end(string $data, int $offset, bool $included): void {
		if ($included) {
			$end = null;
			$extensions = CborDecoder::decodeInPlace($data, $offset, $end);
			$this->require(is_array($extensions));
			$this->map_fields($data, $offset, $end);
			$offset = $end;
		}
		$this->require($offset === strlen($data));
	}

	/** Preserve CBOR map structure and reject duplicate keys that a PHP array would otherwise hide. */
	private function map_fields(string $bytes, int $start, int $end): array {
		$this->require($start < strlen($bytes) && (ord($bytes[$start]) >> 5) === 5);
		$size = ord($bytes[$start]) & 31;
		$this->require($size < 28);
		$offset = $start + 1 + match ($size) { 24 => 1, 25 => 2, 26 => 4, 27 => 8, default => 0 };
		$fields = [];
		while ($offset < $end) {
			$key = CborDecoder::decodeInPlace($bytes, $offset, $offset);
			$this->require(is_string($key) || is_int($key));
			$this->require(!array_key_exists($key, $fields) && $offset < $end);
			$fields[$key] = $offset;
			CborDecoder::decodeInPlace($bytes, $offset, $offset);
		}
		$this->require($offset === $end);
		return $fields;
	}

	private function validate_key(mixed $key): int {
		$this->require(is_array($key) && in_array($key[3] ?? null, self::ALGORITHMS, true));
		if ($key[3] === -7) {
			$this->require(($key[1] ?? null) === 2 && ($key[-1] ?? null) === 1);
			foreach ([-2, -3] as $field) { $this->require(($key[$field] ?? null) instanceof ByteBuffer && $key[$field]->getLength() === 32); }
		} else {
			$this->require(($key[1] ?? null) === 3 && ($key[-1] ?? null) instanceof ByteBuffer && $key[-1]->getLength() === 256 && ($key[-2] ?? null) instanceof ByteBuffer && $key[-2]->getLength() === 3);
		}
		return $key[3];
	}

	private function require(bool $condition): void { if (!$condition) { throw new \InvalidArgumentException('Invalid passkey proof'); } }

	private function guard(callable $operation, string $code = 'authentication_failed'): array {
		// Library/parser warnings must not leak into JSON responses or bypass exception handling.
		set_error_handler(static function (int $severity, string $message, string $file, int $line): never { throw new \ErrorException($message, 0, $severity, $file, $line); });
		try { return ['ok' => true, 'code' => 'ok', 'data' => $operation(), 'message' => '']; }
		catch (\Throwable $error) { return ['ok' => false, 'code' => $error instanceof \UnexpectedValueException && $error->getCode() === 400 ? 'invalid_request' : $code, 'data' => [], 'message' => 'The passkey could not be verified. Try again.']; }
		finally { restore_error_handler(); }
	}
}
