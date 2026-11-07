#!/bin/sh
# Runs the PHP tests inside wp-env's disposable tests site (never the dev site).
# Optional: AZWP_TWO_FACTOR_SOURCE=<path inside the container to a Two-Factor release> also runs two-factor.php.
# Optional: AZWP_REQUIRE_CONCURRENCY=1 fails instead of skipping concurrency.php when pcntl/posix are missing.
set -e
dir=/var/www/html/wp-content/plugins/azwp-passkeys/tests
cli() { npx wp-env run tests-cli "$@"; }
# Output is buffered so tests that set cookies still see writable headers.
wp_test() { cli wp --url=http://localhost:8090 $3 eval "ob_start(); define('AZWP_PASSKEYS_TESTS', true); $2 require '$dir/$1.php';"; }

for test in webauthn authentication; do
	cli php "$dir/$test.php"
done
for test in storage logs passkeys passkey-only screens lifecycle watchdog; do
	wp_test "$test"
done
if cli php -r "exit(extension_loaded('pcntl') && extension_loaded('posix') ? 0 : 1);" >/dev/null 2>&1; then
	wp_test concurrency
elif [ -n "$AZWP_REQUIRE_CONCURRENCY" ]; then
	echo "concurrency.php needs pcntl and posix in tests-cli PHP." >&2
	exit 1
else
	echo "Skipped concurrency.php: tests-cli PHP lacks pcntl/posix."
fi
if [ -n "$AZWP_TWO_FACTOR_SOURCE" ]; then
	wp_test two-factor "define('AZWP_TWO_FACTOR_SOURCE', '$AZWP_TWO_FACTOR_SOURCE');" --skip-plugins
else
	echo "Skipped two-factor.php: set AZWP_TWO_FACTOR_SOURCE."
fi
