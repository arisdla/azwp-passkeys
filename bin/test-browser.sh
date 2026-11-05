#!/bin/sh
# Runs the browser tests against wp-env's disposable tests site with Chrome's virtual authenticator.
set -e
page=$(sh "$(dirname "$0")/seed-tests.sh")
AZWP_PASSKEYS_TESTS=1 TEST_URL=http://localhost:8090 TEST_USERNAME=admin TEST_PASSWORD=password TEST_PAGE_ID="$page" \
	BROWSER_PATH="${BROWSER_PATH:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}" node tests/browser.cjs
