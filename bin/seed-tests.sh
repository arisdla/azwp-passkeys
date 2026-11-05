#!/bin/sh
# Prepares wp-env's disposable tests site for tests/browser.cjs and prints the page ID it needs.
set -e
wp() { npx wp-env run tests-cli wp --url=http://localhost:8090 "$@" 2>/dev/null; }

page=$(wp post list --post_type=page --name=azwp-passkeys-test --field=ID --format=ids)
if [ -z "$page" ]; then
	page=$(wp post create --post_type=page --post_status=publish --post_name=azwp-passkeys-test --post_title='Passkeys test' \
		--post_content='[azwp_pk_login][azwp_pk_register][azwp_pk_test][azwp_pk_list]' --porcelain)
fi
wp user get azwp-no-passkey --field=ID >/dev/null || wp user create azwp-no-passkey azwp-no-passkey@example.test --role=subscriber >/dev/null
echo "$page"
