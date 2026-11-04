#!/bin/sh
# Regenerates the translation catalogs with WP-CLI inside wp-env; translate new entries in the .po files, then run again.
set -e
dir=/var/www/html/wp-content/plugins/azwp-passkeys
cli() { npx wp-env run cli -- "$@"; }
cli wp i18n make-pot "$dir" "$dir/languages/azwp-passkeys.pot" --slug=azwp-passkeys --domain=azwp-passkeys \
	--exclude=bin,data,docs,node_modules,tests,vendor,wireframes --skip-audit
cli wp i18n update-po "$dir/languages/azwp-passkeys.pot" "$dir/languages"
cli wp i18n make-mo "$dir/languages"
cli wp i18n make-json "$dir/languages" --no-purge
