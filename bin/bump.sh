#!/bin/sh
# Sets a new plugin version everywhere it is written, then regenerates the translations.
# Committing, tagging and pushing stay manual; see docs/release.md.
set -e
version=$1
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "Usage: pnpm bump <major.minor.patch>" >&2
	exit 1
fi
cd "$(dirname "$0")/.."
if ! npx wp-env run cli wp --version >/dev/null 2>&1; then
	echo "Start wp-env first with pnpm start: the translations are regenerated inside it." >&2
	exit 1
fi

sed -i.bak -E "s/^( \* Version: ).*/\1$version/; s/(define\('AZWP_PASSKEYS_VERSION', ')[^']*/\1$version/" azwp-passkeys.php
sed -i.bak -E "s/(Project-Id-Version: AZWP Passkeys )[0-9.]+/\1$version/" languages/*.po
rm -f azwp-passkeys.php.bak languages/*.po.bak
if ! log=$(sh bin/i18n.sh 2>&1); then
	echo "$log" >&2
	exit 1
fi

echo "Set version $version. Review, then commit everything listed here, new files included:"
git status --short
