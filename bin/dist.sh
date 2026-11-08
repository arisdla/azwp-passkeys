#!/bin/sh
# Build only committed source and locked production dependencies.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo 'Commit tracked changes before building a release.' >&2
    exit 1
fi
output=${1:-"$root/dist/azwp-passkeys.zip"}
mkdir -p "$(dirname "$output")"
output=$(CDPATH= cd -- "$(dirname "$output")" && pwd)/$(basename "$output")
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
mkdir "$stage/azwp-passkeys"
git archive HEAD | tar -x -C "$stage/azwp-passkeys"
export SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
# Composer must not discover a root version or reference from the caller's checkout.
version=$(sed -n 's/^ \* Version: *//p' "$stage/azwp-passkeys/azwp-passkeys.php")
composer_run() {
    env -i PATH="$PATH" HOME="$stage" COMPOSER_HOME="$stage/composer-home" \
        COMPOSER_ROOT_VERSION="$version" composer "$@"
}
cd "$stage/azwp-passkeys"
if ! composer_run --version --no-ansi | grep -q '^Composer version 2\.11\.1 '; then
    echo 'Release builds require Composer 2.11.1, matching CI.' >&2
    exit 1
fi
composer_run validate --strict --no-check-publish
composer_run install --no-dev --prefer-dist --no-interaction --no-progress --no-plugins --no-scripts --classmap-authoritative
composer_run check-platform-reqs --no-dev
composer_run audit --locked --no-dev
php tests/dependencies.php "$version"
python3 -I bin/zip-release.py "$PWD" "$output" "$SOURCE_DATE_EPOCH"
python3 -I tests/release.py "$output"
printf '%s\n' "$output"
