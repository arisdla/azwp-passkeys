#!/bin/sh
# Builds dist/azwp-passkeys.zip from the working tree, leaving out every path listed in .distignore.
set -e
root=$(cd "$(dirname "$0")/.." && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/azwp-passkeys" "$root/dist"
rsync -a --exclude-from="$root/.distignore" "$root/" "$stage/azwp-passkeys/"
rm -f "$root/dist/azwp-passkeys.zip"
(cd "$stage" && zip -qr "$root/dist/azwp-passkeys.zip" azwp-passkeys)
echo "$root/dist/azwp-passkeys.zip"
