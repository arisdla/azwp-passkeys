#!/usr/bin/env python3
"""Validate the actual installable archive, not the source directory."""
import json
import sys
import zipfile

def check(condition, message):
    if not condition:
        raise SystemExit(message)


with zipfile.ZipFile(sys.argv[1]) as archive:
    names = archive.namelist()
    check(names == sorted(set(names)), "ZIP entries must be unique and sorted")
    check(all(n.startswith("azwp-passkeys/") and ".." not in n.split("/") for n in names), "Unsafe ZIP path")
    relative = {n.removeprefix("azwp-passkeys/") for n in names}
    for required in ["azwp-passkeys.php", "autoload.php", "uninstall.php", "src/class-plugin.php",
                     "watchdog/azwp-passkeys-watchdog.php", "vendor/autoload.php", "composer.lock",
                     "vendor/lbuchs/webauthn/src/WebAuthn.php",
                     "vendor/yahnis-elsts/plugin-update-checker/load-v6p0.php"]:
        check(required in relative, f"Missing {required}")
    forbidden = {".git", ".github", ".env", "node_modules", "bin", "tests", "docs", "wireframes",
                 "package.json", "pnpm-lock.yaml", ".wp-env.json"}
    check(not {n.split("/")[0] for n in relative} & forbidden, "Development/private files in ZIP")
    check(not any(n.startswith("vendor/lbuchs/webauthn/_test/") for n in relative), "WebAuthn demo endpoint in ZIP")
    check("vendor/lbuchs/webauthn/LICENSE" in relative, "WebAuthn license missing")
    check("vendor/yahnis-elsts/plugin-update-checker/license.txt" in relative, "PUC license missing")
    lock = json.loads(archive.read("azwp-passkeys/composer.lock"))
    installed = json.loads(archive.read("azwp-passkeys/vendor/composer/installed.json"))
    check(installed["dev"] is False, "Development dependency installation in release")
    expected = {(p["name"], p["version"], p.get("dist", {}).get("reference")) for p in lock["packages"]}
    actual = {(p["name"], p["version"], p.get("dist", {}).get("reference")) for p in installed["packages"]}
    check(expected == actual, "Shipped packages differ from composer.lock")
    check(len({i.date_time for i in archive.infolist()}) == 1, "Non-normalized ZIP times")
    check(all(i.external_attr >> 16 == 0o100644 for i in archive.infolist()), "Non-normalized modes")
    check(archive.testzip() is None, "Corrupt ZIP member")
print("PASS: release layout, lockfile package identity, production-only install and ZIP metadata")
