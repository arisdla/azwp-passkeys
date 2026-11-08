#!/usr/bin/env python3
"""Write a portable, byte-reproducible WordPress ZIP from a prepared stage."""
import datetime
from pathlib import Path
import sys
import zipfile

root, output = Path(sys.argv[1]), Path(sys.argv[2])
# ZIP timestamps are UTC, at least 1980, and have two-second precision.
epoch = max(315532800, int(sys.argv[3]))
time = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
stamp = (time.year, time.month, time.day, time.hour, time.minute, time.second // 2 * 2)
# An allowlist prevents new development files or local configuration from shipping.
roots = ["azwp-passkeys.php", "autoload.php", "uninstall.php", "LICENSE", "README.md",
         "composer.json", "composer.lock", "src", "assets", "views", "languages",
         "data", "watchdog", "vendor"]
files = []
for name in roots:
    path = root / name
    if path.is_symlink():
        raise SystemExit(f"Release symlinks are not allowed: {path}")
    if not path.exists():
        raise SystemExit(f"Missing release path: {name}")
    files.extend(path.rglob("*") if path.is_dir() else [path])
with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
    for path in sorted(files, key=lambda p: p.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative == "vendor/lbuchs/webauthn/.gitignore" or relative.startswith("vendor/lbuchs/webauthn/_test/"):
            continue
        if path.is_symlink():
            raise SystemExit(f"Release symlinks are not allowed: {path}")
        if not path.is_file():
            continue
        entry = zipfile.ZipInfo("azwp-passkeys/" + path.relative_to(root).as_posix(), stamp)
        entry.create_system = 3
        entry.external_attr = 0o100644 << 16
        # Stored entries avoid variation across zlib versions, at a small size cost.
        archive.writestr(entry, path.read_bytes())
