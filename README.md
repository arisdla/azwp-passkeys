# AZ's WP Passkeys

[![Latest release](https://img.shields.io/github/v/release/arisdla/azwp-passkeys)](https://github.com/arisdla/azwp-passkeys/releases/latest)
[![Tests](https://github.com/arisdla/azwp-passkeys/actions/workflows/test.yml/badge.svg)](https://github.com/arisdla/azwp-passkeys/actions/workflows/test.yml)
![WordPress 6.9+](https://img.shields.io/badge/WordPress-6.9%2B-21759b)
![PHP 8.3+](https://img.shields.io/badge/PHP-8.3%2B-777bb4)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)](LICENSE)

Passkey sign-in and management for WordPress, with login integration, shortcodes, blocks and multisite support.

![Passkeys section of a user profile](docs/profile-passkeys.jpg)

The [UX demo](https://raw.githack.com/arisdla/azwp-passkeys/main/wireframes/index.html) is a clickable wireframe of every screen. Its source is [wireframes/index.html](wireframes/index.html).

## Features

- **Passkey sign-in.** One button opens the browser's passkey picker. Users don't type a username.
- **Passkey only mode.** The mode hides the password form. Administrators can also turn off password login for single accounts.
- **Profile management.** Users add, rename, test and remove passkeys. Each passkey shows its authenticator model and whether it is synced.
- **Recovery links.** An administrator can send another account a one-time passkey setup link.
- **Shortcodes and blocks.** Login, registration, test and list components work on any page.
- **Multisite.** Sites share passkey storage, and the network sets the policies.
- **Passkey Logs.** A filterable table records sign-in, passkey, admin and settings events.
- **Updates.** New GitHub releases appear as normal WordPress plugin updates.

## Requirements

| | |
| --- | --- |
| WordPress | 6.9 or later |
| PHP | 8.3 or later, with OpenSSL |
| HTTPS | Required. Plain HTTP works only on `localhost` |
| Database | InnoDB tables |

> [!NOTE]
> The plugin saves data in transactions, so activation fails on MyISAM tables. To convert one, back up the database and run `ALTER TABLE <table> ENGINE=InnoDB`.

## Install

1. Download `azwp-passkeys.zip` from the [latest release](https://github.com/arisdla/azwp-passkeys/releases/latest).
2. In WordPress, go to Plugins, Add New, Upload Plugin and upload the zip.
3. Activate it. On multisite, network-activate it.
4. Under Settings, open the AZ's WP Passkeys page and set **Website name** and **Passkey domain**.

Users then add and test passkeys from their profile. Updates come through [plugin-update-checker](https://github.com/YahnisElsts/plugin-update-checker).

## Shortcodes and blocks

Each shortcode is also a block.

| Shortcode | Shows |
| --- | --- |
| `[azwp_pk_login]` | Passkey sign-in, with the password form unless `traditional="false"` |
| `[azwp_pk_register]` | Adds a passkey to the signed-in account |
| `[azwp_pk_test]` | Tests the signed-in account's passkeys |
| `[azwp_pk_list]` | Lists the signed-in account's passkeys |

The [specification](docs/specification.md) describes every attribute and the full behaviour.

## Develop

<details>
<summary>Local setup, commands and releases</summary>

Requires Docker, Node.js 22.13 or newer, pnpm, PHP 8.3 or newer with OpenSSL, and Composer 2.11.1. Release builds also use Python 3 and Git.

```sh
composer install --no-plugins --no-scripts
pnpm install
pnpm start
```

The dev site is http://localhost:8080 (`admin` / `password`). The tests use a separate site at http://localhost:8090.

The dev site sends all its email to [Mailpit](https://mailpit.axllent.org/), which `pnpm start` runs in Docker. Read it at http://localhost:8025. The tests site does not use it.

| Command | Does |
| --- | --- |
| `pnpm start` / `pnpm stop` | Start or stop both sites |
| `pnpm wp <command>` | Run WP-CLI on the dev site |
| `pnpm reset` | Delete both sites (databases, WordPress files, Docker containers and volumes) and Mailpit, then start fresh |
| `pnpm test` | Reset the tests site and run every suite |
| `pnpm test:js`, `test:php`, `test:http`, `test:browser` | Run one suite |
| `pnpm i18n` | Regenerate translation files |
| `pnpm bump <version>` | Set a new plugin version and regenerate translation files |
| `pnpm dist` | Build the release ZIP from committed source and locked production dependencies in `dist/` |

`pnpm reset` cannot remove passkeys your devices saved for `localhost`. After a reset, delete them from your password manager or security key, or the passkey picker offers accounts the new site does not know.

`test:browser` uses Google Chrome; set `BROWSER_PATH` for another browser. The tests skip `concurrency.php` and `two-factor.php` unless the environment supports them.

PHP dependencies are declared in `composer.json` and pinned by `composer.lock`. Run `composer install` after pulling dependency updates. Do not edit `vendor/` or commit it. The plugin's own classes stay in `src/class-*.php`; Composer generates their classmap. Run `composer dump-autoload` after adding or renaming a class file. The release ZIP includes all runtime dependencies, so site owners do not need PHP CLI or Composer.

Dependabot checks Composer, pnpm and GitHub Actions weekly. To update a PHP package locally, run `composer update <package> --with-dependencies`, review and commit both Composer files, then run the tests. `composer audit --locked` checks declared packages; `tests/dependencies.php` also checks PUC's bundled Parsedown, which is not a separate Composer requirement.

To release, follow [docs/release.md](docs/release.md).

</details>

## Support

Report bugs and translation issues on [GitHub Issues](https://github.com/arisdla/azwp-passkeys/issues).

## License

[GPL-3.0-or-later](LICENSE)
