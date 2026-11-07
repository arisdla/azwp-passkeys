# Releasing

A release is a version bump commit on `main` plus an annotated tag. Pushing the tag starts the release workflow, which checks the versions, runs the tests and publishes the zip and the update metadata.

## 1. Check that main is ready

Run `git status`. It should show no changes, and `main` should not be ahead of or behind GitHub.

The latest Tests run on `main` should be green.

Choose the version number. If every change since the last release is a fix, raise the last number, as in 0.3.0 to 0.3.1. If any change adds a feature or changes behavior, raise the middle number and reset the last, as in 0.3.1 to 0.4.0.

## 2. Update the WordPress and PHP versions when they change

When a Tests run warns "WordPress X.Y is out and the tests pass on it", set this line in the header of `azwp-passkeys.php`:

```
 * Tested up to: X.Y
```

If you raise the minimum WordPress or PHP version, change `Requires at least` or `Requires PHP` in the same header, and the requirements line in `README.md`.

The release reads all three from the header.

## 3. Bump the version

Start wp-env first if it is not running, because the translations are regenerated inside it:

```bash
pnpm start
```

```bash
pnpm bump 0.4.0
```

The script sets the version in the plugin header, in `AZWP_PASSKEYS_VERSION` and in the `.po` headers, then regenerates the translation files. It ends by listing every changed and new file.

## 4. Commit and push

Add everything the script listed. Translation updates can create new files, which `git commit -a` would leave out:

```bash
git add -A
```

```bash
git commit -m "chore: bump version to 0.4.0"
```

```bash
git push github main
```

## 5. Write the changelog as a tag message

Site admins read this message in WordPress's "View details" window, and it becomes the notes of the GitHub release. Group the lines under headings, and write one line for each change that says what changed for them:

```bash
git tag -a v0.4.0 -F docs/releases/0.4.0.md
```

Review [the 0.4.0 release notes](releases/0.4.0.md) before tagging. They include the loss of old diagnostic history during the upgrade.

Use the headings that apply: Added, Changed, Fixed, Security and Removed.

Always create the tag with `-a`. A tag made without it has no message, and the release stops at the version check.

## 6. Push the tag

```bash
git push github v0.4.0
```

## 7. What the release workflow does

1. It checks that the tag, the header's `Version` and `AZWP_PASSKEYS_VERSION` name the same version, that the header has all three WordPress and PHP version lines, and that the tag is annotated. This takes seconds.
2. It runs the tests on the minimum, latest and trunk versions of WordPress, plus a multisite PHP lane on the minimum version. The upgrade regression runs in every PHP lane. If the minimum, latest or multisite job fails, it publishes nothing. A trunk failure does not block the release.
3. It builds the zip and the update metadata. The metadata takes `requires`, `requires_php` and `tested` from the plugin header and the changelog from the tag message.
4. It publishes the `v0.4.0` release with the zip, the metadata and the changelog as its notes. Then it uploads the same files to the release tagged `latest` and moves that tag to the new commit.

Sites check `releases/download/latest/azwp-passkeys.json`, so they see the update once that file is uploaded to the `latest` release. Its download link points to the zip in the `v0.4.0` release, which is uploaded first.

## 8. Confirm the release

The Release Plugin run on the Actions tab should be green.

Read the update metadata that sites download and check `version`, `tested` and the changelog:

```bash
curl -sL https://github.com/arisdla/azwp-passkeys/releases/download/latest/azwp-passkeys.json
```

## If something goes wrong

If the version check or the tests fail, nothing was published. Delete the tag on your machine and on GitHub:

```bash
git tag -d v0.4.0
```

```bash
git push github :refs/tags/v0.4.0
```

Fix the problem on `main`, push it, and tag again from step 5.

If the workflow fails after the tests, while uploading, open the failed run and choose "Re-run failed jobs". The upload steps update the existing releases and replace their files, so a rerun usually finishes the release. If the rerun cannot succeed, delete the `v0.4.0` release on the repository's Releases page, then delete and push the tag again as above. Sites keep the previous version until the metadata reaches the `latest` release.

If a broken release reached sites, keep its version number as it is. Fix the problem and release the next version, such as 0.4.1.
