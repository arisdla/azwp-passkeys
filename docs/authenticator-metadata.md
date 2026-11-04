# Authenticator metadata catalog

`data/authenticator-metadata-catalog.json` is a small, curated map from AAGUID to a product label. The passkey list uses it only to show which model holds each passkey. It is not an allow list, not a security decision, and not a substitute for attestation validation.

## Origin

The catalog was copied unchanged from the BenOui project (`packages/auth/src/authenticator-metadata-catalog.json`, release v0.3.5-alpha.1), which maintains it under the rules below. It has 385 entries. Five carry a `source` URL; the rest record `null` because no source was retained, not because one was invented.

## How the plugin uses it

`AZWP\Passkeys\Authenticators::name()` reads the file once per request and looks up a credential's stored AAGUID. The plugin downloads nothing and queries no metadata service. Unknown AAGUIDs, malformed entries and the all-zero AAGUID that browsers send under `none` attestation have no match, and the list shows "—". A missing or unreadable catalog removes the labels and never affects a passkey.

Only the `label` field is read. The `manufacturer`, `authenticatorType`, `attachment`, `keyProtection` and `supportedTransports` fields describe a model's documented characteristics and are kept for future use. They are null for almost every entry.

Whether a passkey is synced is not catalog data. It is per credential: the plugin shows the "Synced" badge from the backed-up flag the authenticator reports.

## Updating the catalog

1. Verify the AAGUID and label against an authoritative manufacturer source, or the signed FIDO Metadata Service data when it is available.
2. Add one compact entry with the lowercase dashed UUID, a user-facing label, the manufacturer and the model attributes. Keep the source URL when there is one; otherwise use `null` rather than inventing one. Use `null` for any unknown attribute rather than inferring it.
3. Do not add an inferred mapping for a browser, operating system or password manager whose AAGUID is unavailable, anonymized or not authoritatively attributable.
4. Do not vendor the full FIDO metadata blob into the repository.
5. Run `pnpm test:php` before committing.
