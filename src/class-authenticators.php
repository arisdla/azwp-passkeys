<?php
/** Display names for known authenticator models, from the bundled catalog. */
namespace AZWP\Passkeys;

final class Authenticators {
    private const CATALOG = 'data/authenticator-metadata-catalog.json';
    /** @var array<string, string>|null */
    private static ?array $labels = null;

    /** The catalog name for a raw 16-byte AAGUID, or null when the model is unknown. */
    public static function name(string $aaguid): ?string {
        if (strlen($aaguid) !== 16) { return null; }
        self::$labels ??= self::load();
        return self::$labels[vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($aaguid), 4))] ?? null;
    }

    /** A missing or malformed catalog only removes the extra label; it never affects a passkey. */
    private static function load(): array {
        $file = dirname(__DIR__) . '/' . self::CATALOG;
        $json = is_readable($file) ? file_get_contents($file) : false;
        $entries = $json === false ? null : json_decode($json, true);
        $labels = [];
        foreach (is_array($entries) ? $entries : [] as $entry) {
            if (is_array($entry) && is_string($entry['aaguid'] ?? null) && is_string($entry['label'] ?? null) && $entry['label'] !== '') {
                $labels[strtolower($entry['aaguid'])] = $entry['label'];
            }
        }
        return $labels;
    }
}
