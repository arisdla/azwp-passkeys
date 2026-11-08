<?php
/** Runs without WordPress, against both a checkout and a freshly installed release stage. */
declare(strict_types=1);
define('ABSPATH', __DIR__ . '/');
require_once dirname(__DIR__) . '/autoload.php';

function dependency_check(bool $ok, string $message): void {
    if (!$ok) { throw new RuntimeException($message); }
    echo "PASS: $message\n";
}

foreach (['Plugin', 'Settings', 'Passkeys', 'Storage', 'WebAuthn', 'Authentication', 'Authenticators', 'Ajax', 'Screens', 'Lifecycle', 'Events', 'Logs'] as $class) {
    dependency_check(class_exists('AZWP\\Passkeys\\' . $class), "Plugin class $class autoloads");
}
dependency_check(class_exists(lbuchs\WebAuthn\WebAuthn::class), 'WebAuthn library autoloads');
dependency_check(class_exists(YahnisElsts\PluginUpdateChecker\v6\PucFactory::class), 'PUC v6 bootstrap is loaded by Composer');
dependency_check(class_exists(YahnisElsts\PluginUpdateChecker\v6p0\Plugin\UpdateChecker::class), 'PUC update checker autoloads');

// PUC bundles Parsedown outside its Composer requirements. Audit this copy explicitly.
$parsedown = dirname(__DIR__) . '/vendor/yahnis-elsts/plugin-update-checker/vendor/ParsedownModern.php';
dependency_check(is_file($parsedown), 'PUC bundled Parsedown exists');
require_once $parsedown;
dependency_check(version_compare(Parsedown::version, '1.8.0', '>='), 'PUC bundled Parsedown is at least 1.8.0');
$parser = (new Parsedown())->setSafeMode(true);
$html = $parser->text('[unsafe](javascript:alert(1))' . "\n\n<script>alert(1)</script>");
dependency_check(!str_contains($html, 'href="javascript:') && !str_contains($html, '<script>'), 'Parsedown safe mode rejects script markup and links');

if (isset($argv[1])) {
    dependency_check(Composer\InstalledVersions::getRootPackage()['pretty_version'] === $argv[1], 'Composer root version matches the plugin header');
}
