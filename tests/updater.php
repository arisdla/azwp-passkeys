<?php
/** Verify the Composer-loaded updater against WordPress, without a network request. */
declare(strict_types=1);
require_once dirname(__DIR__) . '/autoload.php';
$checker = YahnisElsts\PluginUpdateChecker\v6\PucFactory::buildUpdateChecker(
    'https://example.test/azwp-passkeys.json', AZWP_PASSKEYS_FILE, 'azwp-passkeys-updater-test', 0
);
$respond = static function ($response, array $args, string $url) {
    if (!str_starts_with($url, 'https://example.test/azwp-passkeys.json')) { return $response; }
    return ['headers'=>[], 'body'=>json_encode([
        'name'=>"AZ's WP Passkeys", 'version'=>'999.0.0',
        'download_url'=>'https://example.test/azwp-passkeys.zip',
        'requires'=>'6.9', 'requires_php'=>'8.3', 'tested'=>'7.1',
        'sections'=>['changelog'=>'<p>Release fixture.</p>'],
    ], JSON_THROW_ON_ERROR), 'response'=>['code'=>200, 'message'=>'OK'], 'cookies'=>[]];
};
add_filter('pre_http_request', $respond, 10, 3);
try {
    if ($checker->getInstalledVersion() !== AZWP_PASSKEYS_VERSION) {
        throw new RuntimeException('Updater cannot read the installed plugin version');
    }
    $info = $checker->requestInfo();
    if (!$info || $info->version !== '999.0.0' || $info->download_url !== 'https://example.test/azwp-passkeys.zip'
        || $info->sections['changelog'] !== '<p>Release fixture.</p>') {
        throw new RuntimeException('Updater did not preserve release metadata');
    }
    echo "PASS: PUC v6 constructs in WordPress, reads installed version and parses release metadata\n";
} finally {
    remove_filter('pre_http_request', $respond, 10);
    $checker->removeHooks();
}
