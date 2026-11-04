<?php
/** Class loaders for the plugin and its pinned dependency. */
declare(strict_types=1);
spl_autoload_register(static function (string $class): void {
    $classes = ['Plugin', 'Settings', 'Passkeys', 'Storage', 'WebAuthn', 'Authentication', 'Authenticators', 'Ajax', 'Screens', 'Lifecycle'];
    $prefix = 'AZWP\\Passkeys\\';
    if (str_starts_with($class, $prefix)) {
        $name = substr($class, strlen($prefix));
        if (in_array($name, $classes, true)) {
            require_once __DIR__ . '/src/class-' . strtolower($name) . '.php';
        }
        return;
    }
    $prefix = 'lbuchs\\WebAuthn\\';
    if (str_starts_with($class, $prefix)) {
        $name = substr($class, strlen($prefix));
        if (preg_match('/^[A-Za-z0-9_\\\\]+$/D', $name)) {
            $file = __DIR__ . '/vendor/lbuchs/webauthn/src/' . str_replace('\\', '/', $name) . '.php';
            if (is_file($file)) {
                require_once $file;
            }
        }
    }
});
