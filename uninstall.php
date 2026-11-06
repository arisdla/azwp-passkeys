<?php
/** Remove only this plugin's persisted state during WordPress uninstall. */
if (!defined('ABSPATH') || !defined('WP_UNINSTALL_PLUGIN')) { exit; }
require_once __DIR__ . '/autoload.php';
$azwp_passkeys_storage = new \AZWP\Passkeys\Storage($GLOBALS['wpdb']);
$azwp_passkeys_logs = new \AZWP\Passkeys\Logs($azwp_passkeys_storage);
$azwp_passkeys_settings = new \AZWP\Passkeys\Settings($azwp_passkeys_storage, $azwp_passkeys_logs);
(new \AZWP\Passkeys\Lifecycle($azwp_passkeys_settings, $azwp_passkeys_storage, $azwp_passkeys_logs))->uninstall();
unset($azwp_passkeys_settings, $azwp_passkeys_logs, $azwp_passkeys_storage);
