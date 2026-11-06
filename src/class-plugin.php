<?php
declare(strict_types=1);
namespace AZWP\Passkeys;
final class Plugin
{
    private Storage $storage;
    private Logs $logs;
    private Settings $settings;
    private Passkeys $passkeys;
    private Authentication $authentication;
    private Ajax $ajax;
    private Screens $screens;
    private Lifecycle $lifecycle;
    public function __construct(\wpdb $wpdb)
    {
        $this->storage = new Storage($wpdb);
        $this->logs = new Logs($this->storage);
        $this->settings = new Settings($this->storage, $this->logs);
        $this->passkeys = new Passkeys($this->settings, $this->storage, new WebAuthn());
        $this->authentication = new Authentication($this->settings, $this->passkeys, $this->logs);
        $this->ajax = new Ajax($this->settings, $this->passkeys, $this->authentication, $this->logs);
        $this->screens = new Screens($this->settings, $this->passkeys, $this->storage);
        $this->lifecycle = new Lifecycle($this->settings, $this->storage, $this->logs);
    }
    public function register_hooks(): void
    {
        $this->authentication->register_hooks();
        $this->ajax->register_hooks();
        $this->screens->register_hooks();
        $this->lifecycle->register_hooks();
        register_activation_hook(AZWP_PASSKEYS_FILE, [$this->lifecycle, 'activate']);
        register_deactivation_hook(AZWP_PASSKEYS_FILE, [$this->lifecycle, 'deactivate']);
        add_action('init', static function (): void {
            load_plugin_textdomain('azwp-passkeys', false, dirname(plugin_basename(AZWP_PASSKEYS_FILE)) . '/languages');
        });
    }
}
