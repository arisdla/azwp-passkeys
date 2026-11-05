<?php
/** Dev site only (mapped by .wp-env.json): the container has no mail server, so WordPress mail goes to Mailpit from bin/mailpit.sh. */
add_action('phpmailer_init', static function ($mailer): void {
	$mailer->isSMTP();
	$mailer->Host = 'host.docker.internal';
	$mailer->Port = 1025;
	$mailer->SMTPAuth = false;
	$mailer->SMTPAutoTLS = false;
});
// PHPMailer rejects WordPress's default sender on a localhost site, so mail would fail before reaching Mailpit.
add_filter('wp_mail_from', static fn(string $from): string => str_ends_with($from, '@localhost') ? 'wordpress@localhost.test' : $from);
