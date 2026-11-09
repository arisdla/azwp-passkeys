#!/bin/sh
# Runs Mailpit for the dev site. WordPress there sends through SMTP port 1025; read the mail at http://localhost:8025.
set -e
name=azwp-passkeys-mailpit
case "${1:-start}" in
	start)
		docker start "$name" >/dev/null 2>&1 || docker run -d --name "$name" -p 127.0.0.1:8025:8025 -p 127.0.0.1:1025:1025 axllent/mailpit >/dev/null
		echo "Mailpit inbox: http://localhost:8025"
		;;
	stop)
		docker stop "$name" >/dev/null 2>&1 || true
		;;
	remove)
		docker rm -f "$name" >/dev/null 2>&1 || true
		;;
	*)
		echo "Usage: sh bin/mailpit.sh [start|stop|remove]" >&2
		exit 1
		;;
esac
