#!/bin/sh
# Drop root before starting the orchestrator/signer. When started as root the
# entrypoint first hands the state directories (which older deployments
# created as root) to the unprivileged runtime user.
set -eu

APP_UID="${ORCH_UID:-10001}"
APP_GID="${ORCH_GID:-10001}"
BIN=/usr/local/bin/orchestrator

if [ "$(id -u)" != "0" ]; then
	exec "$BIN" "$@"
fi

own_dir() {
	dir="$1"
	case "$dir" in
		"" | "/" | "." ) return 0 ;;
	esac
	mkdir -p "$dir"
	if [ -n "$(find "$dir" \( ! -user "$APP_UID" -o ! -group "$APP_GID" \) -print -quit)" ]; then
		chown -R "$APP_UID:$APP_GID" "$dir"
	fi
	chmod 0700 "$dir"
}

own_dir "${ORCH_STATE_DIR:-./orch-state}"
[ -n "${ORCH_SIGNER_SOCKET:-}" ] && own_dir "$(dirname "$ORCH_SIGNER_SOCKET")"
[ -n "${ORCH_SIGNER_KEY_PATH:-}" ] && own_dir "$(dirname "$ORCH_SIGNER_KEY_PATH")"
[ -n "${ORCH_SIGNER_LEGACY_KEY_PATH:-}" ] && [ -d "$(dirname "$ORCH_SIGNER_LEGACY_KEY_PATH")" ] && own_dir "$(dirname "$ORCH_SIGNER_LEGACY_KEY_PATH")"

exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups -- "$BIN" "$@"
