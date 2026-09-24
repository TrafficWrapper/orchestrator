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

# Plain if-blocks (not `test && own_dir`) so set -e still aborts on a failed
# mkdir/chown instead of failing later with EACCES.
own_dir "${ORCH_STATE_DIR:-./orch-state}"
if [ -n "${ORCH_SIGNER_SOCKET:-}" ]; then
	own_dir "$(dirname "$ORCH_SIGNER_SOCKET")"
fi
if [ -n "${ORCH_SIGNER_KEY_PATH:-}" ]; then
	own_dir "$(dirname "$ORCH_SIGNER_KEY_PATH")"
fi
if [ -n "${ORCH_SIGNER_LEGACY_KEY_PATH:-}" ] && [ -d "$(dirname "$ORCH_SIGNER_LEGACY_KEY_PATH")" ]; then
	own_dir "$(dirname "$ORCH_SIGNER_LEGACY_KEY_PATH")"
fi

# Keep only CAP_NET_BIND_SERVICE so ORCH_LISTEN may still use ports below 1024.
exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups \
	--inh-caps=-all,+net_bind_service --ambient-caps=-all,+net_bind_service \
	-- "$BIN" "$@"
