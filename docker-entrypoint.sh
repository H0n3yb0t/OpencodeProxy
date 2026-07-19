#!/bin/sh
set -eu

PUID="${PUID:-10001}"
PGID="${PGID:-10001}"

case "$PUID:$PGID" in
  *[!0-9:]*|:*|*:)
    echo "ERROR: PUID and PGID must be numeric." >&2
    exit 1
    ;;
esac

if [ "$(id -u)" -eq 0 ]; then
  current_owner="$(stat -c '%u:%g' /data)"
  if [ "$current_owner" != "$PUID:$PGID" ]; then
    if ! chown -R "$PUID:$PGID" /data; then
      echo "ERROR: /data ownership could not be updated. Set PUID/PGID to the directory owner, grant the container write access, or use a Docker named volume." >&2
      exit 1
    fi
  fi
  if ! su-exec "$PUID:$PGID" sh -c 'test -w /data'; then
    echo "ERROR: /data is not writable by PUID=$PUID PGID=$PGID. Fix the bind-mount permissions or use a Docker named volume." >&2
    exit 1
  fi
  exec su-exec "$PUID:$PGID" /app/opencodeproxy "$@"
fi

if [ ! -w /data ]; then
  echo "ERROR: /data is not writable by uid $(id -u). Fix the bind-mount permissions or use the default Docker named volume." >&2
  exit 1
fi

exec /app/opencodeproxy "$@"
