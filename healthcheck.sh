#!/bin/bash
# Container liveness for the crypto gateway (#460).
#
# Two things this deliberately does NOT do:
#   - it does not run `nginx -t`: that resolves the upstream host, so a DNS blip at the
#     bank would mark a perfectly healthy gateway unhealthy and restart it;
#   - it does not call the bank: an outage on their side must not restart-loop us.
# It asks our own listener for /healthz and nothing else.
#
# Implemented over bash's /dev/tcp instead of curl/wget so the runtime image needs no
# HTTP client at all (one less package to keep patched in a payments path).
set -uo pipefail

PORT="${GW_LISTEN:-1080}"

exec 3<>"/dev/tcp/127.0.0.1/${PORT}" || { echo "port ${PORT} closed"; exit 1; }
printf 'GET /healthz HTTP/1.0\r\nHost: healthz\r\nConnection: close\r\n\r\n' >&3 || exit 1
# -t: a worker that accepts the connection but never answers would otherwise leave this
# blocked until Docker's own HEALTHCHECK --timeout kills it. Failing on our own terms gives
# a readable message instead of a truncated one.
read -t 4 -r status_line <&3 || { echo 'no response'; exit 1; }
exec 3<&-

case "$status_line" in
  *' 200 '*) exit 0 ;;
  *) echo "unexpected: ${status_line}"; exit 1 ;;
esac
