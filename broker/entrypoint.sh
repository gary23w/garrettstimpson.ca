#!/usr/bin/env bash
set -e
# Start Tor in the background
tor --RunAsDaemon 1 --SocksPort 9050 --Log "notice stdout" >/tmp/tor.log 2>&1 || true
echo "waiting for Tor bootstrap..."
for i in $(seq 1 40); do
  if curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/ 2>/dev/null | grep -qi "Congratulations\|not using Tor"; then
    echo "Tor reachable."; break
  fi
  sleep 2
done
exec uvicorn app:app --host 0.0.0.0 --port "${PORT:-8080}"
