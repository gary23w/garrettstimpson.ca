# Agent Garrett — OSINT Broker (optional)

Cloudflare Workers can't open Tor circuits or run Python OSINT binaries. This tiny
service does both; the Worker delegates to it when `TOOL_BROKER_URL` is set. Without
it, the agent still works — onion tools fall back to free clearnet gateways and
social recon uses the in-worker `username_enum`. **Defensive / educational use only.**

## Tools exposed
- `onion_fetch` — fetch `.onion` content over real Tor (+ pivots)
- `onion_search` — Ahmia search over Tor
- `sherlock` — username across 400+ sites (sherlock-project)
- `holehe` — which sites a given email is registered on

## Run (Docker)
```bash
cd broker
docker build -t gg-broker .
docker run -d --restart unless-stopped -p 8080:8080 \
  -e BROKER_TOKEN="$(openssl rand -hex 24)" gg-broker
# note the token you set
curl localhost:8080/health
```

## Wire it to the Worker
In the Cloudflare Worker (dashboard → Settings → Variables, or wrangler.toml):
```
TOOL_BROKER_URL    = https://your-host:8080/run      # put it behind HTTPS!
TOOL_BROKER_TOKEN  = <the same BROKER_TOKEN>
CUSTOM_TOOL_NAMES  = sherlock,holehe                  # makes them appear/run in the UI
```
`onion_fetch` / `onion_search` automatically prefer the broker when configured.

## Security
- Always terminate TLS in front of it (Caddy/nginx/Cloudflare Tunnel) — never expose `:8080` raw.
- Use a long random `BROKER_TOKEN`; the Worker sends it as `Authorization: Bearer`.
- Firewall the port to Cloudflare egress where possible. Keep usage lawful and defensive.
