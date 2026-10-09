set -eu
export DEBIAN_FRONTEND=noninteractive
export PLAYWRIGHT_BROWSERS_PATH=/opt/browsers
export PUPPETEER_SKIP_DOWNLOAD=true
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
apt-get update
apt-get install -y --no-install-recommends python3 postgresql chromium ca-certificates curl wget git jq unzip vim dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap ripgrep
curl --fail --location --retry 3 https://go.dev/dl/go1.26.3.linux-amd64.tar.gz --output /tmp/go.tar.gz
node --input-type=module -e 'import fs from "node:fs"; import {createHash} from "node:crypto"; const r=await fetch("https://go.dev/dl/?mode=json&include=all"); if(!r.ok)throw Error("Go manifest failed"); const releases=await r.json(); const f=releases.find(r=>r.version==="go1.26.3")?.files.find(f=>f.filename==="go1.26.3.linux-amd64.tar.gz"); if(!f || createHash("sha256").update(fs.readFileSync("/tmp/go.tar.gz")).digest("hex")!==f.sha256)throw Error("Go checksum failed");'
tar -xzf /tmp/go.tar.gz -C /usr/local
cd /app/source/runtime
CGO_ENABLED=0 /usr/local/go/bin/go test -p 2 ./service -run TestGary -count=1
CGO_ENABLED=0 /usr/local/go/bin/go build -p 2 -o /app/gary ./cmd/gary-tools
npm install -g @playwright/mcp@0.0.83 @playwright/cli@0.1.22 playwright@1.64.0 puppeteer@25.13.0
playwright install --with-deps chromium
mkdir -p /opt/google/chrome
ln -sf /usr/bin/chromium /opt/google/chrome/chrome
mkdir -p /app/data /app/skills
cp -R /app/source/skills/. /app/skills/
cp /app/source/bootstrap.py /app/bootstrap.py
chown -R node:node /app/data /app/skills
chmod 755 /app/gary
rm -f /tmp/go.tar.gz
rm -rf /var/lib/apt/lists/*
