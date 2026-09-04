// Pure harness utilities. Keeping these outside the Worker entry point makes the
// routing, evidence budgeting, and stream parsing independently testable.

const EMAIL_RE = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g;
const DOMAIN_RE = /\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi;
const BAD_DOMAIN_SUFFIX = /\.(md|txt|js|json|png|jpe?g|gif|svg|webp|exe|dll|so|sh|py|c|go|rs|html?|css|yml|yaml|toml|pdf|zip)$/i;

const uniq = values => [...new Set(values || [])];

export function normalizeTarget(target) {
  const value = String(target || '').trim().toLowerCase();
  if (!value) return '';
  try { return new URL(value).hostname.toLowerCase(); }
  catch { return value.replace(/^https?:\/\//, '').split('/')[0].trim(); }
}

export function collectToolTargets(bodyTarget, args = {}) {
  const optionNames = new Set(['braveKey', 'profile', 'focus', 'mode', 'ports', 'timing', 'scope']);
  const raw = [
    bodyTarget,
    ...Object.entries(args)
      .filter(([name, value]) => !optionNames.has(name) && typeof value === 'string')
      .map(([, value]) => value),
  ];
  return uniq(raw.map(value => normalizeTarget(value) || String(value || '').trim().toLowerCase()).filter(Boolean));
}

export function resolveScopedRedirect(current, location, scopedHost = '') {
  const base = new URL(current);
  const next = new URL(location, base);
  const allowedHost = String(scopedHost || base.hostname).toLowerCase();
  if (next.hostname.toLowerCase() !== allowedHost) throw new Error(`Cross-host redirect to ${next.hostname} is outside the authorized target.`);
  return next;
}

export function removeSessionIndexEntry(index, id) {
  return (Array.isArray(index) ? index : []).filter(item => (typeof item === 'string' ? item : item?.id) !== id);
}

export function isPublicIpv4(ip) {
  const octets = String(ip || '').split('.');
  if (octets.length !== 4 || !octets.every(o => /^\d{1,3}$/.test(o) && +o >= 0 && +o <= 255)) return false;
  const n = octets.reduce((value, octet) => ((value << 8) | +octet) >>> 0, 0);
  const inRange = (start, end) => n >= start && n <= end;
  const v4 = (a, b = 0, c = 0, d = 0) => ((((a << 24) >>> 0) | (b << 16) | (c << 8) | d) >>> 0);
  return ![
    [v4(0), v4(0, 255, 255, 255)],             // current network / software
    [v4(10), v4(10, 255, 255, 255)],            // RFC 1918
    [v4(100, 64), v4(100, 127, 255, 255)],       // carrier-grade NAT
    [v4(127), v4(127, 255, 255, 255)],           // loopback
    [v4(169, 254), v4(169, 254, 255, 255)],       // link-local / metadata
    [v4(172, 16), v4(172, 31, 255, 255)],         // RFC 1918
    [v4(192, 0, 0), v4(192, 0, 0, 255)],          // IETF protocol assignments
    [v4(192, 0, 2), v4(192, 0, 2, 255)],          // documentation
    [v4(192, 88, 99), v4(192, 88, 99, 255)],      // deprecated 6to4 relay
    [v4(192, 168), v4(192, 168, 255, 255)],        // RFC 1918
    [v4(198, 18), v4(198, 19, 255, 255)],          // benchmarking
    [v4(198, 51, 100), v4(198, 51, 100, 255)],     // documentation
    [v4(203, 0, 113), v4(203, 0, 113, 255)],       // documentation
    [v4(224), v4(255, 255, 255, 255)],             // multicast / reserved / broadcast
  ].some(([start, end]) => inRange(start, end));
}

export function extractSecurityTargets(query, options = {}) {
  const text = String(query || '');
  const emails = uniq(text.match(EMAIL_RE) || []);
  // An email address is an email target, not an instruction to recon its domain.
  const domainText = text.replace(EMAIL_RE, ' ');
  const cveIds = uniq((text.match(/CVE-\d{4}-\d+/gi) || []).map(x => x.toUpperCase()));
  const allIps = uniq(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])
    .filter(ip => ip.split('.').every(o => +o >= 0 && +o <= 255));
  const urls = uniq(text.match(/https?:\/\/[^\s)\]}>,]+/gi) || []);
  const hashes = uniq((text.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/ig) || []).map(x => x.toLowerCase()));
  const onions = uniq((text.match(/\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b/ig) || []).map(x => x.toLowerCase()));
  const crypto = uniq(text.match(/\b(?:bc1[a-z0-9]{20,62}|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b/g) || []);
  const handles = uniq((text.match(/(?:^|\s)@([A-Za-z0-9_]{2,30})/g) || []).map(s => s.trim().replace(/^@/, '')));
  const domSet = new Set();
  urls.forEach(u => { try { domSet.add(new URL(u).hostname.toLowerCase()); } catch {} });
  (domainText.match(DOMAIN_RE) || []).forEach(d => domSet.add(d.toLowerCase()));
  const excluded = (options.excludeDomains || []).map(d => String(d).toLowerCase());
  const domains = [...domSet]
    .filter(d => !/^\d+\.\d+\.\d+\.\d+$/.test(d))
    .filter(d => !BAD_DOMAIN_SUFFIX.test(d))
    .filter(d => !excluded.some(x => d === x || d.endsWith('.' + x)));
  return { cveIds, ips: allIps, publicIps: allIps.filter(isPublicIpv4), domains, urls, emails, hashes, onions, crypto, handles };
}

export function extractAiText(value) {
  if (typeof value === 'string') return value;
  if (!value || typeof value !== 'object') return '';
  const candidates = [
    value.response,
    value.result && value.result.response,
    value.output_text,
    value.choices?.[0]?.delta?.content,
    value.choices?.[0]?.message?.content,
    value.choices?.[0]?.text,
    value.result?.choices?.[0]?.delta?.content,
    value.result?.choices?.[0]?.message?.content,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === 'string') return candidate;
    if (Array.isArray(candidate)) {
      const text = candidate.map(part => typeof part === 'string' ? part : (part?.text || part?.content || '')).join('');
      if (text) return text;
    }
  }
  return '';
}

export function renderBalancedContext(blocks, budget = 9000, maxPerBlock = 1800) {
  const clean = (blocks || []).map(String).filter(Boolean);
  if (!clean.length || budget <= 0) return '';
  const separators = Math.max(0, clean.length - 1) * 2;
  const usable = Math.max(0, budget - separators);
  const share = Math.max(1, Math.min(maxPerBlock, Math.floor(usable / clean.length)));
  return clean.map(block => block.slice(0, share)).join('\n\n').slice(0, budget);
}

export function toolCallKey(tool, arg) {
  return `${String(tool || '').trim().toLowerCase()}::${String(arg || '').trim().toLowerCase()}`;
}

export function buildIntelPlan(targets, profile = 'full') {
  const plan = [];
  const add = (tool, args) => plan.push({ tool, args, via: 'builtin' });
  for (const cveId of (targets.cveIds || []).slice(0, 3)) {
    add('nvd_lookup', { cveId, target: cveId });
    add('epss_lookup', { cveId, target: cveId });
    add('kev_lookup', { cveId, target: cveId });
  }
  for (const ip of (targets.ips || []).slice(0, 2)) {
    add('rdap_ip', { ip, target: ip });
    add('reverse_dns', { ip, target: ip });
    if (profile === 'full') add('shodan_internetdb', { ip, target: ip });
    add('ip_geo', { ip, target: ip });
    if (profile === 'full') add('asn_info', { ip, target: ip });
  }
  for (const domain of (targets.domains || []).slice(0, 2)) {
    add('rdap_domain', { domain, target: domain });
    add('dns_lookup', { domain, target: domain });
    add('cert_ct', { domain, target: domain });
    if (profile === 'full') {
      add('wayback', { domain, target: domain });
      add('urlscan', { domain, target: domain });
    }
  }
  return plan;
}

export function splitSseLines(buffer, flush = false) {
  const normalized = String(buffer || '').replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  const remainder = flush ? '' : lines.pop();
  if (flush && lines[lines.length - 1] === '') lines.pop();
  return { lines, remainder };
}
