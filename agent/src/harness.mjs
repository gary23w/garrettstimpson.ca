// Pure harness utilities. Keeping these outside the Worker entry point makes the
// routing, evidence budgeting, and stream parsing independently testable.

const EMAIL_RE = /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g;
const DOMAIN_RE = /\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi;
const BAD_DOMAIN_SUFFIX = /\.(md|txt|js|json|png|jpe?g|gif|svg|webp|exe|dll|so|sh|py|c|go|rs|html?|css|yml|yaml|toml|pdf|zip)$/i;

const PS_ARRAY_JOIN_LIMITS = Object.freeze({
  inputChars: 256 * 1024,
  expressionChars: 32 * 1024,
  attempts: 8192,
  expressions: 1024,
  literals: 128,
  literalChars: 4096,
  indices: 256,
  candidateChars: 4096,
});

const WINDOWS_PERSISTENCE_LIMITS = Object.freeze({
  inputChars: 256 * 1024,
  segments: 4096,
  artifactMatchesPerMechanism: 16,
  creationMatchesPerMechanism: 16,
  findings: 64,
  continuityFindings: 16,
  snippetChars: 320,
});

// One string-only argument vocabulary is shared by the direct HTTP and MCP
// surfaces. Tool implementations may use several of these as aliases, but no
// surface may silently discard an unexpected key or coerce a structured value.
export const TOOL_INPUT_STRING_KEYS = Object.freeze([
  'target', 'url', 'domain', 'ip', 'email', 'hash', 'query', 'vector', 'input', 'text',
  'username', 'user', 'host', 'cveId', 'cve', 'address', 'addr', 'onion', 'profile',
  'focus', 'path', 'image', 'sample', 'file', 'uri', 'endpoint', 'website', 'link',
  'asn', 'password', 'pw', 'keyword', 'count', 'technique', 'id', 'name', 'term',
  'phone', 'number', 'selector', 'cidr', 'mode', 'ports', 'timing', 'scope', 'token',
  'braveKey',
]);
const TOOL_INPUT_STRING_KEY_SET = new Set(TOOL_INPUT_STRING_KEYS);

const REGISTRY_WRITE_RE = /\b(?:reg(?:\.exe)?\s+add|Set-ItemProperty|New-ItemProperty|regini(?:\.exe)?|RegSetValue(?:Ex)?[AW]?\s*\()/i;
const FILE_WRITE_RE = /\b(?:Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|New-Item|WriteAll(?:Text|Bytes))\b/i;
const CONTROL_OR_NEGATION_RE = /\b(?:no|not|never|without|did\s+not|does\s+not|was\s+not|were\s+not|failed\s+to|blocked|prevented|denied|disabled|removed|deleted|cleanup|negative\s+control|control\s+only|educational|example|pseudocode|skeleton|detection|detect|hunt|alert|monitor|watch\s+for)\b/i;
const BEHAVIOR_SUBJECT_RE = /\b(?:actor|binary|campaign|dropper|implant|loader|malware|payload|process|rat|sample|stealer|trojan|it)\b/i;
const BEHAVIOR_ACTION_RE = /\b(?:add(?:s|ed)?|configur(?:e|es|ed)|cop(?:y|ies|ied)|creat(?:e|es|ed)|establish(?:es|ed)?|install(?:s|ed)?|load(?:s|ed)?|modif(?:y|ies|ied)|persist(?:s|ed)?|register(?:s|ed)?|relaunch(?:es|ed)?|run(?:s)?\s+at\s+(?:logon|startup)|set(?:s)?|surviv(?:e|es|ed)\s+(?:a\s+)?reboot|writ(?:e|es|ten|ing)|wrote)\b/i;
const CONFIG_BEHAVIOR_ACTION_RE = /\b(?:add(?:s|ed)?|configur(?:e|es|ed)|creat(?:e|es|ed)|establish(?:es|ed)?|install(?:s|ed)?|modif(?:y|ies|ied)|persist(?:s|ed)?|register(?:s|ed)?|run(?:s)?\s+at\s+(?:logon|startup)|set(?:s)?|surviv(?:e|es|ed)\s+(?:a\s+)?reboot|writ(?:e|es|ten|ing)|wrote)\b/i;
const PERSISTENCE_CLAIM_RE = /\bpersistence\s+(?:arrives|came|comes|is|was|works)\s+(?:by|from|through|via|with)\b|\b(?:entry|job|service|subscription|task|value)\s+(?:has\s+been|is|was)\s+(?:added|configured|created|installed|modified|registered|set|written)\b/i;
const DIRECT_BEHAVIOR_GAP_RE = /^\s*(?:(?:an?|the|its|new|existing|was|were|is|has\s+been|had\s+been)\s+)*$/i;
const FILE_TARGET_BEHAVIOR_GAP_RE = /^\s*(?:(?:itself|(?:an?\s+|the\s+)?(?:payload|binary|file|link|value|entry)|[^\s,;]+\.(?:bat|cmd|com|dll|exe|js|jse|lnk|ps1|psd1|psm1|scr|vbe|vbs|wsf))\s+)?(?:in|into|through|to|via)\s+(?:[%A-Za-z0-9_.$:{}()\-]+[\\/])*\s*$/i;

const WINDOWS_PERSISTENCE_MECHANISMS = Object.freeze([
  {
    family: 'Registry Run/RunOnce or Startup folder',
    mitre: 'T1547.001',
    expectedScope: 'HKCU and the per-user Startup folder are normally same-user scope; HKLM or the common Startup folder normally requires administrator rights.',
    artifact: /\b(?:(?:HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKCU|HKLM)(?::)?[\\/]+(?:SOFTWARE[\\/]+)?Microsoft[\\/]+Windows[\\/]+CurrentVersion[\\/]+Run(?:Once)?|(?:registry\s+)?Run(?:Once)?\s+key)\b|\b(?:shell:(?:common\s+)?startup|Start Menu[\\/]+Programs[\\/]+Startup|common Startup folder|per-user Startup folder)\b/i,
    creation: new RegExp(`${REGISTRY_WRITE_RE.source}|${FILE_WRITE_RE.source}`, 'i'),
    creationMatchApplies(creationMatch, artifactMatch) {
      const runArtifact = /CurrentVersion[\\/]+Run(?:Once)?\b|\bRun(?:Once)?\s+key\b/i.test(artifactMatch[0]);
      return runArtifact ? REGISTRY_WRITE_RE.test(creationMatch[0]) : FILE_WRITE_RE.test(creationMatch[0]);
    },
    matchedArtifact(snippet, artifactMatch) {
      return startupArtifactLocation(snippet, artifactMatch);
    },
    behaviorAction: BEHAVIOR_ACTION_RE,
    scope(snippet, artifactMatch) {
      const machineRun = /\b(?:HKEY_LOCAL_MACHINE|HKLM)(?::)?[\\/]+(?:SOFTWARE[\\/]+)?Microsoft[\\/]+Windows[\\/]+CurrentVersion[\\/]+Run(?:Once)?\b/i;
      const userRun = /\b(?:HKEY_CURRENT_USER|HKCU)(?::)?[\\/]+(?:SOFTWARE[\\/]+)?Microsoft[\\/]+Windows[\\/]+CurrentVersion[\\/]+Run(?:Once)?\b/i;
      const commonStartup = /\bshell:common\s+startup\b|\bcommon Startup folder\b|\bProgramData[\\/]+Microsoft[\\/]+Windows[\\/]+Start Menu[\\/]+Programs[\\/]+Startup\b/i;
      const userStartup = /\bshell:startup\b|\bper-user Startup folder\b|(?:%APPDATA%|AppData[\\/]+Roaming)[\\/]+Microsoft[\\/]+Windows[\\/]+Start Menu[\\/]+Programs[\\/]+Startup\b/i;
      const artifact = artifactMatch?.[0] || '';
      if (machineRun.test(artifact)) {
        return 'Machine/all-users scope normally requires administrator rights; verify the actual hive, folder ACL, and resulting principal.';
      }
      if (userRun.test(artifact)) {
        return 'Expected current-user self-scope when the artifact is HKCU or that user\'s Startup folder; this alone is not a Windows boundary violation.';
      }
      const location = startupArtifactLocation(snippet, artifactMatch);
      if (commonStartup.test(location)) {
        return 'Machine/all-users scope normally requires administrator rights; verify the actual hive, folder ACL, and resulting principal.';
      }
      if (userStartup.test(location)) {
        return 'Expected current-user self-scope when the artifact is HKCU or that user\'s Startup folder; this alone is not a Windows boundary violation.';
      }
      return 'The Run-key hive or Startup-folder owner is unresolved; do not infer current-user or machine authority from an unqualified autorun mention.';
    },
  },
  {
    family: 'Scheduled Task/Job',
    mitre: 'T1053.005',
    expectedScope: 'A standard user may create only permitted same-SID/LUA task shapes; protected, SYSTEM, highest-run-level, or other-principal tasks require additional authority.',
    artifact: /\b(?:schtasks(?:\.exe)?|Register-ScheduledTask|Set-ScheduledTask|New-ScheduledTask(?:Action|Trigger)?|scheduled tasks?|TaskCache[\\/]+(?:Tasks|Tree)|System32[\\/]+Tasks)\b/i,
    creation: /\bschtasks(?:\.exe)?\s+\/create\b|\b(?:Register|Set)-ScheduledTask\b/i,
  },
  {
    family: 'Windows Service/ServiceDll',
    mitre: 'T1543.003',
    expectedScope: 'Creating or changing an SCM service normally requires administrator-granted rights; a ServiceDll/path mention alone does not show those rights were obtained.',
    artifact: /\b(?:sc(?:\.exe)?\s+(?:create|config)|New-Service|Set-Service|CreateService[AW]?|ServiceDll|auto-?start service|Windows service persistence)\b|CurrentControlSet[\\/]+Services[\\/]/i,
    creation: new RegExp(`\\bsc(?:\\.exe)?\\s+(?:create|config)\\b|\\b(?:New-Service|Set-Service)\\b|${REGISTRY_WRITE_RE.source}`, 'i'),
  },
  {
    family: 'WMI Permanent Event Subscription',
    mitre: 'T1546.003',
    expectedScope: 'Creation in root\\subscription is commonly administrator-controlled; verify namespace ACLs and the consumer principal rather than assuming elevation.',
    artifact: /\b(?:__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|FilterToConsumerBinding|permanent WMI event subscription|WMI event subscription)\b|root[\\/]subscription/i,
    creation: /\b(?:Set-WmiInstance|New-CimInstance|wmic(?:\.exe)?)\b.*\b(?:__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|FilterToConsumerBinding|root[\\/]subscription)\b|\b(?:__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|FilterToConsumerBinding)\b.*\b(?:create|put)\b/i,
  },
  {
    family: 'Winlogon Helper',
    mitre: 'T1547.004',
    expectedScope: 'Machine Winlogon configuration is normally administrator-controlled; an HKCU mention is user-scoped and still requires proof that the relevant consumer honors it.',
    artifact: /Microsoft[\\/]+Windows NT[\\/]+CurrentVersion[\\/]+Winlogon\b|\bWinlogon[\\/\s]+(?:Shell|Userinit|Notify)\b/i,
    creation: REGISTRY_WRITE_RE,
  },
  {
    family: 'IFEO/SilentProcessExit',
    mitre: 'T1546.012',
    expectedScope: 'The normal machine-wide IFEO/SilentProcessExit configuration is administrator-controlled; verify hive, ACL, target image, and trigger behavior.',
    artifact: /\b(?:Image File Execution Options|SilentProcessExit|MonitorProcess)\b|Image File Execution Options[\\/]/i,
    creation: REGISTRY_WRITE_RE,
  },
  {
    family: 'AppInit/AppCert DLL',
    mitre: 'T1546.009 / T1546.010',
    expectedScope: 'AppInit_DLLs and AppCertDlls are normally machine configuration requiring administrator rights; a string or API reference is capability evidence only.',
    artifact: /\b(?:AppInit_DLLs|LoadAppInit_DLLs|RequireSignedAppInit_DLLs|AppCertDlls)\b/i,
    creation: REGISTRY_WRITE_RE,
  },
  {
    family: 'COM Hijacking',
    mitre: 'T1546.015',
    expectedScope: 'HKCU COM registration is normally same-user scope; HKLM registration normally requires administrator rights. Impact depends on which consumer loads the class.',
    artifact: /(?:HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKCU|HKLM)(?::)?[\\/]+Software[\\/]+Classes[\\/]+CLSID[\\/]+(?:[^\\/\s]+(?:[\\/]+(?:InprocServer32|LocalServer32))?)?|\b(?:InprocServer32|LocalServer32|COM (?:object )?hijack(?:ing)?)\b/i,
    creation: REGISTRY_WRITE_RE,
    scope(_snippet, artifactMatch) {
      const artifact = artifactMatch?.[0] || '';
      return /\b(?:HKEY_LOCAL_MACHINE|HKLM)\b/i.test(artifact)
        ? 'HKLM COM registration normally requires administrator rights; verify the consumer and effective ACL.'
        : /\b(?:HKEY_CURRENT_USER|HKCU)\b/i.test(artifact)
          ? 'HKCU COM registration is expected same-user authority; a cross-principal consumer must be proven for a boundary claim.'
          : 'The hive and consumer are unknown; do not infer current-user or machine authority from a hive-less COM string.';
    },
  },
  {
    family: 'BITS Job',
    mitre: 'T1197',
    expectedScope: 'A user can manage that user\'s BITS jobs; another user or SYSTEM job requires a distinct authority path. A job or API mention is not reboot persistence by itself.',
    artifact: /\b(?:bitsadmin(?:\.exe)?|Start-BitsTransfer|SetNotifyCmdLine|NotifyCmdLine|BITS jobs?|Background Intelligent Transfer Service job)\b/i,
    creation: /\bbitsadmin(?:\.exe)?\s+\/(?:addfile|create|setnotifycmdline)\b|\bSetNotifyCmdLine\b/i,
  },
  {
    family: 'PowerShell Profile/Module Search Path',
    mitre: 'T1546.013 (profiles) / T1574.008 (module search path)',
    expectedScope: 'A user-owned profile or module path is normally same-user scope; all-users paths or a higher-privilege consumer require additional authority and proof.',
    artifact: /\$PROFILE\b|\bMicrosoft\.PowerShell_profile\.ps1\b|(?:^|[\\/])profile\.ps1\b|Documents[\\/]+(?:Windows)?PowerShell(?:[\\/]+Modules)?\b|\bPSModulePath\b|\bPowerShell (?:profile|module (?:path|autoload))\b/i,
    creation: new RegExp(`${FILE_WRITE_RE.source}|(?:>>?|2>)\\s*["']?\\$PROFILE\\b`, 'i'),
    behaviorAction: BEHAVIOR_ACTION_RE,
  },
]);

function startupArtifactLocation(snippet, artifactMatch) {
  const artifact = artifactMatch?.[0] || '';
  if (!/Start Menu[\\/]+Programs[\\/]+Startup/i.test(artifact)) return artifact;
  const artifactStart = Number.isInteger(artifactMatch?.index) ? artifactMatch.index : 0;
  const end = artifactStart + artifact.length;
  const start = Math.max(0, artifactStart - 256);
  const window = snippet.slice(start, end);
  const anchors = [/%APPDATA%/ig, /AppData[\\/]+Roaming/ig, /ProgramData/ig];
  let nearest = -1;
  for (const pattern of anchors) {
    for (const match of window.matchAll(pattern)) nearest = Math.max(nearest, match.index);
  }
  if (nearest < 0) {
    const prefix = snippet.slice(0, artifactStart);
    const boundary = Math.max(prefix.lastIndexOf(' and '), prefix.lastIndexOf(';'), prefix.lastIndexOf(','), prefix.lastIndexOf('\n'));
    return snippet.slice(boundary < 0 ? artifactStart : boundary + 1, end).trim();
  }
  return window.slice(nearest);
}

const uniq = values => [...new Set(values || [])];

function confidenceLabel(score) {
  if (score >= 0.8) return 'high';
  if (score >= 0.6) return 'medium';
  return 'low';
}

export function assessToolEvidence(spec = {}, result = '') {
  const text = String(result || '');
  const lowSignal = /(unknown|unavailable|failed|error|timeout|no record|none\/private|not found|lookup failed|UNKNOWN)/i;
  const strongSignal = /(CISA KEV: LISTED|cvss|epss|rdap|DNS |sha256|asn|provider|snapshot|GitHub public user)/i;
  let score = spec.passive ? 0.72 : 0.62;
  if (spec.category === 'intel') score += 0.08;
  if (spec.category === 'search') score -= 0.08;
  if (!text.trim()) score = 0.2;
  if (lowSignal.test(text)) score -= 0.28;
  if (strongSignal.test(text)) score += 0.08;
  if (text.length > 280) score += 0.03;
  score = Math.max(0.1, Math.min(0.95, score));

  if (spec.name === 'persistence_analyze') {
    // Lexical matches can be useful leads, but never establish execution or a
    // boundary crossing. Keep that distinction in machine-readable metadata too.
    score = Math.min(score, 0.55);
    return { score: +score.toFixed(2), label: confidenceLabel(score), uncertain: true, basis: 'textual-evidence-only' };
  }
  return {
    score: +score.toFixed(2),
    label: confidenceLabel(score),
    uncertain: lowSignal.test(text) || score < 0.65,
    basis: 'tool-result',
  };
}

export function toolEvidenceMetadata(spec = {}, result = '') {
  const assessed = assessToolEvidence(spec, result);
  return {
    confidence: assessed.label,
    confidenceScore: assessed.score,
    uncertain: assessed.uncertain,
    evidenceBasis: assessed.basis,
  };
}

const NON_CACHEABLE_TOOL_RESULTS = new Set([
  'breach_check',
  'email_recon',
  'exposure_search',
  'holehe',
  'leakcheck',
  'persistence_analyze',
  'pwned_password',
  'stealer_check',
]);

export function shouldCacheToolResult(toolName) {
  return !NON_CACHEABLE_TOOL_RESULTS.has(String(toolName || '').trim().toLowerCase());
}

const isPsSpace = char => char === ' ' || char === '\t' || char === '\r' || char === '\n';
const isAsciiDigit = char => !!char && char >= '0' && char <= '9';
const isPsIdentifierChar = char => !!char && (
  (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || isAsciiDigit(char) || char === '_'
);

function skipPsSpace(source, offset, end = source.length) {
  let cursor = offset;
  while (cursor < end && isPsSpace(source[cursor])) cursor++;
  return cursor;
}

function parseStaticPsString(source, offset, expressionStart) {
  const quote = source[offset];
  if (quote !== "'" && quote !== '"') return null;
  let value = '';
  let cursor = offset + 1;
  while (cursor < source.length && cursor - expressionStart <= PS_ARRAY_JOIN_LIMITS.expressionChars) {
    const char = source[cursor];
    if (char === quote) {
      if (quote === "'" && source[cursor + 1] === "'") {
        if (value.length >= PS_ARRAY_JOIN_LIMITS.literalChars) return null;
        value += "'";
        cursor += 2;
        continue;
      }
      return { value, end: cursor + 1 };
    }
    // Double-quoted PowerShell strings can interpolate variables/subexpressions and
    // backtick escapes. Leave those dynamic forms to a real parser rather than guess.
    if (quote === '"' && (char === '$' || char === '`')) return null;
    if (value.length >= PS_ARRAY_JOIN_LIMITS.literalChars) return null;
    value += char;
    cursor++;
  }
  return null;
}

function isPsExpressionDelimiter(char) {
  return !char || isPsSpace(char) || char === ')' || char === '|' || char === ';' || char === ',' || char === '}';
}

function parseStaticPsArrayJoinAt(source, start) {
  let arrayKind = '';
  let arrayOffset = start;
  if (source[start] === '@' && source[start + 1] === '(') {
    arrayKind = '@(...)';
    arrayOffset = start + 2;
  } else if (source[start] === '(') {
    arrayKind = '(...)';
    arrayOffset = start + 1;
  } else {
    return null;
  }
  const expressionEnd = Math.min(source.length, start + PS_ARRAY_JOIN_LIMITS.expressionChars);
  const withinBound = cursor => cursor <= expressionEnd;
  let cursor = skipPsSpace(source, arrayOffset, expressionEnd);
  const literals = [];

  while (withinBound(cursor)) {
    if (literals.length >= PS_ARRAY_JOIN_LIMITS.literals) return null;
    const literal = parseStaticPsString(source, cursor, start);
    if (!literal) return null;
    literals.push(literal.value);
    cursor = skipPsSpace(source, literal.end, expressionEnd);
    if (source[cursor] === ',') {
      cursor = skipPsSpace(source, cursor + 1, expressionEnd);
      continue;
    }
    if (source[cursor] === ')') {
      cursor++;
      break;
    }
    return null;
  }
  if (!literals.length || !withinBound(cursor)) return null;

  cursor = skipPsSpace(source, cursor, expressionEnd);
  if (source[cursor] !== '[') return null;
  cursor = skipPsSpace(source, cursor + 1, expressionEnd);
  const indices = [];
  while (withinBound(cursor)) {
    if (indices.length >= PS_ARRAY_JOIN_LIMITS.indices) return null;
    let sign = 1;
    if (source[cursor] === '-') {
      sign = -1;
      cursor++;
    }
    if (!isAsciiDigit(source[cursor])) return null;
    const numberStart = cursor;
    while (cursor < expressionEnd && isAsciiDigit(source[cursor]) && cursor - numberStart <= 6) cursor++;
    if (cursor - numberStart > 6) return null;
    const requestedIndex = sign * Number(source.slice(numberStart, cursor));
    const index = requestedIndex < 0 ? literals.length + requestedIndex : requestedIndex;
    if (!Number.isSafeInteger(index) || index < 0 || index >= literals.length) return null;
    indices.push(index);
    cursor = skipPsSpace(source, cursor, expressionEnd);
    if (source[cursor] === ',') {
      cursor = skipPsSpace(source, cursor + 1, expressionEnd);
      continue;
    }
    if (source[cursor] === ']') {
      cursor++;
      break;
    }
    return null;
  }
  if (!indices.length || !withinBound(cursor)) return null;

  cursor = skipPsSpace(source, cursor, expressionEnd);
  if (source.slice(cursor, cursor + 5).toLowerCase() !== '-join' || isPsIdentifierChar(source[cursor + 5])) return null;
  cursor = skipPsSpace(source, cursor + 5, expressionEnd);

  let assumption = '';
  const separatorStart = cursor;
  if (source[cursor] === "'" || source[cursor] === '"') {
    const separator = parseStaticPsString(source, cursor, start);
    if (!separator || separator.value !== '') return null;
    cursor = separator.end;
  } else if (source[cursor] === '$') {
    cursor++;
    const nameStart = cursor;
    while (cursor < expressionEnd && isPsIdentifierChar(source[cursor])) cursor++;
    if (cursor === nameStart) return null;
    const variable = source.slice(separatorStart, cursor);
    if (variable.toLowerCase() !== '$null') {
      assumption = `separator variable ${variable} is unresolved; candidate assumes it is empty`;
    }
  } else {
    return null;
  }
  if (!withinBound(cursor) || !isPsExpressionDelimiter(source[cursor])) return null;

  let value = '';
  for (const index of indices) {
    if (value.length + literals[index].length > PS_ARRAY_JOIN_LIMITS.candidateChars) return null;
    value += literals[index];
  }
  return { start, end: cursor, value, assumption, arrayKind };
}

function collectStaticPsArrayStarts(source) {
  const starts = [];
  let quote = '';
  for (let cursor = 0; cursor < source.length; cursor++) {
    const char = source[cursor];
    if (quote) {
      if (quote === "'" && char === "'" && source[cursor + 1] === "'") {
        cursor++;
        continue;
      }
      if (quote === '"' && char === '`') {
        cursor++;
        continue;
      }
      if (char === quote) quote = '';
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === '@' && source[cursor + 1] === '(') {
      starts.push(cursor);
      cursor++;
      continue;
    }
    if (char !== '(' || source[cursor - 1] === '@') continue;
    let lookahead = cursor + 1;
    while (lookahead < source.length && isPsSpace(source[lookahead])) lookahead++;
    if (source[lookahead] === "'" || source[lookahead] === '"') starts.push(cursor);
  }
  return starts;
}

function selectCoverage(items, limit) {
  if (items.length <= limit) return items;
  if (limit <= 1) return [items[items.length - 1]];
  const selected = [];
  for (let slot = 0; slot < limit; slot++) {
    const index = Math.floor(slot * (items.length - 1) / (limit - 1));
    selected.push(items[index]);
  }
  return selected;
}

// Statically recover a narrow PowerShell obfuscation idiom without invoking a
// PowerShell parser or evaluator: @('pieces')[index,order] (or the parenthesized
// literal-array form) joined with an empty-ish separator. Negative indices use
// PowerShell's end-relative array semantics.
// Unknown separator variables are useful triage leads, but are explicitly marked
// as assumptions. Dynamic strings, selectors, indices and non-empty joins fail closed.
export function deobfuscatePowerShellArrayJoins(input) {
  const source = String(input || '');
  if (!source || source.length > PS_ARRAY_JOIN_LIMITS.inputChars) {
    return { text: source, confirmedText: source, candidates: [], limitReached: source.length > PS_ARRAY_JOIN_LIMITS.inputChars };
  }

  const allStarts = collectStaticPsArrayStarts(source);
  const starts = selectCoverage(allStarts, PS_ARRAY_JOIN_LIMITS.attempts);
  const parsedCandidates = starts
    .map(start => parseStaticPsArrayJoinAt(source, start))
    .filter(Boolean)
    .sort((left, right) => left.start - right.start || right.end - left.end);

  // Prefer the outermost expression at each position and discard overlaps before
  // coverage sampling. This keeps replacement deterministic even when a literal
  // contains text that itself resembles another array expression.
  const nonOverlapping = [];
  let previousEnd = -1;
  for (const candidate of parsedCandidates) {
    if (candidate.start < previousEnd) continue;
    nonOverlapping.push(candidate);
    previousEnd = candidate.end;
  }
  const candidates = selectCoverage(nonOverlapping, PS_ARRAY_JOIN_LIMITS.expressions);
  const limitReached = allStarts.length > starts.length || nonOverlapping.length > candidates.length;
  if (!candidates.length) return { text: source, confirmedText: source, candidates, limitReached };

  const chunks = [];
  const confirmedChunks = [];
  let copiedThrough = 0;
  for (const candidate of candidates) {
    const original = source.slice(candidate.start, candidate.end);
    chunks.push(source.slice(copiedThrough, candidate.start), candidate.value);
    confirmedChunks.push(source.slice(copiedThrough, candidate.start), candidate.assumption ? original : candidate.value);
    copiedThrough = candidate.end;
  }
  chunks.push(source.slice(copiedThrough));
  confirmedChunks.push(source.slice(copiedThrough));
  return {
    text: chunks.join(''),
    confirmedText: confirmedChunks.join(''),
    candidates: candidates.map(candidate => ({
      value: candidate.value,
      assumption: candidate.assumption,
      start: candidate.start,
      end: candidate.end,
      arrayKind: candidate.arrayKind,
    })),
    limitReached,
  };
}

export function buildPowerShellIocEvidence(input) {
  const source = String(input || '');
  const deobfuscation = deobfuscatePowerShellArrayJoins(source);
  return {
    deobfuscation,
    confirmedEvidenceText: source + (deobfuscation.confirmedText !== source ? '\n' + deobfuscation.confirmedText : ''),
  };
}

function evidenceSegments(source) {
  return String(source || '')
    .split(/\r?\n|[.!?]\s+(?=[A-Z])|[,;]?\s+(?:but|however|whereas|while|although|yet)\s+|[,;]?\s+and\s+(?=(?:no|not|never|did\s+not|does\s+not|was\s+not|were\s+not)\b)/i)
    .map(value => value.trim())
    .filter(Boolean);
}

function boundedEvidenceSnippet(value) {
  const clean = String(value || '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return clean.slice(0, WINDOWS_PERSISTENCE_LIMITS.snippetChars) +
    (clean.length > WINDOWS_PERSISTENCE_LIMITS.snippetChars ? '…' : '');
}

function contextProseOnly(segment) {
  return String(segment || '')
    .replace(/\[[^\]\r\n]{0,256}\]\(\s*https?:\/\/[^)\s]+\s*\)/gi, ' ')
    .replace(/\bhttps?:\/\/[^\s<>"')\]]+/gi, ' ')
    .replace(/\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi, ' ')
    .replace(/(["'])(?:(?:(?:[A-Za-z]:|%[A-Za-z0-9_]+%|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKCU|HKLM)[\\/])|\\\\)[^"'\r\n]*\1/gi, ' ');
}

function evidenceContext(segment) {
  const flags = [];
  if (CONTROL_OR_NEGATION_RE.test(contextProseOnly(segment))) flags.push('negation/control/example language is present');
  if (/^\s*(?:#|\/\/|;)\s*/.test(segment)) flags.push('the match appears in a comment or example-like line');
  return flags;
}

function boundedRegexMatches(pattern, source, limit = 32) {
  const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
  const matcher = new RegExp(pattern.source, flags);
  const matches = [];
  let match;
  while (matches.length < limit && (match = matcher.exec(source))) {
    matches.push(match);
    if (!match[0]) matcher.lastIndex++;
  }
  return matches;
}

function evidenceSpansShareClause(source, left, right, gapMode = 'claim') {
  const first = left.index <= right.index ? left : right;
  const second = first === left ? right : left;
  const gapStart = first.index + first[0].length;
  if (gapStart >= second.index) return true;
  const gap = source.slice(gapStart, second.index);
  if (gap.length > 192 || /(?:[,;]|[.!?]\s+(?=[A-Z]))/.test(gap)) return false;
  if (/\b(?:and|although|but|however|whereas|while|yet)\b/i.test(gap)) return false;
  if (gapMode === 'config' && !DIRECT_BEHAVIOR_GAP_RE.test(gap)) return false;
  if (gapMode === 'file-target' && !DIRECT_BEHAVIOR_GAP_RE.test(gap) && !FILE_TARGET_BEHAVIOR_GAP_RE.test(gap)) return false;
  return true;
}

function looksLikeReportedBehavior(segment, mechanism, artifactMatch) {
  for (const claim of boundedRegexMatches(PERSISTENCE_CLAIM_RE, segment)) {
    if (evidenceSpansShareClause(segment, claim, artifactMatch, 'config')) return true;
  }
  if (!BEHAVIOR_SUBJECT_RE.test(segment)) return false;
  const actionPattern = mechanism.behaviorAction || CONFIG_BEHAVIOR_ACTION_RE;
  return boundedRegexMatches(actionPattern, segment)
    .some(action => evidenceSpansShareClause(segment, action, artifactMatch, mechanism.behaviorAction ? 'file-target' : 'config'));
}

function commandClauseEnd(source, start) {
  let quote = '';
  for (let cursor = start; cursor < source.length; cursor++) {
    const char = source[cursor];
    if (quote) {
      if (char === quote) quote = '';
      continue;
    }
    if (char === '"' || char === "'") { quote = char; continue; }
    if (char === '\r' || char === '\n' || char === ';' ||
        (char === '&' && source[cursor + 1] === '&') ||
        (char === '|' && source[cursor + 1] === '|')) return cursor;
  }
  return source.length;
}

function firstMatchIndex(pattern, source, offset = 0) {
  const match = pattern.exec(source.slice(offset));
  return match ? offset + match.index : -1;
}

function registryWriteTargetsArtifact(segment, creationMatch, artifactMatch) {
  const commandEnd = commandClauseEnd(segment, creationMatch.index);
  if (artifactMatch.index < creationMatch.index || artifactMatch.index >= commandEnd) return false;
  const command = segment.slice(creationMatch.index, commandEnd);
  const artifactAt = artifactMatch.index - creationMatch.index;
  let dataBoundary = -1;

  if (/^\s*reg(?:\.exe)?\s+add\b/i.test(command)) {
    dataBoundary = firstMatchIndex(/(?:^|\s)\/d(?=\s|:|$)/i, command);
  } else if (/^\s*(?:Set-ItemProperty|New-ItemProperty)\b/i.test(command)) {
    const argsStart = creationMatch.index + creationMatch[0].length;
    if (namedArgumentContainsArtifact(segment, argsStart, commandEnd, ['Path', 'LiteralPath', 'Name'], artifactMatch)) return true;
    dataBoundary = firstMatchIndex(/(?:^|\s)-(?:Value|InputObject)\b/i, command);
  } else if (/^\s*regini(?:\.exe)?\b/i.test(command)) {
    dataBoundary = firstMatchIndex(/=/, command);
  } else if (/^\s*RegSetValue(?:Ex)?[AW]?\s*\(/i.test(command)) {
    // RegSetValueEx(hKey, valueName, reserved, type, data, size): the
    // persistence artifact may identify the key/value name, but never data.
    let commas = 0;
    for (let i = command.indexOf('(') + 1; i < command.length; i++) {
      if (command[i] === ',') {
        commas++;
        if (commas === 2) { dataBoundary = i; break; }
      }
    }
  }

  return dataBoundary < 0 || artifactAt < dataBoundary;
}

function argumentTokens(source, start, end) {
  const tokens = [];
  let cursor = start;
  while (cursor < end) {
    while (cursor < end && /\s/.test(source[cursor])) cursor++;
    if (cursor >= end) break;
    const tokenStart = cursor;
    const quote = source[cursor] === '"' || source[cursor] === "'" ? source[cursor++] : '';
    if (quote) {
      while (cursor < end && source[cursor] !== quote) cursor++;
      if (cursor < end) cursor++;
    } else {
      while (cursor < end && !/\s/.test(source[cursor])) cursor++;
    }
    tokens.push({ start: tokenStart, end: cursor, text: source.slice(tokenStart, cursor) });
  }
  return tokens;
}

function namedArgumentContainsArtifact(segment, commandStart, commandEnd, names, artifactMatch) {
  const command = segment.slice(commandStart, commandEnd);
  const pattern = new RegExp(`(?:^|\\s)-(?:${names.join('|')})\\b`, 'ig');
  for (const match of command.matchAll(pattern)) {
    const valueStart = commandStart + match.index + match[0].length;
    const nextOption = segment.slice(valueStart, commandEnd).search(/\s-[A-Za-z][\w-]*\b/);
    const valueEnd = nextOption < 0 ? commandEnd : valueStart + nextOption;
    if (artifactMatch.index >= valueStart && artifactMatch.index < valueEnd) return true;
  }
  return false;
}

function fileWriteTargetsArtifact(segment, creationMatch, artifactMatch) {
  const commandEnd = commandClauseEnd(segment, creationMatch.index);
  if (artifactMatch.index < creationMatch.index || artifactMatch.index >= commandEnd) return false;
  const verb = creationMatch[0].match(/(?:Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|New-Item|WriteAll(?:Text|Bytes))/i)?.[0] || '';
  if (!verb) return true; // A redirection match includes its destination artifact.

  const commandStart = creationMatch.index;
  const argsStart = creationMatch.index + creationMatch[0].length;
  const command = segment.slice(commandStart, commandEnd);
  const artifactAt = artifactMatch.index - commandStart;

  if (/^(?:Copy-Item|Move-Item)$/i.test(verb)) {
    if (namedArgumentContainsArtifact(segment, argsStart, commandEnd, ['Destination'], artifactMatch)) return true;
    if (namedArgumentContainsArtifact(segment, argsStart, commandEnd, ['Path', 'LiteralPath'], artifactMatch)) return false;
    const positional = argumentTokens(segment, argsStart, commandEnd).filter(token => !token.text.startsWith('-'));
    const containing = positional.findIndex(token => artifactMatch.index >= token.start && artifactMatch.index < token.end);
    return containing === 1;
  }

  if (/^Out-File$/i.test(verb) && namedArgumentContainsArtifact(segment, argsStart, commandEnd, ['FilePath', 'LiteralPath'], artifactMatch)) return true;
  if (/^(?:Set-Content|Add-Content|New-Item)$/i.test(verb) && namedArgumentContainsArtifact(segment, argsStart, commandEnd, ['Path', 'LiteralPath'], artifactMatch)) return true;
  const valueBoundary = firstMatchIndex(/(?:^|\s)-(?:Value|InputObject)\b/i, command);
  if (valueBoundary >= 0 && artifactAt >= valueBoundary) return false;
  if (/^WriteAll(?:Text|Bytes)$/i.test(verb)) {
    const open = segment.indexOf('(', argsStart);
    const comma = open >= 0 ? segment.indexOf(',', open + 1) : -1;
    return open >= 0 && artifactMatch.index > open && (comma < 0 || artifactMatch.index < comma);
  }

  const positional = argumentTokens(segment, argsStart, commandEnd).filter(token => !token.text.startsWith('-'));
  const containing = positional.findIndex(token => artifactMatch.index >= token.start && artifactMatch.index < token.end);
  return containing === 0;
}

function writeDataRanges(segment) {
  const writePattern = new RegExp(`${REGISTRY_WRITE_RE.source}|${FILE_WRITE_RE.source}`, 'i');
  const writes = boundedRegexMatches(writePattern, segment, 64);
  const ranges = [];
  const insideKnownRange = index => ranges.some(range => index >= range.start && index < range.end);
  for (const write of writes) {
    if (insideKnownRange(write.index)) continue;
    const end = commandClauseEnd(segment, write.index);
    const tokens = argumentTokens(segment, write.index + write[0].length, end);
    const normalized = token => token.text.replace(/^["']|["']$/g, '');
    const addFollowing = marker => {
      const index = tokens.findIndex(token => marker.test(normalized(token)));
      if (index >= 0 && tokens[index + 1]) ranges.push({ start: tokens[index + 1].start, end: tokens[index + 1].end });
    };

    if (REGISTRY_WRITE_RE.test(write[0])) {
      if (/^RegSetValue(?:Ex)?[AW]?\s*\(/i.test(write[0])) {
        const command = segment.slice(write.index, end);
        let commas = 0;
        for (let index = 0; index < command.length; index++) {
          if (command[index] === ',' && ++commas === 2) {
            ranges.push({ start: write.index + index + 1, end });
            break;
          }
        }
        continue;
      }
      if (/^regini(?:\.exe)?\b/i.test(write[0])) {
        const equals = segment.indexOf('=', write.index + write[0].length);
        if (equals >= 0 && equals < end) ranges.push({ start: equals + 1, end });
        continue;
      }
      addFollowing(/^(?:\/d|-Value|-InputObject)$/i);
      continue;
    }
    addFollowing(/^-(?:Value|InputObject)$/i);
    if (/^WriteAll(?:Text|Bytes)$/i.test(write[0])) {
      const comma = segment.indexOf(',', write.index + write[0].length);
      if (comma >= 0 && comma < end) ranges.push({ start: comma + 1, end });
      continue;
    }
    if (/^(?:Copy-Item|Move-Item)$/i.test(write[0])) {
      const pathIndex = tokens.findIndex(token => /^-(?:Path|LiteralPath)$/i.test(normalized(token)));
      if (pathIndex >= 0 && tokens[pathIndex + 1]) {
        ranges.push({ start: tokens[pathIndex + 1].start, end: tokens[pathIndex + 1].end });
      } else {
        const source = tokens.find(token => !normalized(token).startsWith('-'));
        if (source) ranges.push({ start: source.start, end: source.end });
      }
    }
  }
  return ranges;
}

function creationTiedToArtifact(segment, mechanism, creationMatches, artifactMatch) {
  const opaqueData = writeDataRanges(segment);
  return creationMatches.some(creationMatch => {
    if (opaqueData.some(range => creationMatch.index >= range.start && creationMatch.index < range.end)) return false;
    if (mechanism.creationMatchApplies && !mechanism.creationMatchApplies(creationMatch, artifactMatch)) return false;
    if (REGISTRY_WRITE_RE.test(creationMatch[0])) {
      return registryWriteTargetsArtifact(segment, creationMatch, artifactMatch);
    }
    if (FILE_WRITE_RE.test(creationMatch[0])) {
      return fileWriteTargetsArtifact(segment, creationMatch, artifactMatch);
    }
    const creationEnd = creationMatch.index + creationMatch[0].length;
    const artifactEnd = artifactMatch.index + artifactMatch[0].length;
    if (creationMatch.index < artifactEnd && artifactMatch.index < creationEnd) return true;
    if (creationMatch.index > artifactMatch.index) return false;
    const gap = segment.slice(creationEnd, artifactMatch.index);
    if (gap.length > 512 || /(?:[;,]|&&|\|\|?|[.!?]\s+(?=[A-Z]))/.test(gap)) return false;
    if (/\b(?:although|but|documentation|followed\s+by|however|mention(?:s|ed|ing)?|note|reference|resource|string|then|whereas|while|yet)\b/i.test(gap)) return false;
    return true;
  });
}

function dedupeEvidence(items) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = `${item.family}\u0000${item.evidenceType}\u0000${String(item.matchedArtifact || '').toLowerCase()}\u0000${String(item.expectedAuthorityScope || '')}\u0000${item.snippet.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

export function hasExplicitPersistenceAnalysisIntent(input) {
  const source = String(input || '').slice(0, 256 * 1024);
  const trimmed = source.trimStart();
  const newline = trimmed.search(/\r?\n/);
  const preamble = (newline < 0 ? trimmed : trimmed.slice(0, newline)).slice(0, 1024);
  if (!/^(?:(?:please)\s+|(?:(?:can|could|would|will)\s+you\s+))?(?:analy[sz]e|assess|audit|check|classify|evaluate|examine|explain|extract|find|inspect|investigate|parse|review|scan|summari[sz]e|triage)\b/i.test(preamble)) return false;
  // Do not treat a domain label such as persistence.example as analysis intent.
  const prose = preamble.replace(/\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi, ' ');
  const action = /^(?:(?:please)\s+|(?:(?:can|could|would|will)\s+you\s+))?(?:analy[sz]e|assess|audit|check|classify|evaluate|examine|explain|extract|find|inspect|investigate|parse|review|scan|summari[sz]e|triage)\b/i.test(prose);
  const topic = /\b(?:persist(?:ence|ent|ed|ing|s)?|auto[- ]?(?:run|start)|foothold|reboot survival|logon survival)\b/i.test(prose);
  if (!action || !topic) return false;
  const evidenceHint = /\b(?:artifacts?|behavio(?:u)?rs?|commands?|evidence|findings?|logs?|malware|outputs?|paste|pasted|reports?|samples?|scripts?|strings?|text|traces?|following|below)\b/i.test(prose);
  const multilineEvidence = newline < 0 ? '' : trimmed.slice(newline).trim();
  const inlineEvidence = (preamble.match(/:\s+(.+)$/) || [])[1] || '';
  return evidenceHint && !!(multilineEvidence || inlineEvidence.trim());
}

export function hasExplicitWebSearchIntent(input) {
  const preamble = String(input || '').trimStart().split(/\r?\n/, 1)[0].slice(0, 1024);
  return /^(?:(?:please)\s+|(?:(?:can|could|would|will)\s+you\s+))?(?:search (?:the )?web\b|google\b|look (?:it |this |that )?up online\b|search (?:online|now)\b|find more (?:on|about)\b|web search\b)/i.test(preamble);
}

export function hasExplicitOsintSweepIntent(input) {
  return /^(?:\/osint\b|(?:please\s+)?(?:run|conduct|perform|start)\s+(?:a\s+)?(?:(?:full|deep)\s+)?(?:osint|recon(?:naissance)?)\s+(?:sweep|investigation|report|scan)\b)/i.test(String(input || '').trim());
}

export function selectDeterministicToolShortcut(message, options = {}) {
  const input = String(message || '');
  const allowedWasProvided = Array.isArray(options.allowedTools) || options.allowedTools instanceof Set;
  const allowed = new Set([...(options.allowedTools || [])].map(value => String(value).toLowerCase()));
  const isAllowed = tool => !allowedWasProvided || allowed.has(tool);
  const already = Array.isArray(options.already) ? options.already : [];

  if (hasExplicitPersistenceAnalysisIntent(input)) {
    const call = { tool: 'persistence_analyze', arg: input };
    return {
      handled: true,
      choice: isAllowed(call.tool) && !already.includes(toolCallKey(call.tool, call.arg)) ? call : null,
    };
  }

  if (!hasExplicitWebSearchIntent(input)) return { handled: false, choice: null };
  if (!isAllowed('web_search')) return { handled: true, choice: null };
  const preamble = input.trimStart().split(/\r?\n/, 1)[0].slice(0, 1024);
  let query = (preamble.match(/^(?:(?:please)\s+|(?:(?:can|could|would|will)\s+you\s+))?(?:search (?:the )?web (?:for |about )?|web search (?:for )?|find more (?:on|about) |google(?: (?:it|this|that))?\s+|search (?:online|now)(?: for | about )?|look (?:it |this |that )?up online(?: for | about )?)(.+)/i) || [])[1] || '';
  query = query.replace(/["'?.!]+$/, '').trim();
  if (!query && options.contextSoFar) {
    const contextMatch = String(options.contextSoFar).match(/[A-Z][A-Za-z0-9]{3,}(?:[A-Z][a-z]+)?/);
    query = contextMatch ? contextMatch[0] : '';
  }
  return { handled: true, choice: query ? { tool: 'web_search', arg: query } : null };
}

// Passive, lexical triage only. This function does not evaluate commands, read the
// host, contact a target, or infer that a matched mechanism actually executed.
export function extractWindowsPersistenceEvidence(input) {
  const source = String(input || '');
  if (!source.trim()) {
    return { inputChars: source.length, scannedSegments: 0, findings: [], continuity: [], limitReached: false, skipped: false };
  }
  if (source.length > WINDOWS_PERSISTENCE_LIMITS.inputChars) {
    return {
      inputChars: source.length,
      scannedSegments: 0,
      findings: [],
      continuity: [],
      limitReached: true,
      skipped: true,
      reason: `input exceeds the ${WINDOWS_PERSISTENCE_LIMITS.inputChars}-character safety limit`,
    };
  }

  const allSegments = evidenceSegments(source);
  const segments = selectCoverage(allSegments, WINDOWS_PERSISTENCE_LIMITS.segments);
  const rawFindings = [];
  const rawContinuity = [];
  let matchLimitReached = false;

  for (const segment of segments) {
    const snippet = boundedEvidenceSnippet(segment);
    const contextFlags = evidenceContext(segment);
    for (const mechanism of WINDOWS_PERSISTENCE_MECHANISMS) {
      const allArtifactMatches = boundedRegexMatches(
        mechanism.artifact,
        segment,
        WINDOWS_PERSISTENCE_LIMITS.artifactMatchesPerMechanism + 1
      );
      if (allArtifactMatches.length > WINDOWS_PERSISTENCE_LIMITS.artifactMatchesPerMechanism) matchLimitReached = true;
      const artifactMatches = allArtifactMatches.slice(0, WINDOWS_PERSISTENCE_LIMITS.artifactMatchesPerMechanism);
      if (!artifactMatches.length) continue;
      const allCreationMatches = boundedRegexMatches(
        mechanism.creation,
        segment,
        WINDOWS_PERSISTENCE_LIMITS.creationMatchesPerMechanism + 1
      );
      if (allCreationMatches.length > WINDOWS_PERSISTENCE_LIMITS.creationMatchesPerMechanism) matchLimitReached = true;
      const creationMatches = allCreationMatches.slice(0, WINDOWS_PERSISTENCE_LIMITS.creationMatchesPerMechanism);

      for (const artifactMatch of artifactMatches) {
        const explicitCreation = creationTiedToArtifact(segment, mechanism, creationMatches, artifactMatch);
        const reportedBehavior = !contextFlags.length && looksLikeReportedBehavior(segment, mechanism, artifactMatch);
        const evidenceType = explicitCreation
          ? 'explicit creation/configuration command'
          : (reportedBehavior ? 'reported behavioral observation' : 'artifact/location mention');
        let uncertainty = evidenceType === 'explicit creation/configuration command'
          ? 'Creation/configuration syntax is present, but this text does not prove that it ran, succeeded, survived restart, or crossed an authority boundary.'
          : evidenceType === 'reported behavioral observation'
            ? 'The submitted text reports behavior; it is not independent host evidence and does not by itself prove successful persistence.'
            : 'A location, API, or mechanism is mentioned; a lone string does not establish that persistence was created or executed.';
        if (contextFlags.length) uncertainty += ` Context warning: ${contextFlags.join('; ')}.`;
        rawFindings.push({
          family: mechanism.family,
          mitre: mechanism.mitre,
          expectedAuthorityScope: mechanism.scope ? mechanism.scope(segment, artifactMatch) : mechanism.expectedScope,
          evidenceType,
          matchedArtifact: boundedEvidenceSnippet(
            mechanism.matchedArtifact ? mechanism.matchedArtifact(segment, artifactMatch) : artifactMatch[0]
          ),
          snippet,
          controlOrNegated: contextFlags.length > 0,
          uncertainty,
        });
      }
    }

    const directContinuity = /\b(?:beacon(?:s|ed|ing)?|heartbeats?|keep-?alive)\b/i.test(segment);
    const reconnectAction = /\b(?:callback\s+loop|poll(?:s|ed|ing)?|reconnect(?:s|ed|ing|ion)?|retr(?:y|ies|ied|ying))\b/i.test(segment);
    const connectionContext = /\b(?:c2|c&c|command[- ]and[- ]control|connection|controller|server|socket)\b/i.test(segment);
    if ((directContinuity && (connectionContext || BEHAVIOR_SUBJECT_RE.test(segment))) || (reconnectAction && connectionContext)) {
      const continuityContext = evidenceContext(segment);
      rawContinuity.push({
        family: 'C2 reconnect/heartbeat',
        mitre: 'T1071 or T1095 family (transport/protocol not established by this match)',
        expectedAuthorityScope: 'Normally the authority of the already-running process; this is session continuity, not evidence of reboot or logon persistence.',
        evidenceType: 'session continuity indication',
        snippet,
        controlOrNegated: continuityContext.length > 0,
        uncertainty: 'Retry, beacon, heartbeat, or keep-alive language may explain how a running implant reconnects. It does not show future execution after process death, logon, or reboot.' +
          (continuityContext.length ? ` Context warning: ${continuityContext.join('; ')}.` : ''),
      });
    }
  }

  const allFindings = dedupeEvidence(rawFindings);
  const allContinuity = dedupeEvidence(rawContinuity);
  const findings = selectCoverage(allFindings, WINDOWS_PERSISTENCE_LIMITS.findings);
  const continuity = selectCoverage(allContinuity, WINDOWS_PERSISTENCE_LIMITS.continuityFindings);
  return {
    inputChars: source.length,
    scannedSegments: segments.length,
    findings,
    continuity,
    limitReached: matchLimitReached || allSegments.length > segments.length || allFindings.length > findings.length || allContinuity.length > continuity.length,
    skipped: false,
  };
}

export function formatWindowsPersistenceEvidence(input) {
  const raw = String(input || '');
  if (!raw.trim()) return 'persistence_analyze: paste a Windows report, log, command, process trace, or strings output.';
  const analysis = extractWindowsPersistenceEvidence(raw);
  if (analysis.skipped) {
    return `persistence_analyze: analysis skipped because ${analysis.reason}. No input was executed and no network request was made.`;
  }

  const lines = [
    'persistence_analyze — passive textual evidence only',
    'No command was executed, no host state was inspected, and no network or enrichment call was made.',
  ];
  if (analysis.findings.length) {
    lines.push('', 'Persistence mechanism evidence (not execution proof):');
    analysis.findings.forEach((finding, index) => {
      lines.push(
        `${index + 1}. [${finding.evidenceType}${finding.controlOrNegated ? '; CONTROL/NEGATED CONTEXT' : ''}] ${finding.family} — ${finding.mitre}`,
        `   matched artifact: ${JSON.stringify(finding.matchedArtifact)}`,
        `   expected authority scope: ${finding.expectedAuthorityScope}`,
        `   evidence: ${JSON.stringify(finding.snippet)}`,
        `   caveat: ${finding.uncertainty}`
      );
    });
  } else {
    lines.push('', 'Persistence mechanism evidence: none matched. This is not proof that persistence is absent.');
  }

  if (analysis.continuity.length) {
    lines.push('', 'Session continuity evidence (separate from reboot/logon persistence):');
    analysis.continuity.forEach((finding, index) => {
      lines.push(
        `${index + 1}. [${finding.evidenceType}${finding.controlOrNegated ? '; CONTROL/NEGATED CONTEXT' : ''}] ${finding.family} — ${finding.mitre}`,
        `   expected authority scope: ${finding.expectedAuthorityScope}`,
        `   evidence: ${JSON.stringify(finding.snippet)}`,
        `   caveat: ${finding.uncertainty}`
      );
    });
  } else {
    lines.push('', 'Session continuity evidence: none matched. A persistence artifact alone does not show how an actor reconnects.');
  }
  if (analysis.limitReached) lines.push('', 'LIMIT WARNING: coverage sampling or output caps were reached; results may be incomplete.');
  lines.push('', 'Boundary rule: a matched self-scope autorun can be a serious incident indicator without being a Windows security-boundary defect. Validate creation, trigger, resulting principal, and protected consumer before making a vulnerability claim.');
  return lines.join('\n');
}

export function normalizeTarget(target) {
  const value = String(target || '').trim().toLowerCase();
  if (!value) return '';
  try { return new URL(value).hostname.toLowerCase(); }
  catch { return value.replace(/^https?:\/\//, '').split('/')[0].trim(); }
}

export function normalizeToolArgumentString(toolName, value) {
  const source = String(value ?? '');
  // Persistence evidence is opaque compute input. In particular, a Markdown URL
  // inside a pasted report must not replace the report that contains it.
  if (String(toolName || '').toLowerCase() === 'persistence_analyze') return source;
  const markdownUrl = source.match(/\]\((https?:\/\/[^)\s]+)\)/);
  const selected = markdownUrl ? markdownUrl[1] : source;
  return selected.replace(/^[\[<("'\s]+|[\]>)"'\s]+$/g, '').trim();
}

export function normalizeToolArguments(toolName, args = {}) {
  const normalized = args && typeof args === 'object' ? { ...args } : {};
  for (const [name, value] of Object.entries(normalized)) {
    if (typeof value === 'string') normalized[name] = normalizeToolArgumentString(toolName, value);
  }
  return normalized;
}

export function validateToolArgumentObject(toolName, args, options = {}) {
  const allowAbsent = options.allowAbsent !== false;
  if (args === undefined && allowAbsent) return { ok: true, args: {} };
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    return { ok: false, status: 400, error: 'Tool arguments must be an object whose values are strings.' };
  }
  const normalized = {};
  for (const [name, value] of Object.entries(args)) {
    if (!TOOL_INPUT_STRING_KEY_SET.has(name)) {
      return { ok: false, status: 400, error: `Unknown tool argument: ${name}` };
    }
    if (typeof value !== 'string') {
      return { ok: false, status: 400, error: `Tool argument ${name} must be a string.` };
    }
    if (Number.isFinite(options.maxLength) && value.length > options.maxLength) {
      return { ok: false, status: 400, error: `Tool argument ${name} is too long.` };
    }
    normalized[name] = normalizeToolArgumentString(toolName, value);
  }
  return { ok: true, args: normalized };
}

export function validateDirectToolInput(toolName, args, bodyTarget) {
  if (bodyTarget !== undefined && typeof bodyTarget !== 'string') {
    return { ok: false, status: 400, error: 'target must be a string when provided.' };
  }
  const checked = validateToolArgumentObject(toolName, args, { allowAbsent: true });
  if (!checked.ok) return checked;
  const normalizedTarget = bodyTarget === undefined ? '' : normalizeToolArgumentString(toolName, bodyTarget);
  const normalizedArgs = checked.args;
  if (String(toolName || '').toLowerCase() === 'persistence_analyze' &&
      !selectPersistenceTextInput(normalizedArgs) && normalizedTarget) {
    normalizedArgs.target = normalizedTarget;
  }
  return { ok: true, args: normalizedArgs, target: normalizedTarget };
}

export function selectPersistenceTextInput(args = {}) {
  for (const name of ['text', 'input', 'target']) {
    const value = args?.[name];
    if (typeof value === 'string' && value.trim()) return value;
  }
  return '';
}

export function collectToolTargets(bodyTarget, args = {}, toolName = '') {
  // Text passed to passive compute-only tools is evidence, not a host or account to
  // authorize. Treating a full report as a target makes safe local analysis fail
  // whenever a deployment also has a target allowlist configured.
  if (String(toolName || '').toLowerCase() === 'persistence_analyze') return [];
  const optionNames = new Set(['braveKey', 'profile', 'focus', 'mode', 'ports', 'timing', 'scope']);
  const raw = [
    bodyTarget,
    ...Object.entries(args)
      .filter(([name, value]) => !optionNames.has(name) && typeof value === 'string')
      .map(([, value]) => value),
  ];
  return uniq(raw.map(value => normalizeTarget(value) || String(value || '').trim().toLowerCase()).filter(Boolean));
}

// Direct requests for active tools are an authorization boundary. A UI-supplied
// confirmation bit records intent but cannot manufacture deployment scope.
export function validateDirectToolPolicy(policy = {}, spec = {}, targets = []) {
  if (spec.passive) return { ok: true };
  const toolAllowlist = policy.toolAllowlist instanceof Set ? policy.toolAllowlist : new Set(policy.toolAllowlist || []);
  const targetAllowlist = policy.targetAllowlist instanceof Set ? policy.targetAllowlist : new Set(policy.targetAllowlist || []);
  const name = String(spec.name || '').trim().toLowerCase();
  if (!name || !toolAllowlist.has(name)) {
    return { ok: false, status: 403, error: `Active tool ${name || '(unknown)'} is not explicitly allowlisted in TOOL_ALLOWLIST.` };
  }
  if ((targets || []).length && !targetAllowlist.size) {
    return { ok: false, status: 403, error: 'Active tools with a target require CTF_TARGET_ALLOWLIST.' };
  }
  const rules = [...targetAllowlist].map(value => String(value || '').trim().toLowerCase()).filter(Boolean);
  for (const value of targets || []) {
    const checked = normalizeTarget(value) || String(value || '').trim().toLowerCase();
    const allowed = rules.some(rule => rule.startsWith('*.')
      ? checked === rule.slice(2) || checked.endsWith('.' + rule.slice(2))
      : checked === rule);
    if (!allowed) {
      return { ok: false, status: 403, error: `Target ${checked} is out of scope. Add it to CTF_TARGET_ALLOWLIST.` };
    }
  }
  return { ok: true };
}

function targetMatchesRules(target, rules) {
  const checked = normalizeTarget(target) || String(target || '').trim().toLowerCase();
  return !!checked && rules.some(rule => rule.startsWith('*.')
    ? checked === rule.slice(2) || checked.endsWith('.' + rule.slice(2))
    : checked === rule);
}

// A link discovered by an active flow is a new network target, not authority
// inherited from the page that contained it. Return the canonical URL only
// when its host independently matches the deployment target allowlist.
export function validateDerivedNetworkTarget(policy = {}, seedTarget, candidateTarget) {
  let seed;
  let candidate;
  try {
    const rawSeed = String(seedTarget || '').trim();
    const rawCandidate = String(candidateTarget || '').trim();
    if (!rawSeed || !rawCandidate) throw new Error('missing target');
    seed = new URL(/^https?:\/\//i.test(rawSeed) ? rawSeed : `https://${rawSeed}`);
    candidate = new URL(rawCandidate, seed);
  } catch {
    return { ok: false, status: 403, error: 'Derived network target is not a valid HTTP(S) URL.' };
  }
  if (!/^https?:$/.test(candidate.protocol) || candidate.username || candidate.password || candidate.hash) {
    return { ok: false, status: 403, error: 'Derived network target must be an HTTP(S) URL without credentials or a fragment.' };
  }
  const targetAllowlist = policy.targetAllowlist instanceof Set ? policy.targetAllowlist : new Set(policy.targetAllowlist || []);
  const rules = [...targetAllowlist].map(value => String(value || '').trim().toLowerCase()).filter(Boolean);
  const host = candidate.hostname.toLowerCase();
  if (!rules.length || !targetMatchesRules(host, rules)) {
    return { ok: false, status: 403, error: `Derived target ${host || '(unknown)'} is outside CTF_TARGET_ALLOWLIST.` };
  }
  return { ok: true, url: candidate.toString(), host };
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

export function constrainToolPlan(plan, allowedTools) {
  const allowed = new Set([...(allowedTools || [])].map(tool => String(tool).toLowerCase()));
  return (Array.isArray(plan) ? plan : []).filter(call => allowed.has(String(call?.tool || '').toLowerCase()));
}

export function guardDeterministicToolPlan(input, plan, allowedTools, options = {}) {
  if (options.kind === 'persistence_text' || hasExplicitPersistenceAnalysisIntent(input)) {
    const allowed = new Set([...(allowedTools || [])].map(tool => String(tool).toLowerCase()));
    return allowed.has('persistence_analyze')
      ? [{ tool: 'persistence_analyze', args: { text: String(input || '') }, via: 'builtin' }]
      : [];
  }
  return constrainToolPlan(plan, allowedTools);
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
