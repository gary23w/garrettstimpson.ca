import { spawnSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import { packageGary } from './archive.mjs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const require = createRequire(import.meta.url);
const wrangler = path.join(path.dirname(require.resolve('wrangler/package.json')), require('wrangler/package.json').bin.wrangler);
const agentDir = fileURLToPath(new URL('../', import.meta.url));
const backendConfig = path.join(agentDir, 'gary', 'wrangler.toml');
const args = process.argv.slice(2);
function call(argv, input, quiet = false, backend = false) {
  const env = { ...process.env };
  if (backend) delete env.WRANGLER_CI_MATCH_TAG;
  const result = spawnSync(process.execPath, [wrangler, ...argv], {
    cwd: agentDir, encoding: 'utf8', input, env,
    stdio: quiet || input !== undefined ? ['pipe', 'pipe', 'pipe'] : 'inherit',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error((result.stderr || result.stdout || `Deployment command failed (${result.status}).`).trim());
  return result.stdout || '';
}
if (args.includes('--dry-run')) {
  call(['deploy', '--config', backendConfig, ...args], undefined, false, true);
  call(['deploy', '--config', path.join(agentDir, 'wrangler.toml'), ...args]);
} else {
  const source = await packageGary(path.join(agentDir, 'gary'));
  const hash = createHash('sha256').update(source).digest('hex');
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'gary-deploy-'));
  const archive = path.join(temporary, 'source.tar.gz');
  await fs.writeFile(archive, source);
  const listed = call(['r2', 'bucket', 'list'], undefined, true);
  if (!/(?<![A-Za-z0-9_-])garrettstimpson-gary-state(?![A-Za-z0-9_-])/.test(listed)) call(['r2', 'bucket', 'create', 'garrettstimpson-gary-state']);
  try { call(['r2', 'object', 'put', 'garrettstimpson-gary-state/build/' + hash + '.tar.gz', '--file', archive, '--remote']); }
  finally { await fs.unlink(archive); await fs.rmdir(temporary); }
  call(['deploy', '--config', backendConfig, '--var', 'GARY_BUILD_ID:' + hash], undefined, false, true);
  const secrets = call(['secret', 'list', '--config', backendConfig], undefined, true, true);
  if (!secrets.includes('GARY_RUNTIME_TOKEN')) call(['secret', 'put', 'GARY_RUNTIME_TOKEN', '--config', backendConfig], randomBytes(32).toString('hex') + '\n', true, true);
  call(['deploy', '--config', path.join(agentDir, 'wrangler.toml'), ...args]);
  console.log('Garrett and its dedicated Gary backend are deployed in this Cloudflare account.');
}
