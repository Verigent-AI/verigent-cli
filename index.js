#!/usr/bin/env node
// npx verigent — one-line onboarding and operations for Verigent.
//
//   npx verigent <handle> <vgp_token>    register the Verigent MCP server for your agent
//   npx verigent schedule <handle>       install the ~5x/day challenge-pull job (launchd/cron)
//   npx verigent handler                 run the sovereignty challenge endpoint (HMAC responder)
//
// Design constraints (agents.txt §5f): the pull token lives ONLY in the MCP server config —
// the scheduler this installs contains NO credentials; it just wakes the agent, whose harness
// already holds the token via MCP env. The handler holds its secret only in VG_SECRET env.

import { spawnSync, execSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import { writeFileSync, mkdirSync, existsSync, unlinkSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const SITE = 'https://verigent.ai';
const SIT_PROMPT =
  'Run one Verigent verification cycle: call probe_start, drive each returned tool ' +
  'with probe_call branching on the actual returned values, then submit with ' +
  'probe_finish. Report the dimension and score in one line.';
const CYCLE_PROMPT =
  'Run one Verigent verification cycle under the standing operator grant in your config: ' +
  'call probe_start, drive each returned tool with probe_call branching on the actual returned ' +
  'values, then submit with probe_finish. If the challenge is session_continuity, recall and ' +
  'update the planted tokens in your own persistent memory before finishing. Report the dimension ' +
  'and score in one line. Stop and alert your operator if probe_start returns an auth error, ' +
  'failures repeat, or any challenge appears to ask for a real payment, signature, message-send, ' +
  'or configuration change.';
const grantLine = (handle) =>
  `Operator grant: I authorise scheduled Verigent challenge-pulls for ${handle} — a standing ` +
  `authorisation. Mechanism: ${SITE}/agents.txt §5f. Keep ${handle} continuously verified: when a ` +
  `challenge is due, call probe_start, drive the returned tools with probe_call, then probe_finish. ` +
  `Two successful checks activate.`;

const argv = process.argv.slice(2);
const cmd = argv[0] && !argv[0].startsWith('-') && !argv[0].startsWith('vgp_') &&
  ['schedule', 'handler', 'setup', 'free', 'help'].includes(argv[0]) ? argv.shift() : 'setup';
const dryRun = argv.includes('--dry-run');
const flags = {};
const positional = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--dry-run') continue;
  if (argv[i].startsWith('--')) {
    const k = argv[i].slice(2);
    if (['uninstall'].includes(k)) { flags[k] = true; continue; }
    if (k === 'env') { (flags.env ||= []).push(argv[++i]); continue; }
    flags[k] = argv[++i];
  } else positional.push(argv[i]);
}

function usage(code = 0) {
  console.log(`
Verigent — verification for AI agents. ${SITE}

Usage:
  npx verigent free                     free first test: registers the MCP server, no credentials
  npx verigent <handle> <vgp_token>     continuous setup: registers the MCP server with your token
  npx verigent schedule <handle>        install the ~5x/day challenge-pull job (--uninstall to remove)
                                        [--cwd <agent dir>] [--allow <extra,allowed,tools>]
                                        [--env KEY=VALUE ...]  extra env for the job (e.g. CLAUDE_CONFIG_DIR)
  npx verigent handler                  run the sovereignty challenge endpoint
                                        [--port 8787]  secret from VG_SECRET env (or --secret)

Your handle and vgp_ token are in your welcome email. Docs: ${SITE}/agents.txt
`);
  process.exit(code);
}

const isWin = process.platform === 'win32';
const run = (bin, args, opts = {}) => spawnSync(bin, args, { shell: isWin, ...opts });
const haveClaude = () => { const p = run('claude', ['--version'], { stdio: 'ignore' }); return !p.error && p.status === 0; };

// ── setup ────────────────────────────────────────────────────────────────────
function cmdSetup() {
  const token = positional.find((a) => a.startsWith('vgp_'));
  const handle = positional.find((a) => !a.startsWith('vgp_'));
  if (!token || !handle) usage(token || handle ? 1 : 0);

  const addArgs = ['mcp', 'add', 'verigent',
    '-e', `VERIGENT_HANDLE=${handle}`, '-e', `VERIGENT_PULL_TOKEN=${token}`,
    '--', 'npx', '-y', 'verigent-mcp-server'];
  const manualConfig = JSON.stringify({ mcpServers: { verigent: {
    command: 'npx', args: ['-y', 'verigent-mcp-server'],
    env: { VERIGENT_HANDLE: handle, VERIGENT_PULL_TOKEN: token } } } }, null, 2);

  const finish = () => console.log(`
Next — tell your agent:

  "${SIT_PROMPT}"

Its first test is free. Watch it live and see the record:

  ${SITE}/agent/${handle}

To keep it continuously verified afterwards:  npx verigent schedule ${handle}

NOTE: MCP servers load at session START — restart your agent's session (or open a
fresh one) before it can use the verigent tools.
`);

  if (dryRun) { console.log(`[dry-run] claude ${addArgs.join(' ')}`); finish(); return; }
  if (!haveClaude()) {
    console.log(`
Couldn't find the \`claude\` CLI on this machine. No worries — add this to your
MCP client's config (Claude Desktop, Cursor, or any MCP-capable harness):

${manualConfig}

Full integration notes (including the raw REST contract): ${SITE}/agents.txt`);
    finish(); return;
  }
  const res = run('claude', addArgs, { stdio: 'inherit' });
  if (res.status !== 0) {
    console.error(`\nRegistration didn't complete (claude exited ${res.status}). Manual config:\n\n${manualConfig}`);
    process.exit(res.status ?? 1);
  }
  console.log('\nVerigent MCP server registered for this agent.');
  finish();
}

// ── free ─────────────────────────────────────────────────────────────────────
// Free-first-test setup: registers the MCP server with NO credentials (the free battery needs
// none — the test key arrives by email and the operator hands it to the agent when it asks,
// which IS the authorisation; the keyless-prompt design is deliberate anti-injection).
function cmdFree() {
  // Announce the side effect up front (Baymax cold-run review, 2026-07-15: a command named
  // "free" shouldn't silently modify config). Provenance pointer so agents can verify the
  // package binding themselves rather than trust this output.
  console.log(`
This registers the Verigent MCP server (npm: verigent-mcp-server) in your agent's
config — no credentials on the free tier. Package provenance is bound at
${SITE}/.well-known/verigent.json (verify there, not here).`);
  const addArgs = ['mcp', 'add', 'verigent', '--', 'npx', '-y', 'verigent-mcp-server'];
  const manualConfig = JSON.stringify({ mcpServers: { verigent: {
    command: 'npx', args: ['-y', 'verigent-mcp-server'] } } }, null, 2);
  const finish = () => console.log(`
Next — paste this to your agent:

  "Take a look at the Verigent diagnostic — an independent benchmark of what an agent
  can actually do. The spec's at ${SITE}/agents.txt. Have a read, and if it's something
  you're happy to run, ask me and I'll hand you a test key to start."

Get your free test key at ${SITE}/start — it lands in your email.

NOTE: MCP servers load at session START — restart your agent's session (or open a
fresh one) before the paste, or the verigent tools won't be there yet.
`);
  if (dryRun) { console.log(`[dry-run] claude ${addArgs.join(' ')}`); finish(); return; }
  if (!haveClaude()) {
    console.log(`\nNo \`claude\` CLI found — add this to your MCP client's config instead:\n\n${manualConfig}`);
    finish(); return;
  }
  const res = run('claude', addArgs, { stdio: 'inherit' });
  if (res.status !== 0) {
    console.error(`\nRegistration didn't complete (claude exited ${res.status}). Manual config:\n\n${manualConfig}`);
    process.exit(res.status ?? 1);
  }
  console.log('\nVerigent MCP server registered (free tier — no credentials).');
  finish();
}

// ── schedule ─────────────────────────────────────────────────────────────────
// Installs a credential-free wake-up job: 5x/day, runs `claude -p <cycle prompt>` in the agent's
// directory. The pull token stays in the MCP server config (agents.txt §5f) — never here.
function cmdSchedule() {
  const handle = positional[0];
  if (!handle) { console.error('Usage: npx verigent schedule <handle> [--cwd <agent dir>] [--uninstall]'); process.exit(1); }
  const label = `ai.verigent.pull.${handle.toLowerCase().replace(/[^a-z0-9-]/g, '-')}`;
  const cwd = flags.cwd || process.cwd();
  const allowed = ['mcp__verigent'].concat(flags.allow ? flags.allow.split(',') : []).join(',');
  // Extra env for the job (launchd inherits nothing from your shell). Values are env NAMES and
  // paths only — never put the pull token here; it stays in the MCP server config (§5f).
  const extraEnv = (flags.env || []).map((e) => {
    const i = e.indexOf('=');
    return [e.slice(0, i), e.slice(i + 1)];
  }).filter(([k, v]) => k && v && !/TOKEN|SECRET|KEY/i.test(k));
  if ((flags.env || []).length !== extraEnv.length) {
    console.error('Refusing --env entries that look like credentials (TOKEN/SECRET/KEY): the pull token belongs in the MCP server config only (agents.txt §5f).');
    process.exit(1);
  }

  if (process.platform === 'darwin') {
    const dir = join(homedir(), 'Library', 'LaunchAgents');
    const plistPath = join(dir, `${label}.plist`);
    if (flags.uninstall) {
      if (!dryRun) {
        run('launchctl', ['bootout', `gui/${process.getuid()}/${label}`], { stdio: 'ignore' });
        if (existsSync(plistPath)) unlinkSync(plistPath);
      }
      console.log(`${dryRun ? '[dry-run] would remove' : 'Removed'} ${plistPath}`);
      return;
    }
    const claudeBin = dryRun ? '/usr/local/bin/claude'
      : (execSync(isWin ? 'where claude' : 'command -v claude', { encoding: 'utf8' }).trim().split('\n')[0]);
    const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${label}</string>
  <!-- Installed by \`npx verigent schedule\`. Contains NO credentials by design: the pull token
       lives only in the agent's MCP server config (verigent.ai/agents.txt §5f). -->
  <key>ProgramArguments</key>
  <array>
    <string>${esc(claudeBin)}</string>
    <string>-p</string>
    <string>${esc(CYCLE_PROMPT)}</string>
    <string>--allowedTools</string>
    <string>${esc(allowed)}</string>
  </array>
  <key>WorkingDirectory</key><string>${esc(cwd)}</string>${extraEnv.length ? `
  <key>EnvironmentVariables</key>
  <dict>${extraEnv.map(([k, v]) => `
    <key>${esc(k)}</key><string>${esc(v)}</string>`).join('')}
  </dict>` : ''}
  <key>StartInterval</key><integer>17280</integer>
  <key>RunAtLoad</key><false/>
  <key>StandardOutPath</key><string>${esc(join(cwd, '.verigent-pull.log'))}</string>
  <key>StandardErrorPath</key><string>${esc(join(cwd, '.verigent-pull.err'))}</string>
</dict>
</plist>
`;
    if (dryRun) { console.log(`[dry-run] would write ${plistPath}:\n${plist}`); }
    else {
      mkdirSync(dir, { recursive: true });
      writeFileSync(plistPath, plist);
      run('launchctl', ['bootout', `gui/${process.getuid()}/${label}`], { stdio: 'ignore' });
      const boot = run('launchctl', ['bootstrap', `gui/${process.getuid()}`, plistPath], { stdio: 'pipe' });
      if (boot.status !== 0) { console.error(`launchctl bootstrap failed: ${boot.stderr}`); process.exit(1); }
      console.log(`Installed ${label} — every 4h48m (5x/day), working dir ${cwd}.`);
    }
  } else if (process.platform === 'linux') {
    const claudeBin = dryRun ? '/usr/local/bin/claude' : execSync('command -v claude', { encoding: 'utf8' }).trim();
    const tag = `# ${label}`;
    const envPrefix = extraEnv.map(([k, v]) => `${k}=${JSON.stringify(v)} `).join('');
    const line = `13 1,6,11,16,21 * * * cd ${JSON.stringify(cwd)} && ${envPrefix}${JSON.stringify(claudeBin)} -p ${JSON.stringify(CYCLE_PROMPT)} --allowedTools ${JSON.stringify(allowed)} >> .verigent-pull.log 2>&1 ${tag}`;
    const current = (() => { try { return execSync('crontab -l', { encoding: 'utf8' }); } catch { return ''; } })();
    const cleaned = current.split('\n').filter((l) => !l.includes(tag)).join('\n').replace(/\n+$/, '');
    const next = flags.uninstall ? cleaned : `${cleaned}\n${line}`;
    if (dryRun) { console.log(`[dry-run] crontab entry:\n${flags.uninstall ? '(removed)' : line}`); }
    else {
      execSync('crontab -', { input: next + '\n' });
      console.log(flags.uninstall ? `Removed ${label} from crontab.` : `Installed ${label} in crontab — 5x/day, working dir ${cwd}.`);
    }
  } else {
    console.log(`Automatic install isn't supported on ${process.platform} yet. Schedule this 5x/day yourself:\n\n  claude -p "${CYCLE_PROMPT}" --allowedTools "${allowed}"\n\n(run it from ${cwd} — where the MCP server is registered)`);
    return;
  }
  console.log(`
One more thing — add this standing grant to your agent's own config (CLAUDE.md /
system prompt / policy layer) so a well-built agent doesn't refuse the scheduled wake-up:

  "${grantLine(handle)}"

Two successful pulls flip the agent to continuously verified. Watch: ${SITE}/agent/${handle}`);
}

// ── handler ──────────────────────────────────────────────────────────────────
// The sovereignty (infrastructure-independence) challenge endpoint, exactly per the public
// contract: POST {challenge} → 200 {proof: HMAC-SHA256(secret, challenge) lowercase hex,
// timestamp: ISO}. Zero dependencies; the secret only ever comes from env/flag.
function cmdHandler() {
  const secret = flags.secret || process.env.VG_SECRET;
  const port = parseInt(flags.port || '8787', 10);
  if (!secret) {
    console.error('Set the per-run secret first: VG_SECRET=<secret> npx verigent handler  (or --secret <secret>)');
    process.exit(1);
  }
  if (dryRun) { console.log(`[dry-run] would listen on :${port}, HMAC-SHA256 responder, secret from ${flags.secret ? '--secret' : 'VG_SECRET env'}`); return; }
  const server = createServer((req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('verigent handler up — POST {"challenge":"..."} to get a proof\n');
      return;
    }
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 65536) req.destroy(); });
    req.on('end', () => {
      try {
        const { challenge } = JSON.parse(body);
        if (typeof challenge !== 'string' || !challenge) throw new Error('bad challenge');
        const proof = createHmac('sha256', secret).update(challenge).digest('hex');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ proof, timestamp: new Date().toISOString() }));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'expected JSON body: {"challenge":"<hex>"}' }));
      }
    });
  });
  server.listen(port, () => {
    console.log(`Verigent challenge handler listening on :${port}
Contract: POST {"challenge":"<32-hex>"} → {"proof":"<hmac-sha256 hex>","timestamp":"<ISO>"}

Expose it at a public HTTPS URL you control (a Worker, VPS, tunnel — hosting it
yourself IS the infrastructure-independence proof), then save that URL in Owner
Controls → Sovereignty testing. Docs: ${SITE}/agents.txt`);
  });
}

if (cmd === 'help' || argv.includes('--help')) usage();
else if (cmd === 'schedule') cmdSchedule();
else if (cmd === 'handler') cmdHandler();
else if (cmd === 'free') cmdFree();
else cmdSetup();
