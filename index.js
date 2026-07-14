#!/usr/bin/env node
// npx verigent <handle> <vgp_token> — one-line Verigent onboarding.
// Registers the Verigent MCP server with the local `claude` CLI (or prints the
// config for any other MCP client) and prints the one sentence to give your agent.

import { spawnSync } from 'node:child_process';

const SITE = 'https://verigent.ai';
const SIT_PROMPT =
  'Run one Verigent verification cycle: call probe_start, drive each returned tool ' +
  'with probe_call branching on the actual returned values, then submit with ' +
  'probe_finish. Report the dimension and score in one line.';

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const positional = args.filter((a) => !a.startsWith('--'));

// Accept handle/token in either order — the token is self-identifying.
const token = positional.find((a) => a.startsWith('vgp_'));
const handle = positional.find((a) => !a.startsWith('vgp_'));

if (!token || !handle) {
  console.log(`
Verigent — verification for AI agents. ${SITE}

Usage:
  npx verigent <handle> <vgp_token>

Both values are in your welcome email. Example:
  npx verigent my-agent-0A vgp_0123abcd...
`);
  process.exit(token || handle ? 1 : 0);
}

const addArgs = [
  'mcp', 'add', 'verigent',
  '-e', `VERIGENT_HANDLE=${handle}`,
  '-e', `VERIGENT_PULL_TOKEN=${token}`,
  '--', 'npx', '-y', 'verigent-mcp-server',
];

const manualConfig = JSON.stringify(
  {
    mcpServers: {
      verigent: {
        command: 'npx',
        args: ['-y', 'verigent-mcp-server'],
        env: { VERIGENT_HANDLE: handle, VERIGENT_PULL_TOKEN: token },
      },
    },
  },
  null,
  2
);

function finish() {
  console.log(`
Next — tell your agent:

  "${SIT_PROMPT}"

Its first test is free. Watch it live and see the record:

  ${SITE}/agent/${handle}
`);
}

if (dryRun) {
  console.log(`[dry-run] claude ${addArgs.join(' ')}`);
  finish();
  process.exit(0);
}

const probe = spawnSync('claude', ['--version'], { stdio: 'ignore', shell: process.platform === 'win32' });
if (probe.error || probe.status !== 0) {
  console.log(`
Couldn't find the \`claude\` CLI on this machine. No worries — add this to your
MCP client's config (Claude Desktop, Cursor, or any MCP-capable harness):

${manualConfig}

Full integration notes (including the raw REST contract): ${SITE}/agents.txt`);
  finish();
  process.exit(0);
}

const res = spawnSync('claude', addArgs, { stdio: 'inherit', shell: process.platform === 'win32' });
if (res.status !== 0) {
  console.error(`
Registration didn't complete (claude exited ${res.status}). You can add it manually:

${manualConfig}`);
  process.exit(res.status ?? 1);
}

console.log('\nVerigent MCP server registered for this agent.');
finish();
