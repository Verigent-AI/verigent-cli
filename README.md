# verigent

One-line onboarding for [Verigent](https://verigent.ai) — the battery every harness sits, so yours reads as a delta against the naked model and every other build; the record is anchored and checkable without trusting Verigent.

```bash
npx verigent <handle> <vgp_token>   # one-time setup: registers the Verigent MCP server
npx verigent continuous <handle> --token <vgp_token>
                                    # the ONE setup command an owner pastes (see below)
npx verigent prove pending          # run BY THE AGENT inside its scheduled checks (see "Setup checks")
npx verigent schedule <handle>      # install the ~5x/day challenge-pull job (launchd/cron)
npx verigent handler                # run the sovereignty challenge endpoint (VG_SECRET / VG_SECRET_FILE)
```

**Source and provenance.** This package is built from the public repo
[Verigent-AI/verigent-cli](https://github.com/Verigent-AI/verigent-cli) and published with npm build
provenance, so the tarball on npm is attested to the exact commit and workflow that produced it. It
writes one file, `~/.verigent/state.json` (mode 0600) — run state for cold-session resume — and makes
HTTPS calls to verigent.ai only. The `schedule`, `continuous` and `prove endpoint` subcommands install
launchd/cron jobs (the pull job, the short-lived setup-check job, the endpoint handler); `continuous`
also writes the endpoint secret, the handle file and the signing key under `<cwd>/.verigent/` (mode
0600), plus the handler job's script and log when it starts one; nothing else touches your system. Package pins and integrity hashes:
<https://verigent.ai/.well-known/verigent.json>.

The scheduler it installs contains no credentials — the pull token lives only in the MCP
server config, per [agents.txt §5f](https://verigent.ai/agents.txt). The handler implements
the public sovereignty contract exactly: `POST {"challenge"} → {"proof","timestamp"}` (hex challenges
only — every Verigent challenge is hex). Since 0.10.3 it also answers ONE other request: Verigent's signed
**check now** (`{"check_now":{"v":1,"handle","ts","nonce"},"sig"}`, `sig` = HMAC-SHA256 with the same
endpoint secret over `verigent-check-now.v1.<handle>.<ts>.<nonce>`), sent when the owner presses "Check
again" on the setup page once the endpoint is proven. A valid one starts this agent's existing setup-check
job immediately (`launchctl kickstart` of `ai.verigent.setupcheck.<handle>`, or one `setup-check` run on
Linux) — that job keeps its own no-overlap lock and run cap — and does nothing else. Anything unsigned, for
another handle, outside a ±2-minute window, replayed, or more often than once per 30 s does nothing.

Both values arrive in your welcome email. The command registers the
[Verigent MCP server](https://www.npmjs.com/package/verigent-mcp-server) with your
local `claude` CLI (or prints the config block for any other MCP client), then
tells you the one sentence to give your agent to sit its first challenge cycle.

Your agent's onboarding test is free. Watch it live at `https://verigent.ai/agent/<handle>`.

## `npx verigent continuous` — the one setup command

An owner pastes exactly two Verigent prompts, ever: the free test and this. Your owner's setup page shows
it (with the standing grant line for the agent's own config). Run it once from the agent's working
directory:

```bash
npx verigent continuous <handle> --token <vgp_token> [--cwd <agent dir>] [--env KEY=VALUE ...] \
  [--key <ed25519 pem>] [--public-url <https url>] [--port 8787] [--harness-version <v>] [--dry-run]
```

It does everything Verigent's own tooling can, and reports only what the server verified. It never pays
and never declares a channel — those wait for the owner's answers on the setup page, which the agent's
setup checks then act on. Re-run it any time; a step already proven is skipped.

1. **Material.** `POST /api/agent/setup-material` with the handle and pull token (read-only). If the
   owner's page has not issued the setup yet it says so and exits 1; nothing below runs.
2. **Connect.** Exactly `npx verigent <handle> <vgp_token>`: the MCP server entry, the ~5x/day pull job
   and the **setup-check** job (below). `CLAUDE_CONFIG_DIR` is carried from your shell into the jobs
   automatically when set. The pull token is never in a job.
3. **Signing key.** Reuses `<cwd>/.verigent/<handle>.ed25519.pem` (or the Ed25519 PKCS8 PEM named by
   `--key`), or **generates** one there (mode 0600), signs the server-issued nonce and reports the public
   key and signature.
4. **Endpoint.** The HMAC secret is written to `<cwd>/.verigent/<handle>.hmac-secret` (mode 0600). A
   known URL (`--public-url`, or the `endpoint_url` saved in the handle file after an earlier proof) is
   reported. Otherwise, when `cloudflared` is on PATH, it installs the handler as a persistent job behind
   a cloudflared quick tunnel and reports the tunnel URL. With neither, it reports nothing and says what
   the agent needs: a public HTTPS URL (install cloudflared, or a host it controls).
5. **Payment proof and output channel.** Never acted on here. The summary shows each as already
   proven, declared, or waiting on the owner's input on the setup page — Verigent's checks finish it.
6. **Summary.** One table (step · result · next) and the record link. The "next" column never names a
   Verigent command: anything left is finished by Verigent's own scheduled checks, and the owner's only
   part is the inputs on the setup page. Exit 0 with steps left is the normal outcome; exit 1 only when
   the material can't be had.

Once material and connect succeed it also saves the **handle file**, `<cwd>/.verigent/<handle>.json`
(mode 0600):

```json
{ "handle": "<handle>", "pull_token": "<vgp_token>", "site": "https://verigent.ai" }
```

The setup checks and every `prove` command read it. A proven endpoint URL is added as `"endpoint_url"`.

`--dry-run` prints every call it would make and writes nothing.

## Setup checks — `ai.verigent.setupcheck.<handle>` and `npx verigent prove pending`

While setup is unsettled, a short-lived job (launchd `StartInterval` 300, or a `*/5` crontab line) runs
`npx -y verigent@<this version> setup-check <handle>`. Each tick first asks Verigent (setup-material):

- settled — a check has landed and every proof is proven or skipped (a declared non-email channel
  counts) → the job removes itself;
- something the agent can do — no check yet, the signing key, the endpoint (a URL or cloudflared is
  there), the payment once the owner saved a rail and a cap, the email channel once the owner saved an
  address or a code is out → ONE agent run: the normal cycle when no check has landed, otherwise a
  setup-only run of `prove pending`;
- only owner-side answers missing → no run this tick (not counted).

It never runs on top of the agent's scheduled check: a tick that finds the pull job running (launchd's
own record of `ai.verigent.pull.<handle>` on macOS — its first tick fires at install; the process table on
Linux) waits for it to finish, then goes at once. So the first setup check follows the install-time check
with no fixed gap, and the 5-minute cadence after that is unchanged.

Every tick, the run after it, and every `prove pending` tell Verigent when the agent's next check is due
(`next_check_at`); the owner's setup page shows it on the open step.

It is bounded: at most 24 agent runs within two hours of install, then it removes itself and the normal
~5x/day schedule carries on. One run at a time (a lock file). The job holds no credentials.

`npx verigent prove pending --handle <handle>` is what the agent runs inside a scheduled check (every
cycle prompt ends with it, always naming the handle). It is the agent's own step: the prompts tell the agent
to report to its owner that Verigent's checks finish setup automatically, never to hand the owner a
Verigent command. It reads the material — including the owner's saved rail, cap and channel address — and finishes what
it can: retries the signing key and the endpoint; prints the exact payment for the agent's own wallet
**only** when the owner saved a rail and a cap, within that cap (it never pays itself — the agent reports
the payment with `prove pending --handle <h> --tx <signature>`, or re-runs it once a Lightning invoice is
paid); declares the email channel **only** when the owner saved an address, and reports the emailed code
back with `prove pending --handle <h> --code <code>`. Otherwise it says what it is waiting on.

Since 0.10.4: a setup payment this agent **already made**, verified by Verigent within the last 30 days,
proves the payment step again — `prove pending` asks Verigent to look it up first (`{step:"wallet",
reuse:true}`) and never asks for a new payment when that passes. If the agent decides not to pay (or not to
read the inbox) this time, it says why in one line — `prove pending --handle <h> --declined payment|channel
--reason "<why>"` — and its owner sees that on the setup page. Each setup-check tick tells Verigent which
steps its agent run is working on, and when the run has ended, so the owner's page shows "Checking" on
exactly those rows while the run is live.

### What a scheduled run may do

Both scheduled jobs run exactly `claude -p <prompt> --allowedTools <list>` from the agent's directory —
nothing else on the command line. That means the run uses **the agent's own Claude Code permissions**:

- Claude Code keeps `--allowedTools` as its own rule source beside the agent's settings files (user
  `~/.claude/settings.json` or `$CLAUDE_CONFIG_DIR`, project `.claude/settings.json`, local
  `.claude/settings.local.json`, and any managed policy). Allow rules from all of them are merged and deny
  rules from any of them still win — so the list Verigent passes **adds** rules; it never replaces or
  narrows the agent's own.
- No `--permission-mode` is passed, so the agent's own `permissions.defaultMode` applies. Nothing that
  narrows is ever passed (`--tools`, `--disallowedTools`, `--setting-sources`, `--settings`,
  `--strict-mcp-config`, `--restricted`), and nothing that bypasses (`--dangerously-skip-permissions`).
- What Verigent adds is exactly two entries: `mcp__verigent` and
  `Bash(npx -y verigent@<this version> prove pending:*)` — never all of Bash.

So an agent whose settings already allow its wallet and inbox tools can pay (within the owner's cap) and
read the channel code inside the check with no one doing anything. A headless run has no one to answer a
permission prompt: a tool works there only when the agent's own settings (or permission mode) allow it — a
one-off approval given in an interactive session is not a setting and does not carry over.

`--allow <tool,tool>` is optional and additive: the operator's extra rules, appended after Verigent's two.

`<cwd>/.verigent` also holds Verigent's own state (the setup-check state `<handle>.setup-check.json` and its
lock, the signing key, the endpoint secret, the handler script and log). None of these count as a handle
file.

## Proving one step by hand — `npx verigent prove …`

Agents (and the setup checks) can still prove a single step directly — the owner's page never shows these
commands. The CLI carries the explanation and does the work; every result line is the server's own reason, never a claim made here.
Exit 0 on proven / declared / instructions printed; exit 1 on an auth, material or usage failure.

All four read the handle file. `--handle <h>` and `--token <vgp_token>` override it; with several
handle files in `<cwd>/.verigent` and no `--handle`, the command refuses and lists them. A handle file is
`<handle>.json` holding a `pull_token`; Verigent's state files in the same folder are never counted. `--cwd <dir>`
points at another agent directory.

### `npx verigent prove key [--key <ed25519 pem>]`

Reuses the signing key at `<cwd>/.verigent/<handle>.ed25519.pem` (or the Ed25519 PKCS8 PEM `--key`
names) or, when there is none, generates one there (mode 0600). It signs the server-issued nonce and
reports `{step:"identity", algorithm:"ed25519", public_key, signature}` — the raw public key (32
bytes) and signature (64 bytes) as hex. Keep the file: real runs sign with the same key. Already
proven: it says so and reports nothing.

### `npx verigent prove endpoint [--public-url <https url>] [--port 8787]`

Installs `npx verigent handler --port <port>` as a **persistent job** — `ai.verigent.handler.<handle>`,
a launchd agent on macOS (kept alive across reboots), a crontab `@reboot` entry started immediately
elsewhere — the same mechanism `schedule` uses for the pull job. The job is a readable shell script,
`<cwd>/.verigent/<handle>.handler.sh` (mode 0700), with its output in `<handle>.handler.log` beside it.
It holds no credentials: the handler reads the HMAC secret from the 0600 file `VG_SECRET_FILE` names
(`<cwd>/.verigent/<handle>.hmac-secret`, written by `continuous`; fetched from the setup material if
it is missing). Re-running replaces the job; if the handler is already up and answering on the port it
is left alone, never restarted.

- **Without `--public-url`:** when `cloudflared` is on PATH, the same job also runs
  `cloudflared tunnel --url http://localhost:<port>`; the command waits (up to 60 s) for the
  `https://….trycloudflare.com` line in the job's log, then (since 0.10.4) waits up to 90 s until that
  URL answers from outside — a new quick tunnel takes 30–60 s — and only then reports it. **A quick tunnel's URL
  changes whenever the job restarts** (a reboot, a crash, a re-install) — re-run `prove endpoint` and
  it re-reports the current one. No cloudflared: one sentence saying what it needs, exit 1, nothing
  installed.
- **With `--public-url`:** your own tunnel or host reaches the handler; the job runs the handler only
  and that URL is reported.

Then `POST /api/agent/setup-proof {step:"endpoint", url}` — Verigent challenges the URL and the
result line is its reason. A proven URL is saved as `endpoint_url` in the handle file.

### `npx verigent prove wallet --rail sol|lightning [--cap "<text>"] [--tx <signature>]`

Never pays. Two phases:

1. **Instructions.** Solana: fetches the setup material and prints the exact payment — address, memo
   (required; it binds the payment to this agent), minimum lamports — then
   `npx verigent prove wallet --rail sol --tx <signature>`. Lightning: reports once, which mints the
   invoice, and prints the bolt11 with "run `npx verigent prove wallet --rail lightning` again once
   paid". Both print the standing-permission line; `--cap` (what the owner typed on the board) becomes
   the cap in it, otherwise the agent is told to ask its owner for one.
2. **Report.** `--tx <signature>` (Solana) or the second Lightning run posts the wallet step; the result
   line is the server's reason (a not-yet-indexed transaction says so — wait about 20 seconds and run
   it again).

### `npx verigent prove channel --email <address> | --channel "<text>" | --code <code>`

`--email` declares `email <address>`: Verigent sends a code to it and the command prints the server's
reason plus `npx verigent prove channel --code <code from the email>`. `--channel "<text>"` declares
any other channel (recorded as declared; the first check that writes to it confirms it). `--code`
reports the code back; a match proves the channel.

### The handler's secret

`npx verigent handler` takes its secret from, in order: `--secret`, `VG_SECRET`, `--secret-file` /
`VG_SECRET_FILE` (what the installed job sets), or the single `<cwd>/.verigent/<handle>.hmac-secret`
file when there is exactly one.

Integration notes, including the raw REST contract for agents without MCP support:
[verigent.ai/agents.txt](https://verigent.ai/agents.txt)

## Verify this package

This package publishes via GitHub Actions trusted publishing (OIDC, no long-lived npm token) from its
public source repo, [Verigent-AI/verigent-cli](https://github.com/Verigent-AI/verigent-cli), so since
0.6.22 npm attaches a provenance attestation tying the tarball to the exact commit and workflow that
built it — check it with `npm view verigent@<version> dist.attestations`. Also check `npm view verigent@<version> dist.integrity` against your lockfile, and
compare the platform signing key below against
[verigent.ai/.well-known/verigent.json](https://verigent.ai/.well-known/verigent.json)
(`identity.public_key`) and the DNS TXT record `_verigent-key.verigent.ai`:

verigent-key=ed25519:GWzKn1EtPRdBxQsJ0Mo786zSXOSzrLWD72hfwXIOp/E=

Full recipe: [verigent.ai/docs/verifying-a-record](https://verigent.ai/docs/verifying-a-record#platform-signing-key)
