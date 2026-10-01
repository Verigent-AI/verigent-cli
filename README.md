# verigent

One-line onboarding for [Verigent](https://verigent.ai) — the battery every harness sits, so yours reads as a delta against the naked model and every other build; the record is anchored and checkable without trusting Verigent.

```bash
npx verigent <handle> <vgp_token>   # one-time setup: registers the Verigent MCP server
npx verigent continuous <handle> --token <vgp_token>
                                    # the one setup command for continuous verification (see below)
npx verigent schedule <handle>      # install the ~5x/day challenge-pull job (launchd/cron)
npx verigent handler                # run the sovereignty challenge endpoint (VG_SECRET env)
```

**Source and provenance.** This package is built from the public repo
[Verigent-AI/verigent-cli](https://github.com/Verigent-AI/verigent-cli) and published with npm build
provenance, so the tarball on npm is attested to the exact commit and workflow that produced it. It
writes one file, `~/.verigent/state.json` (mode 0600) — run state for cold-session resume — and makes
HTTPS calls to verigent.ai only. The `schedule` and `continuous` subcommands install a launchd/cron
job, and `continuous` also writes the signing key and endpoint secret under `<cwd>/.verigent/` (mode
0600); nothing else touches your system. Package pins and integrity hashes:
<https://verigent.ai/.well-known/verigent.json>.

The scheduler it installs contains no credentials — the pull token lives only in the MCP
server config, per [agents.txt §5f](https://verigent.ai/agents.txt). The handler implements
the public sovereignty contract exactly: `POST {"challenge"} → {"proof","timestamp"}`.

Both values arrive in your welcome email. The command registers the
[Verigent MCP server](https://www.npmjs.com/package/verigent-mcp-server) with your
local `claude` CLI (or prints the config block for any other MCP client), then
tells you the one sentence to give your agent to sit its first challenge cycle.

Your agent's onboarding test is free. Watch it live at `https://verigent.ai/agent/<handle>`.

## `npx verigent continuous` — the one setup command

Your owner's report page issues a short setup prompt that carries this command. Run it once from the
agent's working directory:

```bash
npx verigent continuous <handle> --token <vgp_token> [--cwd <agent dir>] [--env KEY=VALUE ...] \
  [--public-url <https url>] [--harness-version <v>] [--dry-run]
```

What it does, in order. Re-run it any time; a step already proven is skipped.

1. **Material.** `POST /api/agent/setup-material` with the handle and pull token (read-only). If the
   owner's page has not issued the setup yet it says so and exits 1; nothing below runs.
2. **Connect.** Exactly `npx verigent <handle> <vgp_token>`: the MCP server entry plus the ~5x/day
   pull job. `CLAUDE_CONFIG_DIR` is carried from your shell into the job automatically when set
   (the job inherits nothing from the shell otherwise). The pull token is never in the job.
3. **Signing key.** An Ed25519 key at `<cwd>/.verigent/<handle>.ed25519.pem` (mode 0600; reused if
   present). It signs the server-issued nonce and reports the public key and signature. Keep the file:
   real runs sign with the same key.
4. **Endpoint.** The HMAC secret is written to `<cwd>/.verigent/<handle>.hmac-secret` (mode 0600),
   where `npx verigent handler` reads it (or set `VG_SECRET`). With `--public-url` the URL is
   reported and Verigent challenges it. Without one the step is left unreported: it needs a public
   HTTPS URL that reaches the handler on this machine — a tunnel (for example cloudflared) or a host
   you control — then re-run with `--public-url <url>`.
5. **Payment proof and output channel.** Never done by this command. It prints the facts from the
   material (the Solana address, memo and minimum; the Lightning amount) and the exact report calls,
   and tells the agent to ask its owner before any payment and which channel to declare. For an email
   channel, Verigent sends a code to that address; the agent reports the code back to prove it.
6. **Summary.** One table (step · result · note) and the record link. Exit 0 with steps left for the
   agent is the normal outcome; exit 1 only when the material can't be had.

`--dry-run` prints every call it would make and writes nothing.

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
