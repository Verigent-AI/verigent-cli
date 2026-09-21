# Releasing `verigent` (the CLI)

**Source of truth: the public repo `Verigent-AI/verigent-cli`** (split out of the private monorepo
2026-09-22 on Ant's ruling, after Kit's install audit found the asymmetry: the MCP server carried npm
build provenance, the CLI — the thing that actually edits a user's config — did not, because its source
was private). The CLI holds no probe content, rubrics, scoring or keys; publishing its source changes
nothing about what a test-taker can learn (the exam hall is public, the exam is not — Constitution §2.2).

Publishing goes through GitHub Actions in the PUBLIC repo using **npm trusted publishing (OIDC)** —
no `NPM_TOKEN`, no stored token, no 2FA prompt — and now **with `--provenance`**, so every release
carries a SLSA attestation tying the tarball on npm to the exact public commit + workflow that built it.

## How the two repos relate

- `verigent-private/cli/` is a **mirror**, kept in the monorepo so `professor/binding-check.mjs` can
  read `cli/package.json` + `cli/index.js` (the MCP_PKG pin) on every prebuild and deploy.
- The mirror is pushed to the public repo automatically by `.github/workflows/cli-mirror.yml` on every
  push to `main` that touches `cli/` (`git subtree push --prefix=cli`). **Edit here, merge to main, and
  the public repo follows.** Never hand-edit the public repo — it would be overwritten by the next mirror
  push, and the private tree would then disagree with what shipped.
- History is preserved: the public repo was seeded with `git subtree split --prefix=cli` of main.

## One-time setup (done once, on npmjs.com — Ant, passkey login)

Someone with publish rights on the `verigent` package rebinds the trusted publisher: package Settings →
Trusted Publisher → GitHub Actions → org `Verigent-AI`, repo **`verigent-cli`** (was `verigent-private`),
workflow filename `cli-publish.yml` — and keep "Allow direct `npm publish`" ticked. Until this is done a
tag push in the public repo fails auth (nothing publishes — safe), and the old binding to the private
repo no longer matches any workflow (its `cli-publish.yml` was removed the same day).

The mirror workflow needs one repo secret in `verigent-private`: `CLI_MIRROR_TOKEN` — a GitHub token
with `contents: write` on `Verigent-AI/verigent-cli` only.

## Cutting a release

The CLI's tag scheme is **`cli-vX.Y.Z`** — deliberately different from the mcp-server repo's `vX.Y.Z`
tags so a tag push can never be pointed at the wrong package or workflow. Releases are bundled with the
MCP server's (Ant 2026-09-20: no standalone releases).

1. In `verigent-private`: bump `version` in `cli/package.json`. If this release picks up a new
   `verigent-mcp-server` version, re-pin it in `cli/index.js` (`MCP_PKG`) and in
   `public/.well-known/verigent.json` (version / install / integrity / shasum) **first** — see the
   mcp-server repo's `docs/RELEASING.md` "After a server publish" — and run
   `professor/binding-check.mjs --online` to confirm the pins match what is live on npm.
2. Merge to `main`. The mirror workflow pushes `cli/` to the public repo.
3. In the PUBLIC repo, tag the mirrored commit and push the tag:
   ```
   git tag cli-vX.Y.Z && git push origin cli-vX.Y.Z
   ```
4. `cli-publish.yml` in the public repo runs a syntax check, then `npm publish --provenance` via trusted
   publishing. Watch the run under the public repo's Actions tab; the npm listing shows the provenance
   badge once it lands.
5. Idempotent: if `X.Y.Z` is already on npm, the publish step is skipped instead of erroring.
   `workflow_dispatch` re-runs against whatever `version` is on that ref.
6. Re-sign the binding after the publish (`professor/emit-binding-signature.mjs`) — the version /
   integrity pins changed.

## Scope note

The publish workflow only ever touches the `verigent` npm package. It never builds, tests or publishes
anything from the private monorepo.
