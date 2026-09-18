# Releasing `verigent` (the CLI)

Publishing to npm goes through GitHub Actions using **npm trusted publishing (OIDC)** — no
`NPM_TOKEN`, no security key, no 2FA prompt. The old manual formula (security-key dance in a
browser) is retired; see
`~/.claude-chunk/memory/persistent/20260817_reference_verigent_npm_publish_formula.md` for the
history of why this exists.

**Source repo is private.** `verigent-private` is a private repo publishing a public npm package
(`verigent`). Trusted-publishing auth works fine from a private repo — npm just won't attach a
provenance attestation to the published package (provenance requires a public source repo). That's
expected and fine; it's a cosmetic difference on the npm listing, not a publish blocker.

## One-time setup (done once, on npmjs.com)

Before the first trusted-publish run, someone with publish rights on the `verigent` package must
bind the workflow on npmjs.com: package Settings → Trusted Publisher → GitHub Actions → org
`Verigent-AI`, repo `verigent-private`, workflow filename `cli-publish.yml` — **and tick "Allow
direct `npm publish`"** (new trusted-publisher configs default to staged-only, which needs a manual
promote click on npmjs.com each time; ticking this avoids that entirely).

## Cutting a release

The CLI's tag scheme is **`cli-vX.Y.Z`** — deliberately different from the mcp-server repo's
`vX.Y.Z` tags so a tag push can never be pointed at the wrong package or workflow.

1. Bump `version` in `cli/package.json`. If this release picks up a new `verigent-mcp-server`
   version, re-pin it in `cli/index.js` (`MCP_PKG`) and in
   `public/.well-known/verigent.json` (version / install / integrity / shasum) **first** — see the
   mcp-server repo's `docs/RELEASING.md` "After a server publish" section — and run
   `professor/binding-check.mjs --online` to confirm the pins match what's actually live on npm.
2. Commit the bump.
3. Tag it and push the tag:
   ```
   git tag cli-vX.Y.Z
   git push origin cli-vX.Y.Z
   ```
4. GitHub Actions (`.github/workflows/cli-publish.yml`) picks up the tag push, runs a syntax check,
   then publishes via trusted publishing. Watch the run under the repo's Actions tab.
5. The workflow is idempotent — if `X.Y.Z` is already live on npm (e.g. the tag push re-ran), it
   skips the publish step instead of erroring.
6. You can also trigger a release manually from the Actions tab (`workflow_dispatch`) against
   whatever `version` is currently in `cli/package.json` on that ref — useful for a re-run without
   needing a new tag.

## Scope note

This workflow only ever runs `cli/` (`working-directory: cli`) and only ever touches the `verigent`
npm package. It never builds, tests, or publishes anything from the rest of this monorepo.
