# Changelog

## 1.1.1 — 2026-10-23

- Merge additive headers into an existing `_headers` wildcard block; create it only when absent.
- Refuse re-check output inside the open project before any requests, using the required `--project` argument.
- Add a local nosniff recipe gated by explicit owner confirmation of correct asset MIME types, the access-impact check and per-item diff approval. Unconfirmed items remain developer-only.

## 1.1.0 — 2026-10-23

- Added an opt-in guided fix after the report, one item at a time, with exact local diffs, testing instructions and a separate approval for every edit.
- Added conservative risk classification, owner-operated dashboard/DNS guidance, and copyable File/Change/How to test prompts for code findings.
- Added focused before/after re-checks for a single finding and confirmed host; unpublished changes produce “deploy, then re-check” without requests.
- Added a synthetic header-project workflow test, approval/path safeguards and checks against publishing, login or cloud-write execution paths.
- Hardened Markdown summaries against site-supplied markup.

## 1.0.1 — 2026-10-23

- Added conservative effort tags/reasons, developer-row booking line, and an opt-in free 15-minute review footer.
- Added public Supabase/Firebase configuration guidance with Row Level Security / Security Rules dashboard steps, browser password/storage gate hints, preview visibility checks, and public platform hints feeding fixes.
- Added explicit bundle sourceMappingURL HEAD checks within the existing two-request asset budget; backend queries, found-key use, guessed map paths and map downloads remain prohibited.
- Renamed the marketplace to `swarm-site-check`; install with `site-check@swarm-site-check`.
- Added offline app-check/report tests, refreshed synthetic examples, and `scripts/selftest.sh --offline`.

## 1.0.0 — 2026-10-23

- Added the `site-check` Claude Code plugin and `swarm-tools` marketplace.
- Added confirmed-scope, passive Python standard-library collection and redacted evidence.
- Added live OSV package matching, a mandatory independent reviewer, and self-contained HTML reports.
- Added offline synthetic parser/safety tests and an opt-in example.com self-test.
