# Guided fixes

After delivering the independently reviewed report, `/site-check` asks:

> Want to fix the 'Fix it yourself' items now, one at a time?

Only an explicit yes starts this flow. Ownership consent and asking for a report do not authorize project inspection or edits. Finish or defer each selected item before starting the next.

## Local code changes

1. Select one accepted DIY finding. Claude locates existing header configuration files in the open project, without running project code.
2. Confirm the actual serving file and that the header has no authentication/access dependency. For nosniff, the owner must also explicitly confirm that assets, including scripts and styles, are served with correct MIME types before the local recipe is offered. Unknown or possible impact requires a developer.
3. Claude prepares the entire exact diff, names the file, explains local syntax/navigation/login tests, and explains how you can publish through your existing project workflow. Planning makes no project change.
4. Say yes to that exact item and diff. The helper applies only the displayed supported change, checking the project, original file, finding, evidence, review and plan hashes. Changed files or plans require another review and yes.
5. Test and publish yourself. The plugin never executes package hooks, commits, pushes or deployment commands.

The supported local recipes add `Referrer-Policy: strict-origin-when-cross-origin` or, after explicit MIME confirmation, `X-Content-Type-Options: nosniff` in an existing `_headers`, simple `next.config.js/mjs/ts`, `vercel.json`, `netlify.toml` or `.htaccess`. `_headers` merges into the existing `/*` block, or creates that block when absent; multiple existing wildcard blocks require review. Any existing target header is refused, including an ineffective value. Complex JavaScript, duplicate JSON keys, legacy routing, symlinks, hard links and suspicious credentials are refused. The helper never evaluates configuration code. Public-key verification offers no code edit or credential use.

For `_headers`, confirm it reaches the publish directory; Netlify/Cloudflare static header files do not set headers on every function or proxied response. Next.js requires its normal application build. Vercel and Netlify root configuration must match the configured project root. Apache needs `mod_headers` and permission to use the directive. These are owner checks; a public platform marker cannot establish them. Missing or unsupported files require a developer instead of a guessed path.

The command uses `guide-locate`, `guide-plan` and `guide-apply`. All are offline. `guide-plan --access-impact none` records established absence of auth/access dependencies; the default `unknown` refuses a plan. Nosniff additionally requires `--mime-types-correct yes`, recording the owner's explicit confirmation. Its default `unknown` and answer `no` keep the item developer-only. Site evidence cannot grant that confirmation, and no extra network probes establish it. Only this gated local path changes nosniff's effort tag; the report and settings guidance remain conservative. A plan file is outside the project, and contains the exact diff, confirmations, tests, publishing instructions and SHA-256. `guide-apply --approval yes --confirmed-plan <displayed-sha256>` records the new item-specific approval and revalidates the plan's confirmations. The flags cannot independently establish that a human said yes; the skill must obtain it.

## Settings instructions

The offline `guide-settings` helper requires a reviewed finding, guided opt-in, and owner confirmation of the actual provider. For a safe referrer-header change on a confirmed Cloudflare domain:

1. Open Cloudflare and select the domain.
2. Open **Rules → Overview → Create rule → Response Header Transform Rule**.
3. Name the rule; select a custom filter with **Hostname equals** the finding's exact hostname, such as `example.com`.
4. Select **Set static**, header **Referrer-Policy**, value **strict-origin-when-cross-origin**.
5. Review existing header rules and matching scope. An existing policy or access dependency needs developer review.
6. The owner selects **Deploy** to activate, or **Save as Draft** to keep it inactive. The plugin never clicks either or calls the write API.

Vercel/Netlify header instructions point to the confirmed source project and configuration file; they do not invent a dashboard header control. Other providers need the owner's documented instructions.

SPF/DMARC handoffs show an exact TXT name/value only after the owner supplies the sender inventory, existing policies and provider/developer-approved value through `--dns-value-file`. For example.com, the names are `example.com` and `_dmarc.example.com`. No mail policy is guessed, and no record is written. Mail-policy changes remain developer-only because they can break mail and account recovery. Server/runtime upgrades also remain developer-only; the developer must identify the actual installation and supported upgrade procedure.

## Re-check one item

If the owner has not published, Claude says **deploy, then re-check** and supplies the command with the selected finding's values:

```sh
sh "${CLAUDE_PLUGIN_ROOT}/scripts/site-check.sh" recheck --evidence "<run>/raw/evidence.json" --review "<run>/review.json" --project "${CLAUDE_PROJECT_DIR}" --finding "<accepted-id>" --url "https://example.com/" --confirmed-scope "<original-scope-sha256>" --ownership "these are sites I own or run" --deployed yes --out "<run>/item-recheck.json"
```

The URL must be the finding's exact originally confirmed URL. The required `--project` identifies the open project; `--out` must resolve outside it, including when parent paths are symlinks. The output check happens before any requests. `--deployed no` (also the default) emits the reminder with zero requests. The result contains original finding/evidence, after status/evidence, coverage and a request ledger. There are no redirects, retries, new hosts, guessed paths, backend queries or found-key use.

| Selected check | Maximum site activity, plus required public DNS |
|---|---|
| One header, cookie flags or disclosure | One GET of the originally listed page; only the selected check is evaluated |
| HTTP behavior | One plain-HTTP root GET; redirects recorded without following |
| One legacy TLS version | One handshake for the protocol cited by that finding |
| SPF or DMARC | One TXT lookup for the selected apex policy |
| Public client-key presence | One listed page and at most two same-origin bundle GETs linked by that page; no map requests or key use |

The normal transport timeouts, byte limits, spacing and confirmation checks still apply. A new transport contains only the selected host. Unavailable/unsupported checks, changed page status and incomplete inspected content are inconclusive. Public-key presence cannot verify backend permissions. The helper does not repeat the full collection or OSV matching.

## Developer handoff and Fix prompts

Live Supabase Row Level Security / Firebase Security Rules, authentication, client-side password gates, secret migration/rotation, server/runtime/package upgrades, and anything that could lock users out remain **Needs a developer**. The report includes the reason and the optional **Free 15-minute review of this report with Swarm: book here and bring the report** ([book here](https://calendar.app.google/6AfUX9o53wDxtQs9A)). No generic guided-flow approval permits an automatic edit to these items.

Every code finding includes an expandable, copyable **Fix prompt**, also saved in `fix-prompts.md`: **File**, **Change**, and **How to test**. Copy it with the associated report row. Public evidence identifies source/configuration families; Claude must locate the actual file in the open project. Developer-only prompts prepare a plan without applying it. Prompts contain no found secret values. Nothing is uploaded or emailed.
