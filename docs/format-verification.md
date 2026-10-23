# Packaging and API verification

Verified against the current official documentation on 2026-10-23:

- [Plugin manifest](https://code.claude.com/docs/en/plugins-reference): `.claude-plugin/plugin.json`, components at the plugin root, `${CLAUDE_PLUGIN_ROOT}` substitution in skill content, `claude plugin validate`.
- [Create a marketplace](https://code.claude.com/docs/en/plugin-marketplaces): repository-local `.claude-plugin/marketplace.json`, required name/owner/plugins, plugin source relative to the marketplace root, install identity `plugin@marketplace`.
- [Skill names and invocation](https://code.claude.com/docs/en/skills#how-a-skill-gets-its-command-name): plugin skills retain a namespace; the bare name also invokes the skill while no other command owns it. This plugin supplies `/site-check`, with `/site-check:site-check` as its unambiguous qualified name.
- [Skill substitutions](https://code.claude.com/docs/en/skills#available-string-substitutions): `${CLAUDE_PROJECT_DIR}` identifies the open project, while `${CLAUDE_PLUGIN_ROOT}` identifies installed helpers. Guided edits target the confirmed project file.
- [Subagents](https://code.claude.com/docs/en/sub-agents): agent Markdown frontmatter, fresh context, read-only tools, inherited model. The reviewer uses `Read, Grep, Glob` only.
- [OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/): batch results contain IDs and timestamps, so the checker retrieves advisory details separately, follows batch pagination up to four pages, and reports incomplete coverage.
- [OSV ecosystem schema](https://ossf.github.io/osv-schema/#affectedpackage-field): npm names for n8n/next/react/vite, Packagist for identifiable PHP packages, and WordPress:Core / WordPress:Plugin / WordPress:Theme. Schema support alone does not establish database coverage. WordPress results include an explicit coverage warning and independent lookup destinations.

Validation on Claude Code 2.1.301:

```text
claude plugin validate . --strict
claude plugin validate .claude-plugin/plugin.json --strict
claude plugin validate skills --strict
claude plugin validate agents --strict
```

All four commands passed.

The marketplace name is `swarm-site-check` and plugin name is `site-check`, so the install identity is `site-check@swarm-site-check`. The current validator accepts that name, the repository-root `./` source, and both manifests under `--strict`.

Dashboard advice was checked against current primary documentation:

- [Supabase API security](https://supabase.com/docs/guides/api/securing-your-api) and [Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security): Database → Policies, enable RLS per exposed table and review policies. Public config alone reveals no policy state.
- [Firebase Rules management](https://firebase.google.com/docs/rules/manage-deploy) and [security checklist](https://firebase.google.com/support/guides/security-checklist): each product's Rules tab; client configuration is public, with access governed separately.
- [Cloudflare Pages preview access](https://developers.cloudflare.com/pages/configuration/preview-deployments/): Workers & Pages project settings, preview access policy, with separate production/custom-host protection.
- [Vercel Deployment Protection](https://vercel.com/docs/deployment-protection) and [Netlify password protection](https://docs.netlify.com/manage/security/secure-access-to-sites/password-protection/): project controls used in platform-specific access advice. Availability depends on the account/plan.

Source-map HEADs share the existing two-request asset ceiling with bundle GETs. RLS/Rules guidance never triggers backend requests or credential use. The opt-in review invitation performs no upload or email action.

Guided header recipes and manual dashboard instructions were checked against:

- [Cloudflare response-header transform rules](https://developers.cloudflare.com/rules/transform/response-header-modification/create-dashboard/): rule creation, custom hostname filter, static header/value and owner-operated Deploy/Save as Draft actions.
- [Netlify custom headers](https://docs.netlify.com/manage/routing/headers/): `_headers` in the publish directory and `[[headers]]` / `[headers.values]` in `netlify.toml`; function/proxy responses need their own handling.
- [Next.js headers](https://nextjs.org/docs/app/api-reference/config/next-config-js/headers): a synchronous or async headers function returns source patterns and key/value header arrays.
- [Vercel static configuration](https://vercel.com/docs/project-configuration/vercel-json#headers): `headers` arrays, the `/(.*)` source pattern, and header key/value pairs.

See [guided fixes](guided-fixes.md) for consent, conservative eligibility, local edit boundaries, owner publishing and focused re-check budgets. No cloud write, login or publishing capability is added.
