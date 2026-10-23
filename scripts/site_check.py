#!/usr/bin/env python3
"""Swarm Site Check: explicit scope -> bounded collection -> independent review -> HTML."""
import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

from checks import collect, match_osv
from network import CheckError, OWNERSHIP, Transport, normalize_url, scope_digest
from report import evidence_hash, render
from guided import accepted_item, apply_plan, locate_configs, prepare_plan, require_opt_in, settings_steps
from recheck import recheck


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def write_new_json(path, value):
    """Guided artifacts must never overwrite a project file or a previous plan."""
    with Path(path).open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=True)
        handle.write("\n")


def require_external_output(path, project):
    target, root = Path(path).resolve(), Path(project).resolve(strict=True)
    if not root.is_dir() or target == root or root in target.parents:
        raise CheckError("Keep plan and re-check artifacts outside the open project; no project file was written or requests sent.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scope = sub.add_parser("scope", help="Normalize and display scope offline. No requests.")
    scope.add_argument("sites", nargs="*")
    scope.add_argument("--hosts-file", type=Path)
    scope.add_argument("--out", type=Path, required=True)
    run = sub.add_parser("run", help="Collect candidate findings only after matching confirmation.")
    run.add_argument("--scope", type=Path, required=True)
    run.add_argument("--confirmed-scope", required=True, help="SHA-256 of the exact displayed site list")
    run.add_argument("--ownership", required=True, help=OWNERSHIP)
    run.add_argument("--output", type=Path, required=True)
    report = sub.add_parser("report", help="Render only findings accepted by the evidence reviewer.")
    report.add_argument("--evidence", type=Path, required=True)
    report.add_argument("--review", type=Path, required=True)
    report.add_argument("--output", type=Path, required=True)
    locate = sub.add_parser("guide-locate", help="After opt-in, list existing header configs in the open project; offline.")
    locate.add_argument("--project", type=Path, required=True)
    locate.add_argument("--opt-in", required=True)
    plan = sub.add_parser("guide-plan", help="Prepare one exact local diff and tests; never applies it.")
    apply = sub.add_parser("guide-apply", help="Apply one reviewed local plan only after an item-specific yes.")
    settings = sub.add_parser("guide-settings", help="Print owner-only dashboard steps or supplied DNS values; no API/CLI writes.")
    again = sub.add_parser("recheck", help="Repeat only one accepted check on its confirmed host.")
    for command in (plan, apply, settings, again):
        command.add_argument("--evidence", type=Path, required=True)
        command.add_argument("--review", type=Path, required=True)
    for command in (plan, settings, again):
        command.add_argument("--finding", required=True)
    for command in (plan, apply, again):
        command.add_argument("--project", type=Path, required=True)
    plan.add_argument("--file", required=True)
    plan.add_argument("--opt-in", required=True)
    plan.add_argument("--access-impact", choices=("none", "possible", "unknown"), default="unknown")
    plan.add_argument("--mime-types-correct", choices=("yes", "no", "unknown"), default="unknown",
                      help="Explicit owner confirmation of correct asset MIME types; required for a nosniff plan")
    plan.add_argument("--out", type=Path, required=True)
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--approval", required=True)
    apply.add_argument("--confirmed-plan", required=True)
    settings.add_argument("--opt-in", required=True)
    settings.add_argument("--host", required=True)
    settings.add_argument("--provider", choices=("Cloudflare", "Vercel", "Netlify", "other"), required=True)
    settings.add_argument("--confirmed-provider", required=True)
    settings.add_argument("--dns-value-file", type=Path)
    settings.add_argument("--access-impact", choices=("none", "possible", "unknown"), default="unknown")
    again.add_argument("--url", required=True)
    again.add_argument("--confirmed-scope", required=True)
    again.add_argument("--ownership", required=True)
    again.add_argument("--deployed", choices=("yes", "no"), default="no")
    again.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.command == "scope":
        inputs = list(args.sites)
        if args.hosts_file:
            inputs += [line.strip() for line in args.hosts_file.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]
        sites = sorted(set(normalize_url(x) for x in inputs))
        if not sites or len(sites) > 200:
            raise CheckError("List 1–200 public URLs.")
        digest = scope_digest(sites)
        write_json(args.out, {"sites": sites, "sha256": digest})
        print("Confirm the entire scope before running:")
        for site in sites:
            print("  " + site)
        print("Scope SHA-256: " + digest)
        print('Required ownership confirmation: "' + OWNERSHIP + '"')
    elif args.command == "run":
        scope = json.loads(args.scope.read_text())
        transport = Transport(scope, args.confirmed_scope, args.ownership)
        if args.output.exists() and any(args.output.iterdir()):
            raise CheckError("Use a new empty output directory to preserve prior evidence.")
        args.output.mkdir(parents=True, exist_ok=True)
        print("Checking %d confirmed pages; values and source bodies are never logged." % len(transport.urls), flush=True)
        ev = collect(transport)
        match_osv(ev, transport)
        result = {"schema_version": 1, "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                  "scope": scope, "facts": ev.facts, "candidates": ev.candidates,
                  "versions": ev.versions, "coverage": ev.coverage, "network_calls": transport.calls}
        evidence = args.output / "raw" / "evidence.json"
        write_json(evidence, result)
        write_json(args.output / "review.template.json", {"evidence_sha256": evidence_hash(evidence.read_bytes()),
                   "reviewer": "", "decisions": [{"id": f["id"], "verdict": None, "severity": f["severity"],
                   "evidence": f["evidence"], "reason": ""} for f in ev.candidates]})
        print("Collected %d evidence lines and %d candidates. Independent review is required before report generation." % (len(ev.facts), len(ev.candidates)))
        print("Raw evidence: " + str(evidence))
    elif args.command == "report":
        kept, dropped = render(args.evidence, args.review, args.output)
        print("Report written: %d accepted findings, %d dropped." % (kept, dropped))
        print(str(args.output / "report.html"))
    elif args.command == "guide-locate":
        print(json.dumps({"files": locate_configs(args.project, args.opt_in), "note": "Confirm the active serving config with the owner; no files changed."}))
    elif args.command == "guide-plan":
        require_external_output(args.out, args.project)
        envelope = prepare_plan(args.evidence, args.review, args.finding, args.project, args.file, args.opt_in, args.access_impact, args.mime_types_correct)
        write_new_json(args.out, envelope)
        print(envelope["plan"]["effort_tag"] + ": " + envelope["plan"]["effort_reason"])
        print(envelope["plan"]["diff"])
        print("How to test: " + envelope["plan"]["how_to_test"])
        print("How to publish yourself: " + envelope["plan"]["how_to_publish"])
        print("Plan SHA-256: " + envelope["sha256"])
        print("Ask for yes to this exact item before guide-apply. No project file changed.")
    elif args.command == "guide-apply":
        result = apply_plan(json.loads(args.plan.read_text()), args.evidence, args.review, args.project, args.approval, args.confirmed_plan)
        print(json.dumps(result, indent=2))
    elif args.command == "guide-settings":
        require_opt_in(args.opt_in)
        data, row = accepted_item(args.evidence, args.review, args.finding)
        if normalize_url(args.host).split("/", 3)[2] != row["site"].split("/", 1)[0]:
            raise CheckError("Settings instructions must refer to the selected finding's host.")
        value = args.dns_value_file.read_text().strip() if args.dns_value_file else None
        print(json.dumps(settings_steps(row, args.host, args.provider, args.confirmed_provider, value, args.access_impact), indent=2))
    elif args.command == "recheck":
        require_external_output(args.out, args.project)
        if args.out.exists():
            raise CheckError("Use a new re-check output file; no requests were sent.")
        result = recheck(args.evidence, args.review, args.finding, args.url, args.confirmed_scope, args.ownership, args.deployed)
        write_new_json(args.out, result)
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Stopped. No site changes made.", file=sys.stderr)
        sys.exit(130)
    except (CheckError, OSError, ValueError, KeyError, TypeError) as exc:
        # Exception details from input/network must never leak secrets or values.
        print("site-check: " + (str(exc) if isinstance(exc, CheckError) else "Invalid input or unavailable local file; no raw values were logged."), file=sys.stderr)
        sys.exit(2)
