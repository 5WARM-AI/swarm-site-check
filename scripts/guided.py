"""Offline, review-bound local header plans. Only an approved item can be written.

No commands, network, credential handling, cloud writes or publishing operations.
"""
import difflib
import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from guidance import CALL, FREE_REVIEW, risk_reason, with_guidance
from network import CheckError, normalize_url
from parsers import redact, secrets
from report import evidence_hash, reviewed_findings

CONFIG_NAMES = {"_headers", "next.config.js", "next.config.mjs", "next.config.ts", "vercel.json", "netlify.toml", ".htaccess"}
HEADER = "Referrer-Policy"
VALUE = "strict-origin-when-cross-origin"
HEADER_RECIPES = {"referrer": (HEADER, VALUE), "nosniff": ("X-Content-Type-Options", "nosniff")}
TEST_STEPS = ("Confirm this file is used by the serving project. Validate its syntax without running unreviewed project scripts. "
              "Use the project's documented local preview/test process after checking it has no publishing hooks; verify navigation, links, assets and login flows. "
              "In browser Network tools inspect the response for {header}: {value}. "
              "After the owner publishes, run the single-finding re-check. If it fails, review this exact diff with a developer.")
PUBLISH_STEPS = ("No publication was performed. Follow your project's documented build and release process yourself: "
                 "confirm the selected config is included in the build, test it, then publish through the existing host/project. "
                 "For _headers, include it in the published output; Next.js needs its normal application build; vercel.json/netlify.toml "
                 "must be in the configured project root; .htaccess needs Apache mod_headers and permission for that directive. "
                 "deploy, then re-check")


def accepted_item(evidence_path, review_path, finding_id):
    raw = Path(evidence_path).read_bytes()
    data = json.loads(raw)
    review = json.loads(Path(review_path).read_text())
    rows, _ = reviewed_findings(data, review, evidence_hash(raw))
    row = next((r for r in rows if r["id"] == finding_id), None)
    if row is None:
        raise CheckError("Select one finding accepted by the evidence reviewer.")
    return data, with_guidance(row, row.get("platforms", []))


def require_opt_in(answer):
    if answer != "yes":
        raise CheckError("Guided fix needs an explicit yes. No project file was changed.")


def require_safe_item(row, *, mime_types_correct="unknown"):
    row = with_guidance(row, row.get("platforms", []), mime_types_correct=mime_types_correct)
    if row["risk_reason"] or not row["guided_eligible"]:
        raise CheckError("Needs a developer. " + row["risk_reason"] + " This item cannot be auto-fixed in the guided flow. " + FREE_REVIEW + ": " + CALL)
    return row


def require_safe_access(access_impact):
    if access_impact != "none":
        raise CheckError("Needs a developer: confirm that this header change has no authentication or user-access dependency before planning an edit. " + FREE_REVIEW + ": " + CALL)


def locate_configs(project, opt_in):
    require_opt_in(opt_in)
    root = Path(project).resolve(strict=True)
    if not root.is_dir():
        raise CheckError("Open a project directory first.")
    found, visited = [], 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        relative = Path(directory).relative_to(root)
        dirs[:] = sorted(d for d in dirs if d not in {".git", ".work", "node_modules", ".next", ".venv", "vendor"}
                         and not (Path(directory) / d).is_symlink() and len(relative.parts) < 5)
        visited += len(files)
        if visited > 5000:
            raise CheckError("Project search limit reached; identify the active config with its owner.")
        for name in sorted(files):
            if name in CONFIG_NAMES and not (Path(directory) / name).is_symlink():
                candidate = str(relative / name)
                checked_path(root, candidate)
                found.append(candidate)
    return found


def checked_path(project, relative):
    root = Path(project).resolve(strict=True)
    rel = Path(relative)
    if any(ord(c) < 32 or ord(c) == 127 for c in str(root) + str(relative)) or redact(str(root) + str(relative)) != str(root) + str(relative):
        raise CheckError("Unsafe or sensitive project path; no path or diff was displayed.")
    if rel.is_absolute() or not rel.parts or any(p in ("..", ".git", "node_modules", ".venv") for p in rel.parts) or rel.name not in CONFIG_NAMES:
        raise CheckError("Choose an existing supported config inside the open project.")
    path = root
    for part in rel.parts:
        path = path / part
        if path.is_symlink():
            raise CheckError("Symlinked project files are refused.")
    if not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > 256 * 1024:
        raise CheckError("Config must be a small regular file with no hard links.")
    path.resolve(strict=True).relative_to(root)
    return path


@contextmanager
def open_config(project, relative, write=False):
    """Anchor every path component to an open directory; never follow symlinks."""
    checked_path(project, relative)
    directory = os.open(Path(project).resolve(), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(relative).parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(Path(relative).name, (os.O_RDWR if write else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "r+b" if write else "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 256 * 1024:
                raise CheckError("Config must remain a small regular file with no hard links.")
            yield handle
    finally:
        os.close(directory)


def safe_config_text(raw):
    text = raw.decode("utf-8")
    sensitive_setting = re.search(r'''(?i)\b(?:password|token|secret|api[_-]?key|authorization)["']?\s*[:=]''', text)
    if secrets(text, "/") or redact(text) != text or sensitive_setting or "\x00" in text:
        raise CheckError("Config may contain sensitive values; no diff was saved or displayed. Ask a developer to prepare a sanitized change.")
    return text


def header_change(name, text, code="referrer"):
    if code not in HEADER_RECIPES:
        raise CheckError("Unsupported header recipe; no edit was made.")
    header, value = HEADER_RECIPES[code]
    pattern = r"[-_]?".join(header.split("-"))
    if re.search(pattern, text, re.I):
        raise CheckError("An existing target header needs review; automatic replacement is refused.")
    if name == "_headers":
        lines = text.splitlines(keepends=True)
        blocks = [i for i, line in enumerate(lines) if line.rstrip() == "/*"]
        if len(blocks) > 1:
            raise CheckError("Multiple wildcard header blocks need developer review.")
        newline = "\r\n" if "\r\n" in text else "\n"
        addition = "  " + header + ": " + value + newline
        if blocks:
            index = blocks[0]
            if not lines[index].endswith("\n"):
                lines[index] += newline
            lines.insert(index + 1, addition)
            return "".join(lines)
        separator = "" if not text or text.endswith(newline * 2) else newline if text.endswith(newline) else newline * 2
        return text + separator + "/*" + newline + addition
    if name == ".htaccess":
        return text.rstrip() + '\n\n<IfModule mod_headers.c>\n  Header always set ' + header + ' "' + value + '"\n</IfModule>\n'
    if name == "netlify.toml":
        if '"""' in text or "'''" in text or "\\" in text:
            raise CheckError("Complex TOML needs a developer-reviewed edit.")
        return text.rstrip() + '\n\n[[headers]]\n  for = "/*"\n  [headers.values]\n    ' + header + ' = "' + value + '"\n'
    if name == "vercel.json":
        def unique_object(pairs):
            if len(dict(pairs)) != len(pairs):
                raise CheckError("Duplicate JSON keys need developer review.")
            return dict(pairs)
        data = json.loads(text, object_pairs_hook=unique_object)
        if re.search(pattern, json.dumps(data), re.I):
            raise CheckError("An existing target header needs review; automatic replacement is refused.")
        if not isinstance(data, dict) or not isinstance(data.get("headers", []), list) or "routes" in data:
            raise CheckError("Custom Vercel routing needs developer review.")
        data.setdefault("headers", []).append({"source": "/(.*)", "headers": [{"key": header, "value": value}]})
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if name in {"next.config.js", "next.config.mjs", "next.config.ts"}:
        # Support only a literal, simple export; never evaluate or run project JS.
        pattern = r'''\A(?P<prefix>\s*(?:import\s+type\s*\{\s*NextConfig\s*\}\s*from\s*["']next["'];?\s*)?(?:module\.exports\s*=|export\s+default|const\s+nextConfig(?:\s*:\s*NextConfig)?\s*=)\s*\{)(?P<body>[^{}]*)(?P<tail>\}\s*;?\s*(?:export\s+default\s+nextConfig\s*;?\s*)?)\Z'''
        match = re.fullmatch(pattern, text)
        prop = r'''\w+\s*:\s*(?:true|false|\d+|"[^"\\\r\n]*"|'[^'\\\r\n]*')'''
        scalar = r"\s*(?:" + prop + r"(?:\s*,\s*" + prop + r")*\s*,?\s*)?"
        if not match or not re.fullmatch(scalar, match["body"]) or ("const nextConfig" in match["prefix"] and "export" not in match["tail"]):
            raise CheckError("Complex Next.js config needs a developer-reviewed edit.")
        addition = '\n  async headers() {\n    return [{ source: "/(.*)", headers: [{ key: "' + header + '", value: "' + value + '" }] }];\n  },\n'
        return match["prefix"] + addition + match["body"] + match["tail"]
    raise CheckError("Unsupported config; no edit was made.")


def plan_hash(plan):
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def prepare_plan(evidence, review, finding_id, project, relative, opt_in, access_impact="unknown", mime_types_correct="unknown"):
    require_opt_in(opt_in)
    data, row = accepted_item(evidence, review, finding_id)
    row = require_safe_item(row, mime_types_correct=mime_types_correct)
    if row["code"] not in HEADER_RECIPES:
        raise CheckError("This item is a read-only verification, not an approved code-edit recipe.")
    require_safe_access(access_impact)
    path = checked_path(project, relative)
    with open_config(project, relative) as handle:
        before = handle.read(256 * 1024 + 1)
    if len(before) > 256 * 1024:
        raise CheckError("Config grew beyond the size limit.")
    text = safe_config_text(before)
    after = header_change(path.name, text, row["code"])
    header, value = HEADER_RECIPES[row["code"]]
    test_steps = TEST_STEPS.format(header=header, value=value)
    if row["code"] == "nosniff":
        test_steps += " Verify each script/style asset's Content-Type in the owner's local tests and confirm no MIME-blocking errors. A page's Content-Type alone does not establish asset MIME types."
    plan = {"schema_version": 1, "finding_id": finding_id, "check": row["code"],
            "project": str(Path(project).resolve()), "file": relative, "access_impact": access_impact,
            "mime_types_correct": mime_types_correct, "effort_tag": row["effort_tag"], "effort_reason": row["effort_reason"],
            "evidence_sha256": evidence_hash(Path(evidence).read_bytes()),
            "review_sha256": evidence_hash(Path(review).read_bytes()),
            "before_sha256": evidence_hash(before), "after_sha256": evidence_hash(after.encode()),
            "diff": "".join(difflib.unified_diff(text.splitlines(True), after.splitlines(True), fromfile=relative, tofile=relative)),
            "how_to_test": test_steps, "how_to_publish": PUBLISH_STEPS}
    return {"plan": plan, "sha256": plan_hash(plan)}


def apply_plan(envelope, evidence, review, project, approval, confirmed_plan):
    require_opt_in(approval)
    plan = envelope["plan"]
    if plan_hash(plan) != confirmed_plan or envelope["sha256"] != confirmed_plan:
        raise CheckError("Approval does not match the exact displayed plan.")
    _, row = accepted_item(evidence, review, plan["finding_id"])
    require_safe_item(row, mime_types_correct=plan.get("mime_types_correct", "unknown"))
    require_safe_access(plan.get("access_impact"))
    if row["code"] not in HEADER_RECIPES or plan["check"] != row["code"] or plan["project"] != str(Path(project).resolve()):
        raise CheckError("The approved item or project changed; prepare a new plan.")
    if plan["evidence_sha256"] != evidence_hash(Path(evidence).read_bytes()) or plan["review_sha256"] != evidence_hash(Path(review).read_bytes()):
        raise CheckError("Evidence or review changed; prepare a new plan.")
    path = checked_path(project, plan["file"])
    # Open only the checked file; no patch execution, shell, package hooks or new paths.
    with open_config(project, plan["file"], write=True) as handle:
        before = handle.read(256 * 1024 + 1)
        if evidence_hash(before) != plan["before_sha256"]:
            raise CheckError("Config changed since the diff; no edit was made. Prepare a new plan.")
        text = safe_config_text(before)
        after = header_change(path.name, text, row["code"])
        diff = "".join(difflib.unified_diff(text.splitlines(True), after.splitlines(True), fromfile=plan["file"], tofile=plan["file"]))
        if evidence_hash(after.encode()) != plan["after_sha256"] or diff != plan["diff"]:
            raise CheckError("The displayed diff does not match the supported change.")
        handle.seek(0)
        handle.write(after.encode())
        handle.truncate()
    return {"finding_id": plan["finding_id"], "file": plan["file"], "status": "local edit applied", "next": PUBLISH_STEPS}


def settings_steps(row, host, provider, confirmed_provider, dns_value=None, access_impact="unknown"):
    """Return instructions only. Provider and mail values must come from the owner."""
    host = urlsplit(normalize_url(host)).hostname
    if confirmed_provider != "yes":
        raise CheckError("Confirm the actual dashboard/provider with the owner first; a public header hint is insufficient.")
    code = row["code"]
    if code in ("mail-spf", "mail-dmarc"):
        if not dns_value or len(dns_value) > 1000 or any(ord(c) < 32 for c in dns_value) or redact(dns_value) != dns_value:
            raise CheckError("Ask the owner for the exact provider-approved DNS value and existing sender/record inventory; do not guess.")
        prefix = "v=spf1" if code == "mail-spf" else "v=DMARC1;"
        if not dns_value.startswith(prefix):
            raise CheckError("The supplied DNS value does not match this policy type.")
        name = host if code == "mail-spf" else "_dmarc." + host
        return {"status": "Needs a developer", "reason": risk_reason(code),
                "record": {"type": "TXT", "name": name, "value": dns_value, "TTL": "provider default"},
                "steps": ["Owner/developer: open the domain's DNS dashboard, select its DNS records, and review every existing SPF/DMARC record and sender.",
                          "Use the supplied exact TXT name/value only after developer approval; edit/consolidate an existing policy instead of adding a duplicate.",
                          "The owner saves the reviewed record and waits for propagation; no record is written by this plugin."],
                "review": FREE_REVIEW + ": " + CALL}
    require_safe_item(row)
    if code == "referrer":
        require_safe_access(access_impact)
    if code == "referrer" and provider == "Cloudflare":
        return {"status": "manual owner action only", "steps": [
            "Open Cloudflare dashboard and select the confirmed domain containing " + host + ".",
            "Open Rules → Overview → Create rule → Response Header Transform Rule.",
            "Name the rule Referrer policy. Select a custom filter: Hostname equals " + host + ".",
            "Choose Set static, header Referrer-Policy, value strict-origin-when-cross-origin.",
            "Review existing header rules, rule order and matching scope. Stop for developer review if an existing referrer policy or authentication dependency would be affected.",
            "The owner alone selects Deploy to activate the reviewed rule, or Save as Draft to leave it inactive. This plugin never performs that action.",
            "After the owner confirms it is live, run the single-finding re-check; no DNS, login or API write is performed here."]}
    if code == "referrer" and provider in ("Vercel", "Netlify"):
        return {"status": "local configuration required", "steps": [
            "Open the confirmed " + provider + " project and verify its linked source and configured root/build output.",
            "Use the guided code plan for the active vercel.json/next.config file on Vercel, or netlify.toml/_headers on Netlify.",
            "Review the exact diff and tests before approving a local edit. The owner publishes through the existing project workflow."]}
    if code == "public-key":
        return {"status": "read-only verification", "steps": [
            "Confirm with the project owner that this is intended public client configuration; use only the reported key type, never its value.",
            "Any Row Level Security, Security Rules, key rotation or auth change becomes Needs a developer. No permission change is part of this item.",
            "Re-checking key presence cannot verify backend permissions."]}
    raise CheckError("Exact settings are not established; ask the owner/developer. No setting was changed.")
