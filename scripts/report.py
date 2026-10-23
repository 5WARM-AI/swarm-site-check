"""Local report rendering. A complete evidence-bound review is mandatory."""
import hashlib
import html
import json
import string
from pathlib import Path

from checks import RANK
from network import CheckError
from parsers import redact
from guidance import CALL, FREE_REVIEW, GUIDED_OFFER, with_guidance


def evidence_hash(raw):
    return hashlib.sha256(raw).hexdigest()


def markdown_cell(value):
    """Keep untrusted cell content literal in Markdown, GFM tables and HTML.

    Encode punctuation as character references, including input ampersands, so
    links, code spans, raw HTML and pre-encoded markup cannot become syntax.
    Flatten whitespace/control characters to prevent extra rows or blocks.
    """
    text = " ".join("".join(" " if ord(char) < 32 or ord(char) == 127 else char
                            for char in str(value)).split())
    return "".join("&#%d;" % ord(char) if char in string.punctuation else char for char in text)


def reviewed_findings(data, review, digest):
    if review.get("evidence_sha256") != digest or not review.get("reviewer"):
        raise CheckError("Review must identify its reviewer and the exact evidence SHA-256.")
    candidates = {x["id"]: x for x in data["candidates"]}
    facts = {x["id"]: x for x in data["facts"]}
    seen, kept, dropped = set(), [], 0
    for decision in review.get("decisions", []):
        fid = decision.get("id")
        if fid not in candidates or fid in seen or not decision.get("reason"):
            raise CheckError("Review has unknown/duplicate findings or a missing reason.")
        seen.add(fid)
        original = candidates[fid]
        if decision.get("verdict") == "drop":
            dropped += 1
            continue
        severity = decision.get("severity")
        refs = decision.get("evidence", [])
        if decision.get("verdict") != "keep" or severity not in RANK or RANK[severity] < RANK[original["severity"]]:
            raise CheckError("Review must keep, drop, or lower a severity; it cannot escalate or add findings.")
        if not refs or refs != original["evidence"] or any(x not in facts for x in refs):
            raise CheckError("Each kept finding needs its original, valid evidence citations.")
        kept.append(dict(original, severity=severity, review_reason=redact(decision["reason"])))
    if seen != set(candidates):
        raise CheckError("Independent review is incomplete; no final report was generated.")
    return sorted(kept, key=lambda x: (RANK[x["severity"]], x["site"], x["code"], x["id"])), dropped


def render(evidence_path, review_path, output):
    raw = Path(evidence_path).read_bytes()
    data, review = json.loads(raw), json.loads(Path(review_path).read_text())
    findings, dropped = reviewed_findings(data, review, evidence_hash(raw))
    findings = [with_guidance(row, row.get("platforms", [])) for row in findings]
    facts = {x["id"]: x for x in data["facts"]}
    esc = lambda x: html.escape(str(x), quote=True)
    counts = {s: sum(x["severity"] == s for x in findings) for s in RANK}
    cards = "".join('<div class="stat"><strong>' + str(counts[s]) + '</strong><span>' + s + '</span></div>' for s in RANK)
    rows = []
    for row in findings:
        evidence = "<br>".join('<code>' + esc(fid) + ' · ' + esc(facts[fid]["source"]) + '<br>' + esc(facts[fid]["line"]) + '</code>' for fid in row["evidence"])
        effort = '<strong class="effort">' + esc(row["effort_tag"]) + '</strong><br>' + esc(row["effort_reason"])
        booking = '<p class="booking">Want Swarm to fix this? Book a call: <a href="' + CALL + '">' + CALL + '</a></p>' if row["booking_line"] else ''
        prompt = '<details class="fix-prompt"><summary>Fix prompt</summary><pre>' + esc(row["fix_prompt"]) + '</pre></details>' if row["fix_prompt"] else ''
        risk = '<p>' + esc(row["risk_review_line"]) + '</p>' if row["risk_review_line"] else ''
        rows.append('<tr><td><span class="badge ' + row["severity"].lower() + '">' + row["severity"] + '</span></td><td>' + esc(row["site"]) + '</td><td><strong>' + esc(row["finding"]) + '</strong></td><td>' + evidence + '</td><td>' + esc(row["fix"]) + prompt + '</td><td>' + esc(row["owner"]) + '<p>' + effort + '</p>' + risk + booking + '</td></tr>')
    coverage = "".join('<li><b>' + esc(x["site"]) + ' · ' + esc(x["check"]) + '</b>: ' + esc(x["status"]) + '</li>' for x in data["coverage"])
    doc = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="color-scheme" content="light"><title>Swarm Site Check</title>
<style>
:root{color-scheme:light;--violet:#5B4BD6;--ink:#25213c;--muted:#676277;--line:#e9e5f1}*{box-sizing:border-box}
body{margin:0;background:#fff;color:var(--ink);font:15px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1520px;margin:auto;padding:48px 40px}header{border-top:5px solid var(--violet);padding-top:26px;display:flex;justify-content:space-between;gap:32px}
.brand{color:var(--violet);font-size:20px;font-weight:800;letter-spacing:.12em}.eyebrow{text-transform:uppercase;letter-spacing:.13em;font-size:12px;color:var(--muted)}
h1{font-size:44px;line-height:1.1;letter-spacing:-.04em;margin:15px 0}h2{font-size:23px;margin:34px 0 14px}p{max-width:900px;color:var(--muted)}
.stamp{max-width:330px;font-size:13px;color:var(--muted);text-align:right}.stats{display:grid;grid-template-columns:repeat(5,1fr);border:1px solid var(--line);border-radius:14px;margin-top:30px;overflow:hidden}
.stat{padding:20px 25px;border-right:1px solid var(--line)}.stat:last-child{border:0}.stat strong{display:block;font-size:30px;color:var(--violet)}.stat span{color:var(--muted);font-size:13px}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;background:#f6f4fc;font-weight:650;padding:15px;color:#4e426d}td{padding:18px 15px;border-top:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}td:nth-child(2){min-width:135px}td:nth-child(3){min-width:170px}td:nth-child(4){min-width:240px;max-width:360px}td:nth-child(5){min-width:240px;max-width:380px}td:last-child{min-width:130px}
code{font:11px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;color:#555066}.badge{white-space:nowrap;display:inline-block;padding:4px 9px;border-radius:6px;font-size:11px;font-weight:750;background:#efedf9;color:var(--violet)}.critical,.high{background:#fce8eb;color:#a82139}.medium{background:#fff0d9;color:#865700}.low{background:#eeeafa;color:#5b4bd6}.info{background:#f0f1f4;color:#59606e}
details{margin:24px 0;padding:18px 22px;background:#faf9fc;border-radius:12px}summary{cursor:pointer;font-weight:600}li{margin:10px 0;font-size:13px}footer{border-top:1px solid var(--line);padding-top:24px;margin-top:40px;font-size:13px;color:var(--muted)}a,.effort{color:var(--violet)}a{overflow-wrap:anywhere}.booking{font-size:12px}.review-invite{padding:18px;background:#f6f4fc;border-radius:8px;font-weight:600}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace}.fix-prompt{padding:12px;margin:12px 0}
@media(max-width:700px){main{padding:24px 18px}header,footer{display:block}.stamp{text-align:left}.stats{grid-template-columns:repeat(5,1fr)}.stat{padding:12px 7px}.stat strong{font-size:23px}h1{font-size:34px}}@media print{main{padding:10px}details{display:block}tr{break-inside:avoid}}
</style></head><body><main>'''
    introduction = data.get("notice") or "A ranked fix list from public evidence. Each finding below survived an independent evidence review."
    doc += '<header><div><div class="brand">5WARM</div><div class="eyebrow">Website hygiene · passive review</div><h1>Swarm Site Check</h1><p>' + esc(introduction) + '</p></div><div class="stamp">' + esc(data["created_at"]) + '<br>' + str(len(data["scope"]["sites"])) + ' scoped pages<br>Review: ' + esc(redact(review["reviewer"])) + '<br>' + str(dropped) + ' candidates dropped</div></header>'
    doc += '<div class="stats">' + cards + '</div><h2>Your ranked fix list</h2><div class="table-wrap"><table><thead><tr><th>Priority</th><th>Site</th><th>Finding</th><th>Evidence</th><th>Fix</th><th>Who does it</th></tr></thead><tbody>' + ("".join(rows) or '<tr><td colspan="6">No findings survived review. Read the coverage limits before drawing conclusions.</td></tr>') + '</tbody></table></div>'
    doc += '<details><summary>Coverage and limits (' + str(len(data["coverage"])) + ')</summary><ul>' + coverage + '</ul></details><p>One listed HTTPS page per scope entry, one plain-HTTP root request per host, two old-TLS probes, and two shared asset requests per host: bundle GETs or source-map HEADs from explicit bundle directives. Redirects are recorded. No logins, guessed paths, credential use, backend queries, or site changes. Public metadata can be stale; a package advisory match does not prove exploitability. Empty results do not prove a site is secure.</p>'
    doc += '<p>' + esc(GUIDED_OFFER) + ' Reply yes in Claude Code to opt in. Each eligible local edit needs a separate yes after its exact diff and tests. You publish changes yourself; only the selected check/host is re-checked. Developer-only items are never auto-fixed.</p>'
    doc += '<footer><div>Want Swarm to do the fixes? Book a call: <a href="' + CALL + '">' + CALL + '</a></div><div>Made by Swarm · <a href="https://5warm.ai">5warm.ai</a></div><p>Sharing is opt-in. This plugin never uploads or emails your report; you choose whether to bring it.</p><div class="review-invite">' + FREE_REVIEW + ': <a href="' + CALL + '">' + CALL + '</a></div></footer></main></body></html>\n'
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.html").write_text(doc, encoding="utf-8")
    summary = ["# Swarm Site Check", "", " · ".join(str(counts[s]) + " " + s for s in RANK), "",
               "| Priority | Site | Finding | Fix | Who | Effort and reason |", "|---|---|---|---|---|---|"]
    for row in findings[:12]:
        values = [markdown_cell(row[k]) for k in ("severity", "site", "finding", "fix", "owner")]
        effort = markdown_cell(row["effort_tag"] + ": " + row["effort_reason"] + (" " + row["risk_review_line"] if row["risk_review_line"] else ""))
        # The booking line is a fixed local constant, appended after untrusted text.
        values.append(effort + (" " + row["booking_line"] if row["booking_line"] else ""))
        summary.append("| " + " | ".join(values) + " |")
    summary += ["", "Full evidence and coverage limits: report.html. Review dropped %d candidates." % dropped,
                "Copyable Fix prompt blocks: report.html and fix-prompts.md. Local filenames must be located in your open project before an edit.",
                "", GUIDED_OFFER, "Each local edit needs a separate yes to its exact diff and tests. You publish changes yourself. Developer-only items are never auto-fixed.",
                "", "Want Swarm to do the fixes? Book a call: " + CALL, "", "Made by Swarm · 5warm.ai", "",
                "Sharing is opt-in. Nothing is uploaded or emailed; you choose whether to bring the report.", "", FREE_REVIEW + ": " + CALL, ""]
    (output / "summary.md").write_text("\n".join(summary), encoding="utf-8")
    prompts = ["# Fix prompts", "", "Local file locations must be confirmed in your open project. Developer-only items remain plans for a developer.", ""]
    for row in findings:
        if row["fix_prompt"]:
            prompts += ["## " + markdown_cell(row["id"] + " · " + row["site"]), "", "```text", row["fix_prompt"], "```", ""]
    (output / "fix-prompts.md").write_text("\n".join(prompts), encoding="utf-8")
    return len(findings), dropped
