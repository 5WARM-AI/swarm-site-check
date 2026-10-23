#!/usr/bin/env python3
"""Build the documentation example from a real example.com run and synthetic fixtures.

No network requests; no production review shortcut. Output is explicitly a documentation
demonstration with a manual, fixture-specific review, not a Claude review.
"""
import argparse
import json
from pathlib import Path

from checks import Evidence, check_headers
from network import CheckError
from parsers import header_facts
from report import evidence_hash, render
from site_check import write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.example_evidence.read_text())
    if data["scope"]["sites"] != ["https://example.com/"]:
        raise CheckError("Documentation examples accept only example.com live evidence.")
    fixture = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    ev = Evidence()
    ev.facts, ev.candidates = data["facts"], data["candidates"]
    response = header_facts(json.loads((fixture / "headers.json").read_text()))
    response.update(status=200, url="https://synthetic.example.com/")
    check_headers(ev, "synthetic.example.com (synthetic)", response)
    ev.inspect_content("synthetic.example.com (synthetic)", "https://synthetic.example.com/", (fixture / "vibe-page.html").read_text(), True)
    ev.inspect_content("synthetic.example.com (synthetic)", "https://synthetic.example.com/vibe-bundle.js", (fixture / "vibe-bundle.js").read_text(), False)
    data.update(facts=ev.facts, candidates=ev.candidates)
    data["scope"]["sites"].append("https://synthetic.example.com/ (offline synthetic fixture)")
    data["notice"] = "Documentation example: a live example.com check plus an offline synthetic fixture. Fixture findings are illustrative. This example uses a manual fixture review."
    decisions = []
    # These reviewed, fixed fixture categories illustrate evidence without presenting
    # deliberately fake keys, known framework strings or invented CVEs as real risks.
    for finding in ev.candidates:
        keep = finding["code"] in ("cookie", "hsts", "csp", "frame", "referrer", "public-key", "supabase-rls", "firebase-rules", "client-gate")
        decisions.append({"id": finding["id"], "verdict": "keep" if keep else "drop",
                          "severity": finding["severity"], "evidence": finding["evidence"],
                          "reason": "Manually reviewed documentation example: concrete header or type/length evidence supports cautious wording." if keep else "Omitted from this illustrative example; synthetic secrets and versions are deliberately non-production."})
    args.output.mkdir(parents=True, exist_ok=True)
    evidence = args.output / "example-evidence.json"
    write_json(evidence, data)
    review = args.output / "example-review.json"
    write_json(review, {"evidence_sha256": evidence_hash(evidence.read_bytes()), "reviewer": "Manual documentation fixture review", "decisions": decisions})
    render(evidence, review, args.output)
    print("Documentation example rendered from example.com + synthetic fixture.")


if __name__ == "__main__":
    main()
