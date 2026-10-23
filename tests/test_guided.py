"""Offline approval, risk, single-host and local-project regression tests."""
import ast
import copy
import hashlib
import io
import json
import re
import shlex
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from contextlib import redirect_stdout

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from checks import Evidence, check_headers
from guidance import CALL, FREE_REVIEW, GUIDED_OFFER, effort_for, fix_prompt, risk_reason, with_guidance
from guided import (CONFIG_NAMES, HEADER, HEADER_RECIPES, VALUE, apply_plan, header_change, locate_configs,
                    plan_hash, prepare_plan, settings_steps)
from network import CheckError, OWNERSHIP, normalize_url, scope_digest, service_json
from parsers import header_facts
from recheck import recheck
from report import evidence_hash, render
from site_check import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / "fixtures" / "header-project"


def save_review(root, code="referrer", url="https://example.com/"):
    scope = {"sites": sorted([url, "https://second.example.com/"])}
    scope["sha256"] = scope_digest(scope["sites"])
    ev = Evidence()
    site = url.removeprefix("https://").rstrip("/")
    if code in ("referrer", "nosniff"):
        response = header_facts([("Content-Type", "text/html")])
        response.update(url=url, status=200)
        check_headers(ev, site, response, only=code)
    else:
        ref = ev.fact(site, url, "synthetic evidence for " + code)
        ev.finding(site, code, "Low", "Synthetic " + code, [ref], "Review.")
    data = {"scope": scope, "facts": ev.facts, "candidates": ev.candidates, "coverage": [], "created_at": "synthetic"}
    raw = json.dumps(data).encode()
    evidence, review = root / "evidence.json", root / "review.json"
    evidence.write_bytes(raw)
    review.write_text(json.dumps({"reviewer": "synthetic test reviewer", "evidence_sha256": evidence_hash(raw),
        "decisions": [{"id": row["id"], "verdict": "keep", "severity": row["severity"], "evidence": row["evidence"], "reason": "Synthetic evidence for test."} for row in ev.candidates]}))
    return evidence, review, data, ev.candidates[0]


class GuidedRiskTests(unittest.TestCase):
    def test_risky_items_cannot_become_diy_or_auto_fixed(self):
        for code in ("supabase-rls", "firebase-rules", "client-gate", "secret", "osv", "version", "auth-change", "server-upgrade", "cookie", "hsts", "csp", "frame", "nosniff", "old-tls", "public-ui", "mail-spf", "mail-dmarc", "unknown"):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                project = root / "project"
                shutil.copytree(FIXTURE, project)
                evidence, review, _, row = save_review(root, code)
                self.assertEqual("Needs a developer", effort_for(code)[0])
                self.assertTrue(risk_reason(code))
                self.assertFalse(row["guided_eligible"])
                self.assertIn(FREE_REVIEW, row["risk_review_line"])
                self.assertIn(CALL, row["risk_review_line"])
                before = (project / "public/_headers").read_bytes()
                with self.assertRaises(CheckError):
                    prepare_plan(evidence, review, row["id"], project, "public/_headers", "yes")
                self.assertEqual(before, (project / "public/_headers").read_bytes())

    def test_referrer_is_diy_public_key_is_verification_only(self):
        self.assertTrue(effort_for("referrer")[0].startswith("Fix it yourself"))
        self.assertFalse(risk_reason("referrer"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, review, _, row = save_review(root, "public-key")
            with self.assertRaisesRegex(CheckError, "read-only verification"):
                prepare_plan(evidence, review, row["id"], root, "_headers", "yes")

    def test_nosniff_offered_only_after_explicit_mime_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, review, _, row = save_review(root, "nosniff")
            for answer in ("unknown", "no", "", "YES", True):
                with self.subTest(answer=answer):
                    guided = with_guidance(dict(row, mime_types_correct="yes", guided_eligible=True), mime_types_correct=answer)
                    self.assertEqual("Needs a developer", guided["effort_tag"])
                    self.assertFalse(guided["guided_eligible"])
                    self.assertTrue(risk_reason("nosniff", mime_types_correct=answer))
                    with self.assertRaises(CheckError):
                        prepare_plan(evidence, review, row["id"], root, "_headers", "yes", "none", answer)
            guided = with_guidance(row, mime_types_correct="yes")
            self.assertEqual("Fix it yourself (~30 min)", guided["effort_tag"])
            self.assertTrue(guided["guided_eligible"])
            self.assertFalse(guided["risk_reason"])
            self.assertFalse(risk_reason("nosniff", mime_types_correct="yes"))
            self.assertTrue(risk_reason("cookie", mime_types_correct="yes"))
            self.assertFalse(with_guidance(guided)["guided_eligible"])  # Evidence cannot grant confirmation.


class GuidedPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        shutil.copytree(FIXTURE, self.project)
        self.path = self.project / "public/_headers"
        self.evidence, self.review, self.data, self.row = save_review(self.root)

    def plan(self):
        return prepare_plan(self.evidence, self.review, self.row["id"], self.project, "public/_headers", "yes", "none")

    def apply(self, envelope, answer="yes", digest=None):
        return apply_plan(envelope, self.evidence, self.review, self.project, answer, digest or envelope["sha256"])

    def test_locate_and_plan_wait_for_opt_in(self):
        for answer in ("", "no", "YES"):
            with self.assertRaises(CheckError):
                locate_configs(self.project, answer)
            with self.assertRaises(CheckError):
                prepare_plan(self.evidence, self.review, self.row["id"], self.project, "public/_headers", answer)
        self.assertEqual(["public/_headers"], locate_configs(self.project, "yes"))
        before = self.path.read_bytes()
        envelope = self.plan()
        self.assertEqual(before, self.path.read_bytes())
        self.assertIn("+  Referrer-Policy: " + VALUE, envelope["plan"]["diff"])
        self.assertIn("public/_headers", envelope["plan"]["diff"])
        self.assertIn("How", "How to test: " + envelope["plan"]["how_to_test"])
        self.assertIn("deploy, then re-check", envelope["plan"]["how_to_publish"])

    def test_each_item_needs_yes_to_exact_diff(self):
        envelope = self.plan()
        before = self.path.read_bytes()
        for answer, digest in (("no", envelope["sha256"]), ("", envelope["sha256"]), ("yes", "wrong")):
            with self.assertRaises(CheckError):
                self.apply(envelope, answer, digest)
            self.assertEqual(before, self.path.read_bytes())
        result = self.apply(envelope)
        self.assertEqual("local edit applied", result["status"])
        with self.assertRaises(CheckError):
            self.apply(envelope)  # One approval cannot silently apply again.

    def test_unknown_or_possible_access_impact_blocks_local_and_settings_fixes(self):
        for impact in ("unknown", "possible", ""):
            with self.subTest(impact=impact):
                with self.assertRaisesRegex(CheckError, "authentication"):
                    prepare_plan(self.evidence, self.review, self.row["id"], self.project, "public/_headers", "yes", impact)
                with self.assertRaisesRegex(CheckError, "authentication"):
                    settings_steps(self.row, "example.com", "Cloudflare", "yes", access_impact=impact)
        self.assertNotIn(HEADER, self.path.read_text())

    def test_changed_file_plan_or_review_invalidates_approval(self):
        envelope = self.plan()
        before = self.path.read_bytes()
        tampered = copy.deepcopy(envelope)
        tampered["plan"]["diff"] += "synthetic tampering"
        with self.assertRaises(CheckError):
            self.apply(tampered)
        tampered["sha256"] = plan_hash(tampered["plan"])
        with self.assertRaises(CheckError):
            self.apply(tampered)  # Even a new hash cannot authorize arbitrary patch text.
        self.path.write_bytes(before + b"\n# concurrent edit\n")
        with self.assertRaises(CheckError):
            self.apply(envelope)
        self.path.write_bytes(before)
        self.review.write_text(self.review.read_text() + "\n")
        with self.assertRaises(CheckError):
            self.apply(envelope)
        self.assertEqual(before, self.path.read_bytes())

    def test_paths_symlinks_sensitive_files_and_existing_policy_refused(self):
        for name in ("../outside/_headers", "/tmp/_headers", "public/.env"):
            with self.assertRaises(CheckError):
                prepare_plan(self.evidence, self.review, self.row["id"], self.project, name, "yes", "none")
        outside = self.root / "_headers"
        outside.write_text("/*\n")
        self.path.unlink()
        self.path.symlink_to(outside)
        with self.assertRaises(CheckError):
            self.plan()
        self.path.unlink()
        secret = "sk_test_" + "x" * 24
        self.path.write_text("/*\n# " + secret)
        with self.assertRaises(CheckError) as error:
            self.plan()
        self.assertNotIn(secret, str(error.exception))
        self.path.write_text("/*\n  Referrer-Policy: no-referrer\n")
        with self.assertRaises(CheckError):
            self.plan()
        secret = "synthetic-value-with-no-key-prefix"
        self.path.write_text('{"password": "' + secret + '"}')
        with self.assertRaises(CheckError) as error:
            self.plan()
        self.assertNotIn(secret, str(error.exception))

    def test_supported_header_config_recipes_and_complex_refusal(self):
        bodies = {"_headers": "/*\n", ".htaccess": "# Synthetic Apache config\n", "netlify.toml": '[build]\npublish = "public"\n',
                  "vercel.json": '{"version":2}', "next.config.js": 'module.exports = {reactStrictMode: true};',
                  "next.config.mjs": 'const nextConfig = {};\nexport default nextConfig;',
                  "next.config.ts": 'import type { NextConfig } from "next";\nconst nextConfig: NextConfig = {};\nexport default nextConfig;'}
        self.assertEqual(CONFIG_NAMES, set(bodies))
        for name, body in bodies.items():
            with self.subTest(name=name):
                after = header_change(name, body)
                self.assertIn(HEADER, after)
                self.assertIn(VALUE, after)
        self.assertEqual("/(.*)", json.loads(header_change("vercel.json", "{}"))["headers"][0]["source"])
        for body in ('module.exports = plugin({});', 'export default {...base};', 'module.exports = {async headers() { return []; }};', 'module.exports = { a: true b: false };'):
            with self.assertRaises(CheckError):
                header_change("next.config.js", body)
        with self.assertRaises(CheckError):
            header_change("vercel.json", '{"version": 1, "version": 2}')
        with self.assertRaises(CheckError):
            header_change("vercel.json", r'{"headers":[{"source":"/(.*)","headers":[{"key":"\u0052eferrer-Policy","value":"no-referrer"}]}]}')

    def test_headers_merge_existing_wildcard_without_duplicate(self):
        for code, (header, value) in HEADER_RECIPES.items():
            for newline in ("\n", "\r\n"):
                with self.subTest(code=code, newline=repr(newline)):
                    before = newline.join(["# Synthetic config", "/assets/*", "  Cache-Control: max-age=60", "", "/*", "  Content-Language: en", "", "/private/*", "  Cache-Control: no-store", ""])
                    after = header_change("_headers", before, code)
                    self.assertEqual(before.replace("/*" + newline + "  Content-Language", "/*" + newline + "  " + header + ": " + value + newline + "  Content-Language"), after)
                    self.assertEqual(1, after.splitlines().count("/*"))
                    self.assertEqual("/*" + newline + "  " + header + ": " + value + newline,
                                     header_change("_headers", "/*", code).replace("\n", newline))
        with self.assertRaises(CheckError):
            header_change("_headers", "/*\n  Content-Language: en\n/*\n")

    def test_headers_append_wildcard_only_when_absent(self):
        for code, (header, value) in HEADER_RECIPES.items():
            for before in ("", "# Synthetic config\n", "/assets/*\n  Cache-Control: max-age=60\n"):
                with self.subTest(code=code, before=before):
                    after = header_change("_headers", before, code)
                    self.assertTrue(after.startswith(before))
                    self.assertTrue(after.endswith("/*\n  " + header + ": " + value + "\n"))
                    self.assertEqual(1, after.splitlines().count("/*"))

    def test_nosniff_all_formats_refuse_present_header(self):
        bodies = {"_headers": "/*\n  Content-Language: en\n", ".htaccess": "# Synthetic Apache config\n",
                  "netlify.toml": '[build]\npublish = "public"\n', "vercel.json": '{"version":2}',
                  "next.config.js": 'module.exports = {reactStrictMode: true};',
                  "next.config.mjs": 'const nextConfig = {};\nexport default nextConfig;',
                  "next.config.ts": 'import type { NextConfig } from "next";\nconst nextConfig: NextConfig = {};\nexport default nextConfig;'}
        self.assertEqual(CONFIG_NAMES, set(bodies))
        for name, before in bodies.items():
            with self.subTest(name=name):
                after = header_change(name, before, "nosniff")
                self.assertIn("X-Content-Type-Options", after)
                self.assertIn("nosniff", after)
                for existing in (after, after.replace("X-Content-Type-Options", "x-content-type-options").replace("nosniff", "invalid")):
                    with self.assertRaisesRegex(CheckError, "existing target header"):
                        header_change(name, existing, "nosniff")
        with self.assertRaisesRegex(CheckError, "existing target header"):
            header_change("vercel.json", r'{"headers":[{"source":"/(.*)","headers":[{"key":"\u0058-Content-Type-Options","value":"nosniff"}]}]}', "nosniff")

    def test_nosniff_approved_plan_merges_and_recheck_flips(self):
        self.evidence, self.review, self.data, self.row = save_review(self.root, "nosniff")
        self.path.write_text("/*\n  Referrer-Policy: strict-origin-when-cross-origin\n")
        before_file = self.path.read_bytes()
        common = ["--evidence", str(self.evidence), "--review", str(self.review), "--finding", self.row["id"],
                  "--project", str(self.project), "--file", "public/_headers", "--opt-in", "yes", "--access-impact", "none",
                  "--out", str(self.root / "nosniff-plan.json")]
        with self.assertRaises(CheckError), redirect_stdout(io.StringIO()) as refused:
            main(["guide-plan", *common])
        self.assertNotIn("Fix it yourself", refused.getvalue())
        self.assertFalse((self.root / "nosniff-plan.json").exists())
        with redirect_stdout(io.StringIO()) as offered:
            main(["guide-plan", *common, "--mime-types-correct", "yes"])
        envelope = json.loads((self.root / "nosniff-plan.json").read_text())
        self.assertEqual("yes", envelope["plan"]["mime_types_correct"])
        self.assertIn("Fix it yourself", offered.getvalue())
        self.assertIn("X-Content-Type-Options: nosniff", envelope["plan"]["how_to_test"])
        self.assertEqual(before_file, self.path.read_bytes())
        with self.assertRaises(CheckError):
            prepare_plan(self.evidence, self.review, self.row["id"], self.project, "public/_headers", "yes", "unknown", "yes")
        tampered = copy.deepcopy(envelope)
        tampered["plan"].pop("mime_types_correct")
        tampered["sha256"] = plan_hash(tampered["plan"])
        with self.assertRaises(CheckError):
            self.apply(tampered)
        with self.assertRaises(CheckError):
            self.apply(envelope, "no")
        self.assertEqual(before_file, self.path.read_bytes())
        factory, made = self.fixture_transport()
        self.assertEqual("still present", self.again(factory=factory)["after"])
        self.apply(envelope)
        self.assertEqual(1, self.path.read_text().splitlines().count("/*"))
        self.assertIn("Referrer-Policy: strict-origin-when-cross-origin", self.path.read_text())
        self.assertIn("X-Content-Type-Options: nosniff", self.path.read_text())
        self.assertEqual("finding no longer observed on this response", self.again(factory=factory)["after"])
        self.assertTrue(all(len(t.calls) == 1 for t in made))

    def test_cli_plan_apply_and_undeployed_recheck(self):
        common = ["--evidence", str(self.evidence), "--review", str(self.review)]
        planfile = self.root / "item-plan.json"
        with self.assertRaisesRegex(CheckError, "outside"):
            main(["guide-plan", *common, "--finding", self.row["id"], "--project", str(self.project),
                  "--file", "public/_headers", "--opt-in", "yes", "--access-impact", "none", "--out", str(self.project / "unapproved.json")])
        self.assertFalse((self.project / "unapproved.json").exists())
        with redirect_stdout(io.StringIO()) as output:
            main(["guide-plan", *common, "--finding", self.row["id"], "--project", str(self.project),
                  "--file", "public/_headers", "--opt-in", "yes", "--access-impact", "none", "--out", str(planfile)])
        self.assertIn("+  Referrer-Policy:", output.getvalue())
        envelope = json.loads(planfile.read_text())
        with redirect_stdout(io.StringIO()):
            main(["guide-apply", *common, "--project", str(self.project), "--plan", str(planfile),
                  "--approval", "yes", "--confirmed-plan", envelope["sha256"]])
            main(["recheck", *common, "--project", str(self.project), "--finding", self.row["id"], "--url", "https://example.com/",
                  "--confirmed-scope", self.data["scope"]["sha256"], "--ownership", OWNERSHIP,
                  "--out", str(self.root / "after.json")])
        self.assertIn(HEADER, self.path.read_text())
        self.assertEqual("deploy, then re-check", json.loads((self.root / "after.json").read_text())["after"])

    def test_recheck_output_inside_project_refused_before_requests(self):
        alias = self.root / "project-alias"
        alias.symlink_to(self.project, target_is_directory=True)
        common = ["recheck", "--evidence", str(self.evidence), "--review", str(self.review), "--project", str(self.project),
                  "--finding", self.row["id"], "--url", "https://example.com/", "--confirmed-scope", self.data["scope"]["sha256"],
                  "--ownership", OWNERSHIP]
        before = self.path.read_bytes()
        for deployed in ("yes", "no"):
            for out in (self.project, self.path, self.project / "after.json", self.project / "public/../after.json", alias / "after.json"):
                with self.subTest(deployed=deployed, out=out), patch("site_check.recheck") as check:
                    with self.assertRaisesRegex(CheckError, "outside the open project"):
                        main([*common, "--deployed", deployed, "--out", str(out)])
                    check.assert_not_called()
        self.assertFalse((self.project / "after.json").exists())
        self.assertEqual(before, self.path.read_bytes())
        outside = self.root / "after.json"
        with redirect_stdout(io.StringIO()):
            main([*common, "--out", str(outside)])
        self.assertEqual("deploy, then re-check", json.loads(outside.read_text())["after"])

    def fixture_transport(self, status=200):
        made = []
        project = self.project
        class FixtureTransport:
            def __init__(self, scope, digest, ownership):
                self.scope, self.calls = scope, []
                self.asserted = (digest == scope["sha256"] and ownership == OWNERSHIP)
                made.append(self)
            def request(self, url, purpose, **kwargs):
                assert url == "https://example.com/" and purpose == "page"
                assert self.scope["sites"] == [url] and self.asserted
                assert not self.calls
                self.calls.append({"type": "GET page", "url": url})
                pairs = [("Content-Type", "text/html")]
                for line in (project / "public/_headers").read_text().splitlines():
                    if line.startswith("  ") and ":" in line:
                        pairs.append(tuple(part.strip() for part in line.split(":", 1)))
                response = header_facts(pairs)
                response.update(status=status, url=url, body_truncated=False)
                return response, (project / "public/index.html").read_text(), ""
        return FixtureTransport, made

    def again(self, deployed="yes", url="https://example.com/", ownership=OWNERSHIP, factory=None):
        return recheck(self.evidence, self.review, self.row["id"], url, self.data["scope"]["sha256"], ownership, deployed, factory or self.fixture_transport()[0])

    def test_fixture_approved_header_fix_flips_single_host_recheck(self):
        factory, made = self.fixture_transport()
        before = self.again(factory=factory)
        self.assertEqual("still present", before["after"])
        self.apply(self.plan())
        after = self.again(factory=factory)
        self.assertEqual("finding no longer observed on this response", after["after"])
        self.assertEqual(before["before"], after["before"])
        self.assertTrue(any(HEADER.lower() in x["line"].lower() and VALUE in x["line"] for x in after["facts"]))
        self.assertTrue(all(t.scope["sites"] == ["https://example.com/"] and len(t.calls) == 1 for t in made))
        self.assertEqual(["GET page"], [x["type"] for x in after["network_calls"]])

    def test_not_deployed_wrong_host_scope_or_review_sends_nothing(self):
        factory = Mock(side_effect=AssertionError("No transport should be created"))
        result = self.again(deployed="no", factory=factory)
        self.assertEqual("deploy, then re-check", result["after"])
        self.assertEqual([], result["network_calls"])
        for url in ("https://second.example.com/", "https://example.com/guessed", "https://unlisted.example.com/"):
            with self.assertRaises(CheckError):
                self.again(url=url, factory=factory)
        with self.assertRaises(CheckError):
            self.again(ownership="yes", factory=factory)
        review = json.loads(self.review.read_text())
        review["decisions"][0]["verdict"] = "drop"
        self.review.write_text(json.dumps(review))
        with self.assertRaises(CheckError):
            self.again(factory=factory)
        factory.assert_not_called()

    def test_non_success_response_is_inconclusive(self):
        self.apply(self.plan())
        factory, _ = self.fixture_transport(status=302)
        self.assertTrue(self.again(factory=factory)["after"].startswith("inconclusive"))


class GuidedSettingsTests(unittest.TestCase):
    def row(self, code):
        return with_guidance({"id": "F1", "code": code, "severity": "Low", "site": "example.com", "finding": "Synthetic", "fix": "Review.", "owner": "owner", "evidence": []})

    def test_exact_cloudflare_steps_require_owner_confirmation(self):
        with self.assertRaises(CheckError):
            settings_steps(self.row("referrer"), "example.com", "Cloudflare", "no")
        result = settings_steps(self.row("referrer"), "example.com", "Cloudflare", "yes", access_impact="none")
        steps = " ".join(result["steps"])
        for text in ("Rules → Overview", "Hostname equals example.com", "Set static", "Save as Draft", HEADER, VALUE):
            self.assertIn(text, steps)
        self.assertEqual("manual owner action only", result["status"])

    def test_dns_requires_exact_owner_value_and_remains_developer_only(self):
        for code, value, name in (("mail-spf", "v=spf1 -all", "example.com"), ("mail-dmarc", "v=DMARC1; p=reject", "_dmarc.example.com")):
            with self.subTest(code=code):
                with self.assertRaises(CheckError):
                    settings_steps(self.row(code), "example.com", "other", "yes")
                result = settings_steps(self.row(code), "example.com", "other", "yes", value)
                self.assertEqual("Needs a developer", result["status"])
                self.assertEqual({"type": "TXT", "name": name, "value": value, "TTL": "provider default"}, result["record"])
                self.assertIn(FREE_REVIEW, result["review"])


class FocusedRecheckTests(unittest.TestCase):
    def test_http_tls_and_mail_each_use_only_the_selected_operation(self):
        for code in ("http", "old-tls", "mail-spf", "mail-dmarc"):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                evidence, review, data, row = save_review(Path(directory), code)
                if code == "old-tls":
                    data["candidates"][0]["finding"] = "TLS 1.1 accepted"
                    evidence.write_text(json.dumps(data))
                    approved = json.loads(review.read_text())
                    approved["evidence_sha256"] = evidence_hash(evidence.read_bytes())
                    review.write_text(json.dumps(approved))
                transport = Mock()
                transport.calls = []
                transport.request.return_value = ({"status": 301}, "", "https://example.com/")
                transport.legacy_tls.return_value = "rejected by server"
                transport.dns.return_value = {"Status": 0, "Answer": []}
                factory = Mock(return_value=transport)
                recheck(evidence, review, row["id"], "https://example.com/", data["scope"]["sha256"], OWNERSHIP, "yes", factory)
                self.assertEqual(["https://example.com/"], factory.call_args.args[0]["sites"])
                if code == "http":
                    transport.request.assert_called_once_with("http://example.com/", "http")
                    transport.legacy_tls.assert_not_called()
                    transport.dns.assert_not_called()
                elif code == "old-tls":
                    transport.legacy_tls.assert_called_once_with("example.com", "1.1")
                    transport.request.assert_not_called()
                    transport.dns.assert_not_called()
                else:
                    transport.dns.assert_called_once_with("example.com" if code == "mail-spf" else "_dmarc.example.com", "TXT")
                    transport.request.assert_not_called()
                    transport.legacy_tls.assert_not_called()

    def test_public_key_recheck_respects_two_bundles_and_never_uses_key(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence, review, data, row = save_review(Path(directory), "public-key")
            key = "sb_publishable_" + "x" * 30
            page = '<script src="/a.js"></script><script src="/b.js"></script><script src="/extra.js"></script><script src="https://other.example.com/c.js"></script>'
            class OnlyAssets:
                def __init__(self, scope, digest, ownership):
                    self.calls = []
                    assert scope["sites"] == ["https://example.com/"]
                def request(self, url, purpose, **kwargs):
                    assert (url, purpose) in (("https://example.com/", "page"), ("https://example.com/a.js", "bundle"), ("https://example.com/b.js", "bundle"))
                    self.calls.append({"type": purpose, "url": url})
                    return {"status": 200, "body_truncated": False}, page if purpose == "page" else 'const publicKey="' + key + '";\n//# sourceMappingURL=explicit.map', ""
            result = recheck(evidence, review, row["id"], "https://example.com/", data["scope"]["sha256"], OWNERSHIP, "yes", OnlyAssets)
            self.assertEqual(["page", "bundle", "bundle"], [r["type"] for r in result["network_calls"]])
            self.assertIn("permissions untested", result["after"])
            self.assertNotIn(key, json.dumps(result))


class GuidedReportTests(unittest.TestCase):
    def test_code_findings_have_copyable_file_change_test_prompt_and_risk_handoff(self):
        codes = ("referrer", "hsts", "csp", "frame", "nosniff", "cookie", "disclosure", "http", "secret", "client-gate", "public-key", "osv", "version", "supabase-rls", "firebase-rules", "source-map")
        for code in codes:
            with self.subTest(code=code):
                prompt = fix_prompt(code)
                for label in ("File:", "Change:", "How to test:"):
                    self.assertIn(label, prompt)
                if risk_reason(code):
                    self.assertIn("Developer-only:", prompt)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence, review, _, _ = save_review(root, "supabase-rls")
            render(evidence, review, root)
            doc = (root / "report.html").read_text()
            self.assertIn("<summary>Fix prompt</summary><pre>File:", doc)
            self.assertGreaterEqual(doc.count(FREE_REVIEW), 2)
            self.assertIn("do not auto-apply", doc)
            self.assertIn(GUIDED_OFFER, (root / "summary.md").read_text())
            self.assertIn("```text\nFile:", (root / "fix-prompts.md").read_text())


class GuidedGuardrailTests(unittest.TestCase):
    def test_no_commit_push_deploy_login_or_cloud_write_execution_paths(self):
        process_calls = []
        for path in (ROOT / "scripts").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ("eval", "exec", "compile", "__import__"))
                elif isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, ("system", "popen", "spawn", "execv", "execvp"))
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                        process_calls.append((path.name, node.func.attr))
                        self.assertFalse(any(k.arg == "shell" and getattr(k.value, "value", None) is True for k in node.keywords))
        self.assertEqual([("audit_hosts.py", "check_output"), ("discover.py", "run")], sorted(process_calls))
        for name in ("guided.py", "recheck.py"):
            tree = ast.parse((ROOT / "scripts" / name).read_text())
            imports = {node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)}
            self.assertTrue(imports.isdisjoint({"subprocess", "requests", "urllib.request"}))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        self.assertNotIn(node.func.id, ("eval", "exec", "compile", "__import__"))
                    if isinstance(node.func, ast.Attribute):
                        self.assertNotIn(node.func.attr, ("system", "popen", "spawn", "execv", "execvp"))
        from discover import COMMANDS
        self.assertEqual({"wrangler": ["wrangler", "pages", "project", "list"], "vercel": ["vercel", "project", "ls"]}, COMMANDS)
        with patch("network.http.client.HTTPSConnection") as connection:
            for host in ("api.cloudflare.com", "api.vercel.com", "api.netlify.com", "synthetic-example-project.supabase.co", "firestore.googleapis.com"):
                with self.assertRaises(CheckError):
                    service_json(host, "/write", {"synthetic": "change"})
            connection.assert_not_called()
        skill = (ROOT / "skills/site-check/SKILL.md").read_text()
        for text in (GUIDED_OFFER, "Never commit, push or deploy", "a cloud API with write scope", "Wait for a fresh explicit yes", "Do not run the original full `run` command again", "deploy, then re-check",
                     "Only an explicit yes permits offering the nosniff local recipe", "--mime-types-correct yes", "do not send extra requests to establish MIME correctness"):
            self.assertIn(text, skill)
        allowed = {"scope", "run", "report", "guide-locate", "guide-plan", "guide-apply", "guide-settings", "recheck"}
        for block in re.findall(r"```sh\n(.*?)```", skill, re.S):
            for line in block.strip().splitlines():
                args = shlex.split(line)
                self.assertEqual("sh", args[0])
                self.assertTrue(args[1].endswith("/scripts/site-check.sh"))
                self.assertIn(args[2], allowed)
                self.assertTrue(set(args[2:]).isdisjoint({"commit", "push", "deploy", "login"}))
                if args[2] == "recheck":
                    self.assertEqual("${CLAUDE_PROJECT_DIR}", args[args.index("--project") + 1])


if __name__ == "__main__":
    unittest.main()
