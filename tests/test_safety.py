import copy
import html
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from checks import Evidence, check_headers, check_mail, collect, match_osv
from network import CheckError, OWNERSHIP, Transport, certificate_chain, normalize_url, scope_digest, service_json
from report import evidence_hash, render, reviewed_findings

FIXTURES = Path(__file__).parent / "fixtures"


def scope_for(*sites):
    urls = sorted(normalize_url(s) for s in sites)
    return {"sites": urls, "sha256": scope_digest(urls)}


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = scope_for("example.com")

    def test_no_confirmation_no_network(self):
        with patch("network.service_json") as request:
            with self.assertRaises(CheckError):
                Transport(self.scope, self.scope["sha256"], "yes")
            request.assert_not_called()

    def test_changed_scope_refused(self):
        digest = self.scope["sha256"]
        self.scope["sites"].append("https://example.org/")
        with self.assertRaises(CheckError):
            Transport(self.scope, digest, OWNERSHIP)

    def test_invalid_urls(self):
        for value in ["http://127.0.0.1/", "https://localhost/", "https://example.com:22/", "https://user:pass@example.com/",
                      "https://example.com/?token=abc", "https://example.com/../admin", "https://example.com/%0dX-Test:x",
                      "https://example.com/webhook/token", "https://a.internal/", "file:///etc/passwd", "example.com\n"]:
            with self.subTest(value=value), self.assertRaises(CheckError):
                normalize_url(value)

    def test_idna_and_explicit_path(self):
        self.assertEqual("https://example.com/admin/", normalize_url("http://EXAMPLE.com/admin/"))

    def test_private_dns_rejected_without_connect(self):
        t = Transport(self.scope, self.scope["sha256"], OWNERSHIP)
        with patch.object(t, "dns", return_value={"Answer": [{"type": 1, "data": "127.0.0.1"}]}), patch("network.socket.create_connection") as conn:
            with self.assertRaises(CheckError):
                t.request("https://example.com/", "page")
            conn.assert_not_called()

    def test_unconfirmed_and_guessed_paths_refused(self):
        t = Transport(self.scope, self.scope["sha256"], OWNERSHIP)
        with patch("network.socket.create_connection") as conn:
            for url in ("https://example.org/", "https://example.com/admin"):
                with self.assertRaises(CheckError):
                    t.request(url, "page")
            with self.assertRaises(CheckError):
                t.request("https://third.example/app.js", "bundle", parent="https://example.com/", discovered=["https://third.example/app.js"])
            conn.assert_not_called()

    def test_budget_enforced_on_failed_requests(self):
        t = Transport(self.scope, self.scope["sha256"], OWNERSHIP)
        with patch.object(t, "resolve", side_effect=CheckError("no address")):
            for _ in range(2):
                with self.assertRaises(CheckError):
                    t.request("https://example.com/", "page")
            t.page_used.add("https://example.com/")
            for i in range(3):
                with self.assertRaises(CheckError):
                    t.request("https://example.com/app.js", "bundle", parent="https://example.com/", discovered=["https://example.com/app.js"])
            self.assertEqual(2, t.bundle_used["example.com"])

    def test_service_allowlist(self):
        with self.assertRaises(CheckError):
            service_json("example.com", "/v1/querybatch")

    def test_legacy_local_failure_is_unknown(self):
        t = Transport(self.scope, self.scope["sha256"], OWNERSHIP)
        with patch("network.ssl.SSLContext", side_effect=ValueError()):
            self.assertIn("not tested on this machine", t.legacy_tls("example.com", "1.0"))

    def test_chain_fallback(self):
        self.assertIn("unavailable", certificate_chain(object()))

    def test_public_ip_is_pinned(self):
        t = Transport(self.scope, self.scope["sha256"], OWNERSHIP)
        with patch.object(t, "dns", return_value={"Answer": [{"type": 1, "data": "93.184.216.34"}]}) as dns:
            self.assertEqual("93.184.216.34", t.resolve("example.com"))
            self.assertEqual("93.184.216.34", t.resolve("example.com"))
            self.assertEqual(2, dns.call_count)


class CheckTests(unittest.TestCase):
    def test_duplicate_versions_share_evidence(self):
        ev = Evidence()
        ev.inspect_content("example.com", "/a.js", 'nextVersion="14.0.0"', False)
        ev.inspect_content("example.com", "/b.js", 'nextVersion="14.0.0"', False)
        self.assertEqual(1, len(ev.versions))
        self.assertEqual(1, len(ev.candidates))
        self.assertEqual(2, len(ev.candidates[0]["evidence"]))

    def test_bundle_scope_and_count(self):
        from unittest.mock import Mock
        t = Mock(urls=["https://example.com/"], bundle_used={})
        body = '<html><script src="https://outside.example/a.js"></script><script src="/one.js"></script><script src="/two.js"></script><script src="/three.js"></script><a href="/admin">admin</a></html>'
        def request(url, purpose, **kwargs):
            return ({"status": 200, "headers": {"content-type": ["text/html" if purpose == "page" else "text/javascript"]},
                     "header_names": ["content-type"], "cookies": [], "url": url, "tls": None, "body_truncated": False}, body if purpose == "page" else "", "")
        t.request.side_effect = request
        t.legacy_tls.return_value = "not tested on this machine"
        t.dns.return_value = {"Status": 0}
        collect(t)
        urls = [c.args[0] for c in t.request.call_args_list]
        self.assertEqual(["https://example.com/", "https://example.com/one.js", "https://example.com/two.js", "http://example.com/"], urls)

    def test_csp_frame_ancestors_and_hsts(self):
        from parsers import header_facts
        ev = Evidence()
        response = header_facts(json.loads((FIXTURES / "headers.json").read_text()))
        response.update(status=200, url="https://example.com/")
        check_headers(ev, "example.com", response)
        self.assertNotIn("hsts", [x["code"] for x in ev.candidates])
        self.assertNotIn("frame", [x["code"] for x in ev.candidates])
        self.assertIn("cookie", [x["code"] for x in ev.candidates])

    def test_disabled_hsts_is_not_effective(self):
        from parsers import header_facts
        response = header_facts([("Strict-Transport-Security", "max-age=0")])
        response.update(status=200, url="https://example.com/")
        ev = Evidence()
        check_headers(ev, "example.com", response)
        self.assertIn("hsts", [x["code"] for x in ev.candidates])

    def test_secret_values_never_enter_evidence(self):
        ev = Evidence()
        ev.inspect_content("example.com", "https://example.com/", (FIXTURES / "page.html").read_text(), True)
        data = json.dumps(ev.__dict__)
        for value in ("sk_test_" + "x" * 24, "sb_publishable_" + "x" * 32, "a" * 64, "synthetic-only"):
            self.assertNotIn(value, data)
        self.assertEqual("Info", next(x["severity"] for x in ev.candidates if x["code"] == "public-key"))

    def test_dns_error_not_absent_policy(self):
        from unittest.mock import Mock
        ev, t = Evidence(), Mock()
        t.dns.return_value = {"Status": 2}
        check_mail(ev, t, "example.com")
        self.assertEqual([], ev.candidates)
        self.assertEqual(2, len(ev.coverage))

    def test_osv_live_batch_and_details(self):
        from unittest.mock import Mock
        ev, t = Evidence(), Mock(calls=[])
        ref = ev.fact("example.com", "/", "n8n@1.2.3")
        ev.versions = [{"kind": "npm", "product": "n8n", "version": "1.2.3", "site": "example.com", "evidence_ids": [ref]}]
        replies = [json.loads((FIXTURES / "osv-batch.json").read_text()), json.loads((FIXTURES / "osv-advisory.json").read_text())]
        with patch("checks.service_json", side_effect=replies) as request:
            match_osv(ev, t)
        self.assertEqual("npm", request.call_args_list[0].args[2]["queries"][0]["package"]["ecosystem"])
        self.assertEqual("High", ev.candidates[0]["severity"])
        self.assertIn("1.2.4", ev.candidates[0]["fix"])

    def test_osv_failure_not_clean(self):
        from unittest.mock import Mock
        ev, t = Evidence(), Mock(calls=[])
        ev.versions = [{"kind": "npm", "product": "next", "version": "1.0.0", "site": "example.com", "evidence_ids": []}]
        with patch("checks.service_json", side_effect=CheckError()):
            match_osv(ev, t)
        self.assertIn("incomplete", ev.coverage[0]["status"])

    def test_collect_does_not_follow_redirect(self):
        from unittest.mock import Mock
        t = Mock(urls=["https://example.com/"], bundle_used={})
        t.request.return_value = ({"status": 302, "headers": {"location": ["https://outside.example/login"]},
                                  "header_names": ["location"], "cookies": [], "url": "https://example.com/",
                                  "tls": None, "body_truncated": False}, "", "https://outside.example/login")
        t.legacy_tls.return_value = "not tested on this machine"
        t.dns.return_value = {"Status": 0}
        collect(t)
        self.assertEqual(["https://example.com/", "http://example.com/"], [c.args[0] for c in t.request.call_args_list])


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.data = {"facts": [{"id": "E00001", "source": "/", "line": "HTTP status=200"}],
                     "candidates": [{"id": "F00001", "severity": "Low", "site": "example.com", "code": "test",
                                     "finding": "<script>alert(1)</script>", "evidence": ["E00001"], "fix": "Review.", "owner": "you"}],
                     "scope": {"sites": ["https://example.com/"]}, "created_at": "2026-01-01", "coverage": []}
        self.review = {"evidence_sha256": "digest", "reviewer": "test reviewer", "decisions": [
            {"id": "F00001", "verdict": "keep", "severity": "Low", "evidence": ["E00001"], "reason": "Evidence supports cautious wording."}]}

    def test_review_rejects_digest_and_omissions(self):
        with self.assertRaises(CheckError):
            reviewed_findings(self.data, self.review, "other")
        self.review["decisions"] = []
        with self.assertRaises(CheckError):
            reviewed_findings(self.data, self.review, "digest")

    def test_no_escalation_or_fake_evidence(self):
        for change in ({"severity": "Critical"}, {"evidence": ["E99999"]}, {"reason": ""}, {"verdict": None}):
            review = copy.deepcopy(self.review)
            review["decisions"][0].update(change)
            with self.assertRaises(CheckError):
                reviewed_findings(self.data, review, "digest")

    def test_drop_and_downgrade(self):
        self.review["decisions"][0]["severity"] = "Info"
        kept, dropped = reviewed_findings(self.data, self.review, "digest")
        self.assertEqual("Info", kept[0]["severity"])
        self.review["decisions"][0]["verdict"] = "drop"
        self.assertEqual(([], 1), reviewed_findings(self.data, self.review, "digest"))

    def test_render_html_escaping_and_no_external_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = json.dumps(self.data).encode()
            (root / "evidence.json").write_bytes(raw)
            self.review["evidence_sha256"] = evidence_hash(raw)
            (root / "review.json").write_text(json.dumps(self.review))
            render(root / "evidence.json", root / "review.json", root)
            output = (root / "report.html").read_text()
            self.assertNotIn("<script>", output)
            self.assertIn("&lt;script&gt;", output)
            self.assertNotIn('<link', output)
            self.assertIn("#5B4BD6", output)

    def test_summary_neutralizes_hostile_title_and_all_site_fields(self):
        hostile = ('# Heading\r\n> Quote\n- List | `code` \\ **bold** _emphasis_ ~~strike~~ '
                   '[click](https://example.com/) ![image](https://example.com/image.png) '
                   '<img src="https://example.com/image.png" onerror="alert(1)"> '
                   '&lt;script&gt; &#96; + item 1. item user@example.com\x00end')
        row = self.data["candidates"][0]
        for field in ("site", "finding", "fix", "owner"):
            row[field] = hostile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = json.dumps(self.data).encode()
            (root / "evidence.json").write_bytes(raw)
            self.review["evidence_sha256"] = evidence_hash(raw)
            (root / "review.json").write_text(json.dumps(self.review))
            render(root / "evidence.json", root / "review.json", root)
            summary = (root / "summary.md").read_text()
        rows = [line for line in summary.splitlines() if line.startswith("| Low |")]
        self.assertEqual(1, len(rows))
        self.assertEqual(7, rows[0].count("|"))  # Six cells; no injected rows/columns.
        cells = rows[0].split("|")[1:-1]
        for cell in cells[1:5]:
            with self.subTest(cell=cell):
                self.assertEqual(" ".join(hostile.replace("\x00", " ").split()), html.unescape(cell.strip()))
                for raw_syntax in ('`', '[', ']', '<', '>', '\\', '*', '_', '~', 'https://', 'user@example.com'):
                    self.assertNotIn(raw_syntax, cell)
                self.assertTrue(cell.strip().startswith("&#35; Heading"))
                self.assertIn("&#62; Quote", cell)
                self.assertIn("&#45; List", cell)
                self.assertIn("&#38;lt&#59;script&#38;gt&#59;", cell)


if __name__ == "__main__":
    unittest.main()
