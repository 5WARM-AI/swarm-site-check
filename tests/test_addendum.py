"""Synthetic, offline checks for effort guidance, public app checks and reports."""
import base64
import json
import re
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from checks import Evidence, collect
from audit_hosts import audit
from guidance import CALL, DEVELOPER_BOOKING, FREE_REVIEW, effort_for, with_guidance
from network import CheckError, OWNERSHIP, Transport, normalize_url
from parsers import Page, secrets
from report import evidence_hash, render
from tests.test_safety import scope_for
from vibe import client_gates, firebase_config, platform_hints, preview_posture, source_map, supabase_config

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
BUNDLE = (FIXTURES / "vibe-bundle.js").read_text()
PAGE = (FIXTURES / "vibe-page.html").read_text()


class EffortTests(unittest.TestCase):
    def test_conservative_estimates_and_unknown_fallback(self):
        self.assertEqual("Fix it yourself (~15 min)", effort_for("public-key")[0])
        self.assertEqual("Needs a developer", effort_for("http", ["Cloudflare"])[0])
        self.assertEqual("Needs a developer", effort_for("public-ui", ["Vercel"])[0])
        for code, platforms in (("http", []), ("http", ["Cloudflare Pages", "Cloudflare"]),
                                ("old-tls", ["Cloudflare Workers", "Cloudflare"]),
                                ("old-tls", ["Cloudflare Tunnel", "Cloudflare"]),
                                ("osv", []), ("supabase-rls", []), ("firebase-rules", []),
                                ("client-gate", []), ("source-map", []), ("secret", []), ("unknown", [])):
            with self.subTest(code=code, platforms=platforms):
                tag, reason = effort_for(code, platforms)
                self.assertEqual("Needs a developer", tag)
                self.assertTrue(reason)
                self.assertNotIn("\n", reason)

    def test_every_finding_tagged_without_severity_changes(self):
        ev = Evidence()
        for severity in ("Critical", "High", "Medium", "Low", "Info"):
            ev.finding("example.com", "public-key", severity, "Synthetic", [], "Review.")
        for row in ev.candidates:
            self.assertEqual("Fix it yourself (~15 min)", row["effort_tag"])
            self.assertTrue(row["effort_reason"])
            self.assertEqual("", row["booking_line"])
        self.assertEqual(["Critical", "High", "Medium", "Low", "Info"], [x["severity"] for x in ev.candidates])
        row = with_guidance(dict(ev.candidates[0], code="unknown"))
        self.assertEqual(DEVELOPER_BOOKING, row["booking_line"])
        self.assertEqual(row, with_guidance(row))

    def test_platform_hints_update_earlier_findings(self):
        ev = Evidence()
        ev.finding("example.com", "public-ui", "Info", "Synthetic", [], "Review.")
        ev.note_platforms("example.com", "https://example.com/", headers={"server": ["Vercel"]})
        self.assertIn("Deployment Protection", ev.candidates[0]["fix"])
        self.assertEqual("Needs a developer", ev.candidates[0]["effort_tag"])
        self.assertEqual("Info", ev.candidates[0]["severity"])

    def test_header_only_platform_hints_require_developer(self):
        for platform, codes in (("Cloudflare", ("http", "old-tls")),
                                ("Vercel", ("public-ui",)), ("Netlify", ("public-ui",))):
            with self.subTest(platform=platform):
                ev = Evidence()
                ev.note_platforms("example.com", "https://example.com/", headers={"server": [platform]})
                for code in codes:
                    ev.finding("example.com", code, "Low", "Synthetic", [], "Review.")
                for row in ev.candidates:
                    self.assertEqual("Needs a developer", row["effort_tag"])
                    self.assertIn("do not establish account control", row["effort_reason"])
                    self.assertEqual(DEVELOPER_BOOKING, row["booking_line"])
                    self.assertEqual("Low", row["severity"])


class VibeTests(unittest.TestCase):
    def test_supabase_requires_url_and_public_key(self):
        self.assertTrue(supabase_config(BUNDLE, secrets(BUNDLE, "/app.js")))
        for body in ('const key="sb_publishable_synthetic00000000";',
                     'const url="https://synthetic-example-project.supabase.co";',
                     'const url="https://synthetic-example-project.supabase.co"; const key="sb_secret_synthetic00000000";'):
            self.assertFalse(supabase_config(body, secrets(body, "/app.js")))
        payload = base64.urlsafe_b64encode(b'{"role":"anon"}').decode().rstrip("=")
        body = '"https://synthetic-example-project.supabase.co"; "eyJhbGciOiJIUzI1NiJ9.' + payload + '.syntheticSignature"'
        self.assertTrue(supabase_config(body, secrets(body, "/app.js")))

    def test_rls_and_rules_dashboard_steps_no_permission_claim(self):
        ev = Evidence()
        with patch("network.socket.create_connection") as net, patch("network.service_json") as service:
            ev.inspect_content("example.com", "https://example.com/app.js", BUNDLE, False)
            net.assert_not_called()
            service.assert_not_called()
        bycode = {x["code"]: x for x in ev.candidates}
        rls, rules = bycode["supabase-rls"], bycode["firebase-rules"]
        self.assertEqual("Info", rls["severity"])
        self.assertIn("public by design", rls["fix"].lower())
        self.assertIn("Database → Policies", rls["fix"])
        self.assertIn("every table", rls["fix"])
        self.assertIn("Enable RLS", rls["fix"])
        self.assertEqual("Info", rules["severity"])
        for product in ("Firestore Database", "Realtime Database", "Storage"):
            self.assertIn(product + " → Rules", rules["fix"])
        self.assertIn("No database request", rules["fix"])
        self.assertTrue(all(x["effort_reason"] for x in ev.candidates))

    def test_firebase_public_config_does_not_hide_other_google_key(self):
        self.assertEqual(1, len(firebase_config(BUNDLE)))
        self.assertEqual(1, len(firebase_config('const config={apiKey:"synthetic", projectId:"synthetic", appId:"1:000:web:synthetic"};')))
        self.assertEqual([], firebase_config('const x={apiKey:"synthetic", projectId:"synthetic"};'))
        ev = Evidence()
        ev.inspect_content("example.com", "https://example.com/app.js", BUNDLE, False)
        self.assertEqual(2, len([x for x in ev.candidates if x["code"] == "public-key"]))
        self.assertEqual(1, len([x for x in ev.candidates if x["finding"] == "Potential exposed Google API key"]))

    def test_plain_hash_and_storage_gates_with_uncertainty(self):
        gates = client_gates(BUNDLE) + client_gates("\n".join(Page(PAGE).inline_scripts))
        self.assertTrue(any(x.get("length") == 23 for x in gates))
        self.assertTrue(any(x.get("length") == 64 for x in gates))
        self.assertEqual(2, sum("storage" in x["pattern"] for x in gates))
        for code in ('if(window.localStorage.getItem("example_auth")) show();', 'const ok = !!sessionStorage.getItem("auth");'):
            self.assertTrue(client_gates(code))
        ev = Evidence()
        ev.inspect_content("example.com", "/app.js", BUNDLE + '; fetch("/session");', False)
        self.assertTrue(all(x["severity"] == "Info" for x in ev.candidates if x["code"] == "client-gate"))
        self.assertIn("backend authorization untested", json.dumps(ev.facts))

    def test_preferences_storage_writes_and_prose_are_not_gates(self):
        for js in ('if(localStorage.getItem("theme")) dark();', 'sessionStorage.setItem("auth", "true");',
                   'const password="synthetic";', 'const hashedPassword="synthetic";'):
            self.assertEqual([], client_gates(js))
        ev = Evidence()
        ev.inspect_content("example.com", "/", '<p>if (password === "synthetic") unlock()</p>', True)
        self.assertNotIn("client-gate", [x["code"] for x in ev.candidates])

    def test_secret_and_config_values_never_persist(self):
        ev = Evidence()
        ev.inspect_content("example.com", "https://example.com/", PAGE, True)
        ev.inspect_content("example.com", "https://example.com/app.js", BUNDLE, False)
        data = json.dumps(ev.__dict__)
        for value in ("synthetic-password-only", "b" * 64, "synthetic-example-project", "AIzaSynthetic", "sb_publishable_synthetic"):
            self.assertNotIn(value, data)

    def test_preview_requires_success_no_login_and_no_noindex(self):
        url = "https://staging.example.com/"
        self.assertEqual("preview/staging-looking", preview_posture(url, PAGE, {}, 200))
        for body, headers, status in ((PAGE, {}, 302), (PAGE, {}, 401),
                                     (PAGE + '<input type="password">', {}, 200),
                                     (PAGE + '<form action="/login">', {}, 200),
                                     (PAGE + '<meta name="robots" content="noindex">', {}, 200),
                                     (PAGE, {"x-robots-tag": ["none"]}, 200)):
            self.assertIsNone(preview_posture(url, body, headers, status))
        self.assertIsNone(preview_posture("https://example.com/", PAGE, {}, 200))

    def test_noindex_does_not_suppress_admin_access_review(self):
        self.assertEqual("admin-looking", preview_posture("https://example.com/admin", PAGE, {"x-robots-tag": ["noindex"]}, 200))

    def test_platform_markers_feed_named_dashboard_steps(self):
        fixtures = [
            ("Lovable", PAGE, {}, ()),
            ("Bolt", '<meta name="generator" content="Bolt">', {}, ()),
            ("Replit", '<script src="https://replit.com/public/js/replit-badge-v3.js"></script>', {}, ()),
            ("Vercel", "", {}, ("x-vercel-id",)),
            ("Netlify", "", {"server": ["Netlify"]}, ()),
            ("Cloudflare Pages", '<meta name="generator" content="Cloudflare Pages">', {}, ()),
        ]
        for platform, body, headers, names in fixtures:
            with self.subTest(platform=platform):
                hints = platform_hints("https://example.com/", body, headers, names)
                self.assertIn(platform, hints)
                ev = Evidence()
                ev.note_platforms("example.com", "https://example.com/", body, headers, names)
                ev.finding("example.com", "public-ui", "Info", "Synthetic", [], "Review.")
                self.assertIn(platform, ev.candidates[0]["fix"])
        self.assertNotIn("Replit", platform_hints("https://example.com/", headers={"server": ["Google Frontend"]}))
        self.assertNotIn("Cloudflare Pages", platform_hints("https://example.com/", headers={"server": ["cloudflare"]}))


class SourceMapTests(unittest.TestCase):
    def test_explicit_directives_only(self):
        bundle = "https://example.com/assets/app.js"
        self.assertEqual("https://example.com/assets/vibe-bundle.js.map", source_map(BUNDLE, bundle)[0])
        self.assertEqual("https://example.com/assets/app.map", source_map('x();\n/*# sourceMappingURL=app.map */', bundle)[0])
        for text in ('x();', '"//# sourceMappingURL=app.map"', '`\n//# sourceMappingURL=app.map\n`',
                     '//# sourceMappingURL=data:application/json;base64,e30=',
                     '//# sourceMappingURL=https://outside.example/app.map',
                     '//# sourceMappingURL=app.map?token=synthetic',
                     '//# sourceMappingURL=app.map\nrun();'):
            self.assertIsNone(source_map(text, bundle)[0])

    def transport(self):
        scope = scope_for("example.com")
        return Transport(scope, scope["sha256"], OWNERSHIP)

    def test_no_guessed_map_or_backend_or_found_key_requests(self):
        t = self.transport()
        with patch("network.socket.create_connection") as conn, patch("network.service_json") as service:
            with self.assertRaises(CheckError):
                t.request("https://example.com/app.js.map", "source-map", parent="https://example.com/app.js")
            for host in ("synthetic-example-project.supabase.co", "synthetic-example-project.firebaseio.com", "firestore.googleapis.com"):
                with self.assertRaises(CheckError):
                    normalize_url(host)
            t.page_used.add("https://example.com/")
            with self.assertRaises(CheckError):
                t.request("https://example.com/app.js.map", "bundle", parent="https://example.com/", discovered=["https://example.com/app.js.map"])
            for query in ("token=synthetic", "key=synthetic", "v=sb_publishable_synthetic000000000"):
                url = "https://example.com/app.js?" + query
                with self.assertRaises(CheckError):
                    t.request(url, "bundle", parent="https://example.com/", discovered=[url])
            conn.assert_not_called()
            service.assert_not_called()

    def test_fetched_bundle_provenance_head_no_body_and_shared_budget(self):
        t = self.transport()
        page, bundle, target = "https://example.com/", "https://example.com/app.js", "https://example.com/app.js.map"
        t.page_used.add(page)
        response = Mock(status=200)
        response.getheaders.return_value = []
        response.getheader.side_effect = lambda key, default="": default
        response.read1.side_effect = [b'x();\n//# sourceMappingURL=app.js.map', b'']
        connection, sock = Mock(), Mock()
        connection.getresponse.return_value = response
        sock.getpeercert.return_value = {}
        sock.version.return_value = "TLSv1.3"
        with patch.object(t, "resolve", return_value="93.184.216.34"), patch.object(t, "pause"), \
             patch("network.socket.create_connection", return_value=sock), \
             patch("network.ssl.create_default_context") as ctx, \
             patch("network.certificate_chain", return_value=[]), \
             patch("network.http.client.HTTPConnection", return_value=connection):
            ctx.return_value.wrap_socket.return_value = sock
            t.request(bundle, "bundle", parent=page, discovered=[bundle])
            self.assertEqual(target, t.map_targets[bundle])
            response.read1.reset_mock(side_effect=True)
            response.read1.side_effect = AssertionError("Map body must never be read")
            _, body, _ = t.request(target, "source-map", parent=bundle)
            self.assertEqual("", body)
            response.read1.assert_not_called()
            self.assertEqual(["GET", "HEAD"], [x.args[0] for x in connection.request.call_args_list])
            with self.assertRaises(CheckError):
                t.request("https://example.com/second.js", "bundle", parent=page, discovered=["https://example.com/second.js"])
            with self.assertRaises(CheckError):
                t.request(target, "source-map", parent=bundle)
            self.assertEqual(2, len(t.calls))
            self.assertEqual(2, t.asset_used["example.com"])

    def test_map_after_two_bundle_attempts_is_not_requested(self):
        t = self.transport()
        page, bundle, target = "https://example.com/", "https://example.com/app.js", "https://example.com/app.js.map"
        t.page_used.add(page)
        with patch.object(t, "resolve", side_effect=CheckError("Public address unavailable")), patch("network.socket.create_connection") as conn:
            for _ in range(2):
                with self.assertRaises(CheckError):
                    t.request(bundle, "bundle", parent=page, discovered=[bundle])
            t.map_targets[bundle] = target
            with self.assertRaisesRegex(CheckError, "asset budget"):
                t.request(target, "source-map", parent=bundle)
            conn.assert_not_called()

    def test_map_redirect_not_followed_and_no_finding(self):
        t = Mock(urls=["https://example.com/"], bundle_used={})
        def request(url, purpose, **kwargs):
            body = '<html><script src="/one.js"></script></html>' if purpose == "page" else 'x();\n//# sourceMappingURL=one.map'
            return ({"status": 302 if purpose == "source-map" else 200,
                     "headers": {"content-type": ["text/html" if purpose == "page" else "text/javascript"]},
                     "header_names": ["content-type"], "cookies": [], "url": url, "tls": None, "body_truncated": False}, body, "https://outside.example/map")
        t.request.side_effect = request
        t.legacy_tls.return_value = "not tested on this machine"
        t.dns.return_value = {"Status": 0}
        ev = collect(t)
        self.assertNotIn("source-map", [x["code"] for x in ev.candidates])
        self.assertTrue(any("redirects not followed" in x["status"] for x in ev.coverage))
        self.assertEqual(1, sum(c.args[1] == "source-map" for c in t.request.call_args_list))
        self.assertTrue(all("outside.example" not in c.args[0] for c in t.request.call_args_list))

    def test_collector_records_map_and_only_scoped_preview(self):
        t = Mock(urls=["https://staging.example.com/"], bundle_used={})
        def request(url, purpose, **kwargs):
            body = PAGE if purpose == "page" else BUNDLE if purpose == "bundle" else ""
            return ({"status": 200, "headers": {"content-type": ["text/html" if purpose == "page" else "text/javascript"]},
                     "header_names": ["content-type"], "cookies": [], "url": url, "tls": None, "body_truncated": False}, body, "")
        t.request.side_effect = request
        t.legacy_tls.return_value = "not tested on this machine"
        t.dns.return_value = {"Status": 0}
        ev = collect(t)
        codes = {x["code"] for x in ev.candidates}
        self.assertTrue({"supabase-rls", "firebase-rules", "client-gate", "source-map", "public-ui"} <= codes)
        self.assertTrue(all(c.args[0].startswith(("https://staging.example.com/", "http://staging.example.com/")) for c in t.request.call_args_list))


class TextOnly(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.parts = []
        self.feed(text)
    def handle_data(self, data):
        self.parts.append(data)


class ReportAddendumTests(unittest.TestCase):
    def test_hostname_audit_counts_only_and_domain_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "example.txt").write_text("https://private.example.com/ Private.Example.Com. private.example.com.evil.example")
            with patch("audit_hosts.subprocess.check_output", return_value=b"example.txt\0"):
                result = audit(root, ["private.example.com"])
            self.assertEqual(2, result["private_hostname_occurrences"])
            self.assertEqual(1, result["files_with_private_hostnames"])
            self.assertNotIn("private.example.com", json.dumps(result))

    def test_every_row_effort_developer_row_ends_booking_and_final_opt_in(self):
        ev = Evidence()
        ref = ev.fact("example.com", "/", "synthetic evidence")
        for code in ("public-key", "supabase-rls", "client-gate"):
            ev.finding("example.com", code, "Info", "Synthetic " + code, [ref], "Review.")
        data = {"facts": ev.facts, "candidates": ev.candidates, "scope": {"sites": ["https://example.com/"]}, "created_at": "synthetic", "coverage": []}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = json.dumps(data).encode()
            (root / "evidence.json").write_bytes(raw)
            review = {"evidence_sha256": evidence_hash(raw), "reviewer": "synthetic offline reviewer", "decisions": [
                {"id": x["id"], "verdict": "keep", "severity": x["severity"], "evidence": x["evidence"], "reason": "Synthetic evidence supports demonstration."} for x in ev.candidates]}
            (root / "review.json").write_text(json.dumps(review))
            render(root / "evidence.json", root / "review.json", root)
            doc, md = (root / "report.html").read_text(), (root / "summary.md").read_text()
            rows = re.findall(r"<tr>(.*?)</tr>", doc, re.S)[1:]
            self.assertEqual(3, len(rows))
            for row in rows:
                text = "".join(TextOnly(row).parts)
                if "Needs a developer" in text:
                    self.assertTrue(text.endswith(DEVELOPER_BOOKING))
                else:
                    self.assertIn("Fix it yourself (~15 min)", text)
                    self.assertNotIn(DEVELOPER_BOOKING, text)
            self.assertTrue("".join(TextOnly(doc).parts).strip().endswith(FREE_REVIEW + ": " + CALL))
            self.assertTrue(md.strip().endswith(FREE_REVIEW + ": " + CALL))
            for row in md.splitlines():
                if "Needs a developer" in row:
                    self.assertTrue(row.endswith(DEVELOPER_BOOKING + " |"))
            self.assertNotRegex(doc, r"<(?:script|form|iframe|img|link)\b")
            self.assertIn("never uploads or emails", doc)

    def test_marketplace_install_identity(self):
        marketplace = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
        self.assertEqual("swarm-site-check", marketplace["name"])
        self.assertEqual("site-check", marketplace["plugins"][0]["name"])


if __name__ == "__main__":
    unittest.main()
