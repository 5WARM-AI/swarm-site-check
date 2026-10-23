import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from parsers import Page, SuffixList, cookie_flags, header_facts, n8n_release, osv_package, redact, safe_url, secrets, version_facts, wp_versions

FIXTURES = Path(__file__).parent / "fixtures"


class ParserTests(unittest.TestCase):
    def test_headers_duplicates_and_omission(self):
        result = header_facts(json.loads((FIXTURES / "headers.json").read_text()))
        self.assertEqual(2, len(result["cookies"]))
        self.assertEqual(["Next.js"], result["headers"]["x-powered-by"])
        self.assertNotIn("synthetic-cookie", json.dumps(result))
        self.assertNotIn("synthetic-value-never-retained", json.dumps(result))
        self.assertIn("x-unrecognized", result["header_names"])

    def test_cookie_case_and_samesite(self):
        good = cookie_flags("sid=not-retained; sEcUrE; HTTPOnly; SameSite=None")
        self.assertEqual({"name": "sid", "secure": True, "httponly": True, "samesite": "none"}, good)
        self.assertIsNone(cookie_flags("sid=a; SameSite=bogus")["samesite"])

    def test_n8n_base64_release_only(self):
        page = Page((FIXTURES / "page.html").read_text())
        self.assertEqual("1.2.3", n8n_release(page.meta[0]["content"]))
        for invalid in ["???", "e30=", "WyJsaXN0Il0=", "x" * 65537]:
            self.assertIsNone(n8n_release(invalid))

    def test_wp_core_and_plugins_not_jquery(self):
        values = wp_versions(Page((FIXTURES / "page.html").read_text()).assets)
        self.assertEqual({("wordpress", "5.7"), ("example-forms", "2.5.1")}, {(x["product"], x["version"]) for x in values})

    def test_bundle_versions_and_markers(self):
        values, markers = version_facts((FIXTURES / "bundle.js").read_text(), "https://example.com/app.js")
        self.assertEqual({("react", "18.2.0"), ("next", "14.0.0"), ("vite", "4.0.0")}, {(x["product"], x["version"]) for x in values})
        self.assertIn("react", markers)
        values, _ = version_facts('self.__next_f.push([]);Symbol.for("react.element")', "/a.js")
        self.assertEqual([], values)

    def test_unrelated_bundle_version_not_react(self):
        values, _ = version_facts('Symbol.for("react.element");a.createElement=function(){};a.version="18.2.0";b.version="3.10.2";', "/app.js")
        self.assertEqual(["18.2.0"], [x["version"] for x in values])

    def test_jwt_role_no_claims_or_value(self):
        body = (FIXTURES / "bundle.js").read_text()
        values = secrets(body, "https://example.com/app.js?access_token=synthetic")
        self.assertEqual({"anon", "service_role"}, {x["role"] for x in values if x["type"] == "JWT"})
        self.assertNotIn("synthetic@example.com", json.dumps(values))
        self.assertNotIn("eyJ", json.dumps(values))
        self.assertNotIn("access_token", json.dumps(values))

    def test_all_secret_types_redacted(self):
        samples = {"private key": "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC\n-----END RSA PRIVATE KEY-----",
                   "Anthropic secret": "sk-ant-" + "a" * 30, "Stripe secret": "sk_live_" + "a" * 30,
                   "OpenAI secret": "sk-proj-" + "a" * 40, "AWS access key ID": "AKIA" + "A" * 16,
                   "Google API key": "AIza" + "a" * 35, "Supabase secret": "sb_secret_" + "a" * 30,
                   "Supabase publishable (public)": "sb_publishable_" + "a" * 30,
                   "GitHub token": "ghp_" + "a" * 36, "Slack token": "xoxb-" + "a" * 30,
                   "n8n webhook URL": "https://example.com/webhook/synthetic",
                   "client-side password hash": 'const PASSWORD_HASH = "' + "f" * 64 + '"'}
        for kind, value in samples.items():
            with self.subTest(kind=kind):
                found = secrets(value, "/")
                self.assertEqual(kind, found[0]["type"])
                self.assertNotIn(value, json.dumps(found))
                self.assertNotIn(value, redact(value))

    def test_public_key_and_password_hash(self):
        found = secrets((FIXTURES / "page.html").read_text(), "/")
        self.assertIn("Supabase publishable (public)", [x["type"] for x in found])
        self.assertEqual(64, next(x["length"] for x in found if x["type"] == "client-side password hash"))

    def test_urls_and_nonce_redaction(self):
        self.assertNotIn("password", safe_url("https://user:password@example.com/app.js?token=hidden"))
        self.assertNotIn("hidden", safe_url("https://example.com/webhook/hidden"))
        self.assertNotIn("abcd", redact("script-src 'nonce-abcd'"))
        path = "/wp-content/plugins/stackable-ultimate-gutenberg-blocks/dist/frontend_blocks.js?ver=2.6.1"
        self.assertEqual(path, redact(path))

    def test_osv_mapping(self):
        for name in ("next", "react", "vite", "n8n"):
            self.assertEqual({"ecosystem": "npm", "name": name}, osv_package({"kind": "npm", "product": name}))
        self.assertEqual({"ecosystem": "WordPress:Core", "name": "wordpress"}, osv_package({"kind": "wordpress-core", "product": "wordpress"}))
        self.assertEqual({"ecosystem": "WordPress:Plugin", "name": "example-forms"}, osv_package({"kind": "wordpress-plugin", "product": "example-forms"}))
        self.assertEqual({"ecosystem": "Packagist", "name": "drupal/core"}, osv_package({"kind": "packagist", "product": "drupal"}))
        self.assertIsNone(osv_package({"kind": "runtime", "product": "php"}))

    def test_apex_public_private_and_exception_suffixes(self):
        psl = SuffixList()
        for host, apex in [("www.example.com.au", "example.com.au"), ("app.example.co.uk", "example.co.uk"),
                           ("demo.pages.dev", "demo.pages.dev"), ("www.city.kawasaki.jp", "city.kawasaki.jp"),
                           ("com", None)]:
            self.assertEqual(apex, psl.apex(host))


if __name__ == "__main__":
    unittest.main()
