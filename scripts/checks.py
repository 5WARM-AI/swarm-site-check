"""Evidence-led checks. Findings are candidates until the independent review accepts them."""
import datetime as dt
import http.client
import json
import re
import ssl
from urllib.parse import urljoin, urlsplit

from network import CheckError, error_code, service_json
from parsers import Page, SuffixList, osv_package, redact, safe_url, secrets, version_facts
from guidance import FIREBASE_STEPS, SUPABASE_STEPS, with_guidance
from vibe import client_gates, firebase_config, noindex_marker, platform_hints, preview_posture, source_map, supabase_config

RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
TAKEOVER_SUFFIXES = ("github.io", "herokudns.com", "herokuapp.com", "azurewebsites.net",
                     "cloudapp.net", "s3.amazonaws.com", "readthedocs.io", "surge.sh", "netlify.app")


class Evidence:
    def __init__(self):
        self.facts, self.candidates, self.versions, self.coverage = [], [], [], []
        self.platforms = {}

    def note_platforms(self, site, source, body="", headers=None, header_names=()):
        current = self.platforms.setdefault(site, {})
        for platform, hint in platform_hints(source, body, headers, header_names).items():
            if platform not in current:
                current[platform] = self.fact(site, source, platform + " hint: " + hint)
        for index, row in enumerate(self.candidates):
            if row["site"] == site:
                row["evidence"].extend(ref for ref in current.values() if ref not in row["evidence"])
                self.candidates[index] = with_guidance(row, current)

    def fact(self, site, source, line):
        item = {"id": "E%05d" % (len(self.facts) + 1), "site": site,
                "source": safe_url(source), "line": redact(str(line))}
        self.facts.append(item)
        return item["id"]

    def finding(self, site, code, severity, finding, evidence, fix, owner="your developer"):
        evidence.extend(ref for ref in self.platforms.get(site, {}).values() if ref not in evidence)
        self.candidates.append(with_guidance({"id": "F%05d" % (len(self.candidates) + 1), "site": site, "code": code,
                                "severity": severity, "finding": finding, "evidence": evidence,
                                "fix": fix, "owner": owner}, self.platforms.get(site, {})))

    def inspect_content(self, site, source, body, is_html, headers=None):
        self.note_platforms(site, source, body, headers)
        versions, markers = version_facts(body, source, is_html, headers)
        for item in versions:
            ref = self.fact(site, source, item["product"] + " " + item["version"] + "; " + item["evidence"] + "; " + item["confidence"])
            previous = next((x for x in self.versions if x["site"] == site and x["kind"] == item["kind"] and
                             x["product"] == item["product"] and x["version"] == item["version"]), None)
            if previous:
                previous["evidence_ids"].append(ref)
                continue
            item.update({"site": site, "evidence_ids": [ref]})
            self.versions.append(item)
            self.finding(site, "version", "Info", item["product"] + " " + item["version"] + " publicly indicated", item["evidence_ids"],
                         "Confirm the installed version; review live advisory matches below. Asset query strings can be stale.")
        for marker in markers:
            self.fact(site, source, marker + " marker present; marker alone does not establish a version")
        found = secrets(body, source)
        firebase = firebase_config(body) if not is_html else []
        if not is_html and supabase_config(body, found):
            ref = self.fact(site, source, "bundle: Supabase project URL plus publishable/anon key; values omitted; permissions untested")
            self.finding(site, "supabase-rls", "Info", "Supabase public config: review Row Level Security", [ref], SUPABASE_STEPS)
        for config in firebase:
            ref = self.fact(site, source, "line %d: Firebase config object fields=%s; values omitted; Security Rules untested" %
                            (config["line"], ", ".join(config["fields"])))
            self.finding(site, "firebase-rules", "Info", "Firebase public config: review Security Rules", [ref], FIREBASE_STEPS)
        js = "\n".join(Page(body).inline_scripts) if is_html else body
        for gate in client_gates(js):
            ref = self.fact(site, source, "inline-JS " * is_html + "line %d: %s; %sserver-request marker=%s; backend authorization untested" %
                            (gate["line"], gate["pattern"], "literal length=%d; " % gate["length"] if "length" in gate else "", gate["server_request_marker"]))
            self.finding(site, "client-gate", "Info" if gate["server_request_marker"] else "Low",
                         "Possible client-side-only password/auth gate", [ref],
                         "Have your developer verify authorization on the server for every protected request. Browser password comparisons and storage auth flags are user-controlled. "
                         "A server-request marker may belong to unrelated code; its presence or absence in these bounded sources does not establish backend protection.")
        for item in found:
            firebase_key = item["type"] == "Google API key" and any(a <= item["offset"] < b for a, b in (c["key_span"] for c in firebase))
            key_type = "Firebase API key (public)" if firebase_key else item["type"]
            line = "line %d: %s; length=%d" % (item["line"], key_type, item["length"])
            if "role" in item:
                line += "; JWT role=" + item["role"] + " (unverified claim)"
            if "path" in item:
                line += "; " + item["path"]
            ref = self.fact(site, source, line)
            public = firebase_key or item["type"] == "Supabase publishable (public)" or (item["type"] == "JWT" and item.get("role") == "anon")
            if public:
                severity, title, fix = "Info", "Public client key", "Expected in browser code. Confirm its intended client use; your developer should review Row Level Security or Firebase Security Rules as applicable. This check does not test permissions."
            elif item["type"] == "client-side password hash":
                severity, title, fix = "Low", "Client-side password hash exposed", "Enforce access on the server or Cloudflare Access. A browser gate alone cannot protect data."
            elif item["type"] == "n8n webhook URL":
                severity, title, fix = "Low", "Public n8n webhook URL", "Review intended exposure and require server-side authorization where needed. Retire stale demos."
            else:
                severity, title, fix = "High", "Potential exposed " + item["type"], "Confirm the key type with its owner, revoke/rotate secret credentials, and move them to server-side storage. Do not test the credential."
            self.finding(site, "public-key" if public else "secret", severity, title, [ref], fix)


def check_headers(ev, site, response, only=None):
    headers = response["headers"]
    ref = ev.fact(site, response["url"], "HTTP status=" + str(response["status"]) + "; complete header names=" + ", ".join(response["header_names"]))
    for name, values in headers.items():
        for value in values:
            ev.fact(site, response["url"], name + ": " + value)
    csp = "; ".join(headers.get("content-security-policy", []))
    xfo = "; ".join(headers.get("x-frame-options", [])).upper()
    ancestors = re.findall(r"(?i)(?:^|;)\s*frame-ancestors\s+([^;]+)", csp)
    frame_policy = any(value.strip() and value.strip() != "*" for value in ancestors)
    checks = [
        ("hsts", "Strict-Transport-Security", bool(re.search(r"(?i)max-age\s*=\s*[1-9]\d*", ";".join(headers.get("strict-transport-security", [])))), "Low", "Enable HSTS after confirming all intended HTTPS routes work; review subdomains before includeSubDomains."),
        ("csp", "Content-Security-Policy", bool(csp.strip()), "Low", "Deploy a tested Content-Security-Policy; start with report-only while resolving required sources."),
        ("frame", "frame protection", frame_policy or xfo in ("DENY", "SAMEORIGIN"), "Low", "Set CSP frame-ancestors to intended parents, or X-Frame-Options: DENY/SAMEORIGIN."),
        ("nosniff", "X-Content-Type-Options: nosniff", "nosniff" in [x.lower() for x in headers.get("x-content-type-options", [])], "Low", "Set X-Content-Type-Options: nosniff."),
        ("referrer", "Referrer-Policy", bool(headers.get("referrer-policy")), "Low", "Choose a Referrer-Policy such as strict-origin-when-cross-origin.")]
    for code, label, present, severity, fix in checks:
        if not present and (only is None or only == code):
            ev.finding(site, code, severity, label + " absent or ineffective on this response", [ref], fix)
    for cookie in response["cookies"] if only in (None, "cookie") else []:
        cref = ev.fact(site, response["url"], "Set-Cookie: " + cookie["name"] + "=[value omitted]; " +
                       "; ".join(k + "=" + str(cookie[k]) for k in ("secure", "httponly", "samesite")))
        missing = [k for k in ("secure", "httponly", "samesite") if not cookie[k]]
        if missing:
            ev.finding(site, "cookie", "Medium", "Cookie flags need review: " + ", ".join(missing), [cref],
                       "Confirm cookie purpose. Set Secure; use HttpOnly for server/session cookies and an appropriate SameSite policy. JavaScript-readable cookies can have a legitimate purpose.", "your developer or host")
    if only in (None, "disclosure") and (headers.get("x-powered-by") or any(re.search(r"/\d", v) for v in headers.get("server", []))):
        dref = ev.fact(site, response["url"], "public disclosure: " + "; ".join(headers.get("server", []) + headers.get("x-powered-by", [])))
        ev.finding(site, "disclosure", "Info", "Server or framework disclosed", [dref], "Suppress unnecessary server/framework version headers. Keep the underlying packages patched.", "your developer or host")


def check_tls(ev, site, response):
    tls = response.get("tls")
    if not tls:
        return
    ref = ev.fact(site, response["url"], "TLS issuer=" + tls["issuer"] + "; expiry=" + str(tls["expiry"]) +
                  "; protocol=" + str(tls["protocol"]) + "; chain_verified=True; chain=" + str(tls["chain"]))
    try:
        days = (ssl.cert_time_to_seconds(tls["expiry"]) - dt.datetime.now(dt.timezone.utc).timestamp()) / 86400
        if days < 21:
            ev.finding(site, "tls-expiry", "Medium", "TLS certificate expires in %.1f days" % days, [ref],
                       "Verify certificate auto-renewal and renew before expiry.", "your host")
    except (ValueError, TypeError):
        ev.coverage.append({"site": site, "check": "TLS expiry", "status": "could not parse certificate expiry"})


def check_mail(ev, transport, apex, only=None):
    for kind, name, prefix in [("SPF", apex, "v=spf1"), ("DMARC", "_dmarc." + apex, "v=dmarc1")]:
        if only is not None and only != "mail-" + kind.lower():
            continue
        data = transport.dns(name, "TXT")
        if data.get("error") or data.get("Status") not in (0, 3):
            ev.coverage.append({"site": apex, "check": kind, "status": "DNS unavailable; absence not established"})
            continue
        txts = ["".join(re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', x.get("data", ""))) or x.get("data", "")
                for x in data.get("Answer", []) if x.get("type") == 16]
        policies = [x for x in txts if x.lower().startswith(prefix)]
        # Retain policy posture only, no unrelated verification TXT tokens.
        posture = "; ".join(re.findall(r"(?i)(?:v=spf1|v=DMARC1|[~?+-]all|p=(?:none|quarantine|reject))\b", " ".join(policies)))
        ref = ev.fact(apex, "dns://" + name, "TXT " + name + ": " + kind + " record count=" + str(len(policies)) + "; " + posture)
        if not policies:
            ev.finding(apex, "mail-" + kind.lower(), "Low", "No apex " + kind + " policy observed", [ref],
                       "Confirm whether this domain sends mail. Publish validated mail policies, or document a no-mail policy.", "you in your DNS dashboard")
        elif len(policies) > 1:
            ev.finding(apex, "mail-" + kind.lower(), "Medium", "Multiple " + kind + " records", [ref],
                       "Consolidate into one valid policy with your mail provider.", "you in your DNS dashboard")
        elif (kind == "DMARC" and re.search(r"(?i)\bp=none\b", policies[0])) or (kind == "SPF" and "+all" in policies[0]):
            ev.finding(apex, "mail-" + kind.lower(), "Low", kind + " policy needs enforcement review", [ref],
                       "Validate legitimate senders before tightening the policy.", "you in your DNS dashboard")


def collect(transport):
    ev, host_checked, apex_checked = Evidence(), set(), set()
    suffixes = SuffixList()
    for url in transport.urls:
        host = urlsplit(url).hostname
        site = host + (urlsplit(url).path if urlsplit(url).path != "/" else "")
        try:
            response, body, location = transport.request(url, "page")
            ev.note_platforms(site, url, body, response["headers"], response["header_names"])
            check_headers(ev, site, response)
            check_tls(ev, site, response)
            is_html = "html" in ";".join(response["headers"].get("content-type", [])) or bool(re.search(r"(?i)<(?:html|!doctype|head)\b", body[:500]))
            ev.inspect_content(site, url, body, is_html, response["headers"])
            if response["body_truncated"] or response.get("body_skipped"):
                ev.coverage.append({"site": site, "check": "page body", "status": "body incomplete (2 MiB limit or unsupported encoding)"})
            if 300 <= response["status"] < 400:
                ev.coverage.append({"site": site, "check": "page", "status": "redirect recorded; target not fetched"})
            if response["status"] in (404, 410, 530) or "error code: 1033" in body.lower():
                ref = ev.fact(site, url, "HTTP " + str(response["status"]) + ("; error code: 1033" if "error code: 1033" in body.lower() else ""))
                ev.finding(site, "stale", "Info", "Check stale site or unavailable route", [ref],
                           "Confirm whether the service is still needed. Repair or remove unused routes/DNS. A failed route alone does not establish takeover risk.", "your host or you in your DNS dashboard")
            if is_html:
                page = Page(body)
                posture = preview_posture(url, body, response["headers"], response["status"])
                if posture:
                    ref = ev.fact(site, url, "HTTP 200; listed " + posture + " URL; login/password marker absent; noindex=" + str(noindex_marker(body, response["headers"])) + "; backend access untested")
                    ev.finding(site, "public-ui", "Info", "Check intended visibility of " + posture + " page", [ref],
                               "Review whether this page should be public. A loaded shell does not establish access to backend data. Use server-side access control for private content; noindex alone is not access control.")
                linked = []
                for href in page.links:
                    target = urljoin(url, href)
                    if urlsplit(target).netloc == host and re.search(r"(?i)/(?:admin|dashboard)(?:/|$)", urlsplit(target).path):
                        linked.append(safe_url(target))
                for target in sorted(set(linked))[:10]:
                    ev.fact(site, url, "linked admin-looking URL=" + target + "; not fetched; add explicitly to confirmed scope if needed")
                bundles = []
                for src in page.scripts:
                    target = urljoin(url, src)
                    u = urlsplit(target)
                    if (u.scheme, u.netloc) == ("https", host) and not u.fragment and not u.username and not u.password and re.search(r"\.(?:m?js)$", u.path, re.I) and not secrets(target, "/"):
                        if target not in bundles:
                            bundles.append(target)
                for bundle in bundles[:max(0, 2 - transport.bundle_used.get(host, 0))]:
                    try:
                        bresp, js, _ = transport.request(bundle, "bundle", parent=url, discovered=bundles)
                        ev.fact(site, bundle, "bundle HTTP status=" + str(bresp["status"]))
                        if bresp["status"] == 200:
                            ev.inspect_content(site, bundle, js, False)
                            target, status = source_map(js, bundle)
                            if target and not bresp["body_truncated"] and not bresp.get("body_skipped"):
                                directive = ev.fact(site, bundle, "sourceMappingURL=" + safe_url(target) + "; explicit bundle directive")
                                try:
                                    mresp, _, _ = transport.request(target, "source-map", parent=bundle)
                                    mref = ev.fact(site, target, "source-map HEAD status=" + str(mresp["status"]) + "; contents never downloaded")
                                    if mresp["status"] == 200:
                                        ev.finding(site, "source-map", "Low", "Public source-map URL answers HEAD", [directive, mref],
                                                   "Review build settings and decide whether public source maps are intended. Use private error-monitoring uploads where appropriate; remove public maps through your normal build/deploy process. HEAD does not prove map contents or sensitive source disclosure.")
                                    else:
                                        ev.coverage.append({"site": site, "check": "source map", "status": "HEAD did not return 200; redirects not followed, contents untested"})
                                except (OSError, ValueError, CheckError, http.client.HTTPException) as exc:
                                    ev.coverage.append({"site": site, "check": "source map", "status": error_code(exc)})
                            elif target or "no unambiguous" not in status:
                                ev.coverage.append({"site": site, "check": "source map", "status": "incomplete bundle; not tested" if target else status})
                        if bresp["body_truncated"] or bresp.get("body_skipped"):
                            ev.coverage.append({"site": site, "check": "bundle", "status": "body incomplete (2 MiB limit or unsupported encoding)"})
                    except (OSError, ValueError, CheckError, http.client.HTTPException) as exc:
                        ev.coverage.append({"site": site, "check": "bundle", "status": error_code(exc)})
            del body
        except (OSError, ValueError, CheckError, http.client.HTTPException) as exc:
            ref = ev.fact(site, url, "HTTPS page: " + error_code(exc))
            ev.coverage.append({"site": site, "check": "HTTPS page", "status": error_code(exc)})
            if isinstance(exc, ssl.SSLCertVerificationError):
                ev.finding(site, "tls-trust", "High", "TLS certificate verification failed", [ref],
                           "Check hostname, expiry and the served certificate chain against your host configuration.", "your host")
        if host in host_checked:
            continue
        if site != host and site in ev.platforms:
            ev.platforms.setdefault(host, {}).update(ev.platforms[site])
        host_checked.add(host)
        try:
            response, _, location = transport.request("http://" + host + "/", "http")
            redirect = 300 <= response["status"] < 400 and urlsplit(urljoin("http://" + host + "/", location)).scheme == "https"
            ref = ev.fact(host, "http://" + host + "/", "HTTP status=" + str(response["status"]) + "; redirects_to_https=" + str(redirect))
            if not redirect:
                ev.finding(host, "http", "Medium" if response["status"] == 200 else "Low", "Plain HTTP does not redirect to HTTPS", [ref],
                           "Enable an HTTP-to-HTTPS redirect for this hostname, such as Always Use HTTPS in Cloudflare.", "you in your CDN dashboard or your host")
        except (OSError, ValueError, CheckError, http.client.HTTPException) as exc:
            ev.coverage.append({"site": host, "check": "plain HTTP", "status": error_code(exc)})
        for version in ("1.0", "1.1"):
            result = transport.legacy_tls(host, version)
            ref = ev.fact(host, "tls://" + host, "TLS " + version + ": " + result)
            if result.startswith("ACCEPTED"):
                ev.finding(host, "old-tls", "Low", "TLS " + version + " accepted", [ref],
                           "Set minimum TLS to 1.2 after reviewing client needs. Provider-owned domains may require a custom domain.", "you in your CDN dashboard or your host")
            elif result.startswith("not tested"):
                ev.coverage.append({"site": host, "check": "TLS " + version, "status": result})
        apex = suffixes.apex(host)
        if apex and apex not in apex_checked:
            apex_checked.add(apex)
            check_mail(ev, transport, apex)
        cname_answers = transport.dns(host, "A").get("Answer", [])
        for record in cname_answers:
            target = record.get("data", "").rstrip(".").lower()
            if record.get("type") == 5 and any(target == s or target.endswith("." + s) for s in TAKEOVER_SUFFIXES):
                answers = [transport.dns(target, kind) for kind in ("A", "AAAA")]
                gone = all(x.get("Status") in (0, 3) and not any(y.get("type") in (1, 28) for y in x.get("Answer", [])) for x in answers)
                if gone:
                    ref = ev.fact(host, "dns://" + host, "CNAME " + target + "; target has no A/AAAA answer")
                    ev.finding(host, "dns-check", "Low", "Check possible stale provider CNAME", [ref],
                               "Confirm the resource in your provider account, then repair or remove stale DNS. DNS absence does not prove claimability. Never attempt to claim it.", "you in your DNS/provider dashboard")
    return ev


def advisory_severity(data):
    value = str(data.get("database_specific", {}).get("severity", "")).title()
    if value in RANK:
        return value
    # Do not guess a CVSS score from a vector or infer severity from prose.
    for severity in data.get("severity", []):
        try:
            score = float(severity["score"])
            return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"
        except (ValueError, TypeError, KeyError):
            pass
    return "Info"


def match_osv(ev, transport):
    groups = {}
    for item in ev.versions:
        package = osv_package(item)
        if package:
            key = (package["ecosystem"], package["name"], item["version"])
            groups.setdefault(key, []).append(item)
        else:
            ev.coverage.append({"site": item["site"], "check": "OSV " + item["product"] + " " + item["version"],
                                "status": "No reliable OSV package mapping for this server/runtime. Check the vendor security advisories; distribution backports may differ."})
    if not groups:
        return
    pending = [(key, {"package": {"ecosystem": key[0], "name": key[1]}, "version": key[2]}) for key in sorted(groups)]
    matches, incomplete = {key: set() for key in groups}, set()
    for page in range(4):
        if not pending:
            break
        try:
            transport.calls.append({"type": "OSV querybatch POST", "package_count": len(pending)})
            result = service_json("api.osv.dev", "/v1/querybatch", {"queries": [q for _, q in pending]})
            rows = result["results"]
            if len(rows) != len(pending):
                raise CheckError("OSV result length mismatch")
        except (OSError, ValueError, KeyError, TypeError, CheckError, http.client.HTTPException):
            incomplete.update(k for k, _ in pending)
            break
        more = []
        for (key, query), row in zip(pending, rows):
            if row.get("error"):
                incomplete.add(key)
                continue
            matches[key].update(x["id"] for x in row.get("vulns", []) if isinstance(x.get("id"), str) and re.fullmatch(r"[A-Za-z0-9:_.-]{1,150}", x["id"]))
            if row.get("next_page_token"):
                more.append((key, dict(query, page_token=row["next_page_token"])))
        pending = more
    if pending:
        incomplete.update(k for k, _ in pending)
    details = {}
    ids = sorted(set().union(*matches.values()))
    if len(ids) > 100:
        ev.coverage.append({"site": "all matched packages", "check": "OSV advisory details",
                            "status": "100-advisory detail limit reached; remaining IDs are retained with severity unrated."})
    for advisory in ids[:100]:
        try:
            transport.calls.append({"type": "OSV advisory GET", "id": advisory})
            details[advisory] = service_json("api.osv.dev", "/v1/vulns/" + advisory)
        except (OSError, ValueError, CheckError, http.client.HTTPException):
            details[advisory] = {}
    for key, items in groups.items():
        for item in items:
            status = "query incomplete/unavailable" if key in incomplete else "no matches returned" if not matches[key] else str(len(matches[key])) + " advisory IDs returned"
            if key[0].startswith("WordPress"):
                status += "; WordPress coverage is not assured, including plugins/themes. Also check https://wpscan.com/ and https://www.wordfence.com/threat-intel/vulnerabilities/ with the actual installed version."
            ev.coverage.append({"site": item["site"], "check": "OSV " + ":".join(key), "status": status})
            for advisory in sorted(matches[key]):
                data = details.get(advisory, {})
                if data.get("withdrawn"):
                    continue
                severity = advisory_severity(data)
                fixed = set()
                for affected in data.get("affected", []):
                    if affected.get("package", {}).get("name") == key[1] and affected.get("package", {}).get("ecosystem") == key[0]:
                        for interval in affected.get("ranges", []):
                            for event in interval.get("events", []):
                                v = event.get("fixed", "")
                                if re.fullmatch(r"[A-Za-z0-9.+_-]{1,60}", v):
                                    fixed.add(v)
                ref = ev.fact(item["site"], "https://osv.dev/vulnerability/" + advisory,
                              "OSV querybatch matched " + key[0] + ":" + key[1] + "@" + key[2] + "; advisory=" + advisory +
                              "; severity=" + severity + ("; details unavailable or severity unrated" if not data or severity == "Info" else "") +
                              "; fixed release lines=" + (", ".join(sorted(fixed)) or "not supplied"))
                ev.finding(item["site"], "osv", severity, key[1] + " " + key[2] + " — " + advisory,
                           item["evidence_ids"] + [ref], "Confirm installed package and affected features. Back up, upgrade to a supported patched release, test and deploy. " +
                           ("OSV fixed release lines: " + ", ".join(sorted(fixed)) + ". Choose the appropriate supported branch." if fixed else "Read the linked advisory for affected ranges and fixes."))
