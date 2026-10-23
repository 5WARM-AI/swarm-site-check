"""One reviewed finding, one previously confirmed host, only its passive check."""
import http.client
import re
from urllib.parse import urljoin, urlsplit

from checks import Evidence, check_headers, check_mail
from guided import accepted_item
from network import CheckError, OWNERSHIP, Transport, error_code, normalize_url, scope_digest, validate_scope
from parsers import Page, SuffixList, redact, secrets
from vibe import firebase_config

HEADER_CHECKS = {"hsts", "csp", "frame", "nosniff", "referrer", "cookie", "disclosure"}
SUPPORTED = HEADER_CHECKS | {"http", "old-tls", "mail-spf", "mail-dmarc", "public-key"}


def recheck(evidence, review, finding_id, url, confirmed_scope, ownership, deployed, transport_factory=Transport):
    data, row = accepted_item(evidence, review, finding_id)
    urls = validate_scope(data["scope"], confirmed_scope, ownership)
    target = normalize_url(url)
    host = urlsplit(target).hostname
    site = host + (urlsplit(target).path if urlsplit(target).path != "/" else "")
    code = row["code"]
    if code not in SUPPORTED:
        raise CheckError("This check has no isolated re-check recipe; ask your developer. No requests were sent.")
    matches_site = row["site"] == site
    if code in ("http", "old-tls"):
        matches_site = row["site"] == host
    if code in ("mail-spf", "mail-dmarc"):
        matches_site = row["site"] == SuffixList().apex(host)
    if target not in urls or not matches_site:
        raise CheckError("Re-check must use the selected finding's exact confirmed page/host.")
    facts = {x["id"]: x for x in data["facts"]}
    result = {"finding_id": finding_id, "check": code, "url": target,
              "before": {"finding": redact(row["finding"]), "evidence": [
                  {"source": facts[i]["source"], "line": redact(facts[i]["line"])} for i in row["evidence"]]},
              "after": "deploy, then re-check", "facts": [], "coverage": [], "network_calls": []}
    if deployed != "yes":
        return result
    scope = {"sites": [target], "sha256": scope_digest([target])}
    transport = transport_factory(scope, scope["sha256"], OWNERSHIP)
    ev = Evidence()
    try:
        if code in HEADER_CHECKS:
            response, _, _ = transport.request(target, "page")
            check_headers(ev, site, response, only=code)
            if response["status"] != 200:
                result["after"] = "inconclusive: page status changed or is not 200; no redirects followed"
            else:
                result["after"] = "still present" if ev.candidates else "finding no longer observed on this response"
        elif code == "http":
            response, _, location = transport.request("http://" + host + "/", "http")
            redirects = 300 <= response["status"] < 400 and urlsplit(urljoin("http://" + host + "/", location)).scheme == "https"
            ev.fact(host, "http://" + host + "/", "HTTP status=" + str(response["status"]) + "; redirects_to_https=" + str(redirects))
            result["after"] = "HTTPS redirect observed" if redirects else "still present: no HTTPS redirect observed"
        elif code == "old-tls":
            match = re.fullmatch(r"TLS (1\.0|1\.1) accepted", row["finding"])
            if not match:
                raise CheckError("The selected TLS protocol is not established by this finding.")
            value = transport.legacy_tls(host, match.group(1))
            ev.fact(host, "tls://" + host, "TLS " + match.group(1) + ": " + value)
            result["after"] = value
        elif code in ("mail-spf", "mail-dmarc"):
            check_mail(ev, transport, row["site"], only=code)
            result["after"] = "inconclusive: DNS unavailable" if ev.coverage else "still present" if ev.candidates else "finding no longer observed in this DNS answer"
        elif code == "public-key":
            response, body, _ = transport.request(target, "page")
            if response["status"] != 200:
                result["after"] = "inconclusive: page is not 200; no redirects followed"
            else:
                sources = [(target, body)]
                incomplete = bool(response["body_truncated"] or response.get("body_skipped"))
                bundles = []
                for src in Page(body).scripts:
                    bundle = urljoin(target, src)
                    u = urlsplit(bundle)
                    if (u.scheme, u.netloc) == (urlsplit(target).scheme, urlsplit(target).netloc) and re.search(r"\.m?js$", u.path) and not u.fragment and not u.username and not u.password and not secrets(bundle, "/"):
                        if bundle not in bundles:
                            bundles.append(bundle)
                for bundle in bundles[:2]:
                    resp, js, _ = transport.request(bundle, "bundle", parent=target, discovered=bundles)
                    incomplete |= resp["status"] != 200 or resp["body_truncated"] or bool(resp.get("body_skipped"))
                    if resp["status"] == 200:
                        sources.append((bundle, js))
                for source, text in sources:
                    configs = firebase_config(text)
                    for item in secrets(text, source):
                        firebase_key = item["type"] == "Google API key" and any(a <= item["offset"] < b for a, b in (x["key_span"] for x in configs))
                        if firebase_key or item["type"] == "Supabase publishable (public)" or (item["type"] == "JWT" and item.get("role") == "anon"):
                            ev.fact(site, source, "public client key type=" + ("Firebase API key" if firebase_key else item["type"]) + "; length=" + str(item["length"]) + "; permissions untested")
                result["after"] = "public client configuration still observed; permissions untested" if ev.facts else "public client configuration not observed in the inspected sources; permissions untested"
                if incomplete:
                    result["after"] = "inconclusive: incomplete page/bundle inspection; permissions untested"
    except (OSError, ValueError, CheckError, http.client.HTTPException) as exc:
        result["after"] = "inconclusive: " + error_code(exc)
    result.update(facts=ev.facts, coverage=ev.coverage, network_calls=transport.calls)
    return result
