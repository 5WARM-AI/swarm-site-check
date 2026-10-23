"""Fixed-purpose, consent-gated network transport. No subprocesses, retries or redirects."""
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import warnings
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from parsers import header_facts, safe_url, secrets
from vibe import source_map

UA = "SwarmSiteCheck/1.0 (+https://5warm.ai/guides/site-check/)"
OWNERSHIP = "these are sites I own or run"
TIMEOUT = 8
BODY_LIMIT = 2 * 1024 * 1024
SERVICE_LIMIT = 8 * 1024 * 1024


class CheckError(Exception):
    pass


def backend_host(host):
    return host in ("api.supabase.com", "firebase.googleapis.com", "firestore.googleapis.com", "firebasestorage.googleapis.com", "identitytoolkit.googleapis.com") or any(
        host == suffix or host.endswith("." + suffix) for suffix in
        ("supabase.co", "supabase.in", "firebaseio.com", "firebasedatabase.app"))


def normalize_url(value):
    if len(value) > 2048 or any(ord(c) < 33 for c in value) or "\\" in value:
        raise CheckError("Invalid site URL; use a public hostname and an optional explicit path.")
    u = urlsplit(value if "://" in value else "https://" + value)
    try:
        port = u.port
        host = (u.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    except (ValueError, UnicodeError):
        raise CheckError("Invalid public hostname.") from None
    if u.scheme not in ("http", "https") or port not in (None, 80 if u.scheme == "http" else 443):
        raise CheckError("Only ordinary HTTP/HTTPS default ports are allowed.")
    if u.username or u.password or u.query or u.fragment:
        raise CheckError("Remove credentials, query parameters and fragments from scope URLs.")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
        raise CheckError("Scope requires public DNS names; IP literals and local names are refused.")
    if host.endswith((".localhost", ".local", ".internal", ".invalid", ".test")):
        raise CheckError("Local/test names are refused by the live transport.")
    if backend_host(host):
        raise CheckError("Supabase/Firebase backend endpoints cannot be checked.")
    path = u.path or "/"
    decoded = unquote(path)
    if any(ord(c) < 32 for c in decoded) or any(p in (".", "..") for p in decoded.split("/")):
        raise CheckError("Unsafe path in scope URL.")
    if secrets(path, "/") or "/webhook/" in decoded.lower():
        raise CheckError("Credential-bearing or webhook paths cannot be checked.")
    # Plain HTTP is always checked separately; the page request is HTTPS.
    return urlunsplit(("https", host, quote(decoded, safe="/~-._"), "", ""))


def scope_digest(urls):
    return hashlib.sha256(json.dumps(urls, separators=(",", ":")).encode()).hexdigest()


def validate_scope(scope, digest, ownership):
    urls = scope.get("sites", [])
    if not isinstance(urls, list) or not urls or len(urls) > 200:
        raise CheckError("Scope must contain 1–200 explicitly listed URLs.")
    if urls != sorted(set(normalize_url(u) for u in urls)):
        raise CheckError("Scope changed or is not canonical; display and confirm a new scope.")
    if ownership != OWNERSHIP or scope_digest(urls) != digest or scope.get("sha256") != digest:
        raise CheckError("No matching ownership confirmation. No network requests were sent.")
    return urls


def error_code(exc):
    # Never stringify network exceptions: they can contain server-controlled strings.
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "certificate verification failed"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        return "TLS handshake failed"
    if isinstance(exc, CheckError):
        return str(exc)  # CheckError messages are fixed strings, never server/input text.
    return type(exc).__name__


def bounded_body(response, limit, deadline):
    data = bytearray()
    while len(data) <= limit:
        if time.monotonic() > deadline:
            raise TimeoutError()
        block = response.read1(min(65536, limit + 1 - len(data)))
        if not block:
            break
        data.extend(block)
    return bytes(data[:limit]), len(data) > limit


def service_connection(address, timeout=TIMEOUT, source_address=None):
    """Bound the OS resolver too; the resolver worker is a daemon if libc stalls."""
    host, port = address
    outcome = []

    def resolve():
        try:
            outcome.append(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError:
            outcome.append(None)

    worker = threading.Thread(target=resolve, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise TimeoutError()
    if not outcome or not outcome[0]:
        raise CheckError("Service DNS unavailable")
    options = sorted(outcome[0], key=lambda x: x[0] != socket.AF_INET)
    family, socktype, proto, _, addr = options[0]
    sock = socket.socket(family, socktype, proto)
    sock.settimeout(timeout)
    try:
        sock.connect(addr)
        return sock
    except OSError:
        sock.close()
        raise


def certificate_chain(sock):
    """Use the public API where available; CPython's older API is an optional fallback."""
    from parsers import redact
    try:
        if hasattr(sock, "get_verified_chain"):
            return ["sha256=" + hashlib.sha256(der).hexdigest() for der in sock.get_verified_chain()]
        internal = getattr(sock, "_sslobj", None)
        if internal and hasattr(internal, "get_verified_chain"):
            chain = []
            for cert in internal.get_verified_chain():
                info = cert.get_info()
                fields = []
                for label in ("subject", "issuer"):
                    names = [val for rdn in info.get(label, ()) for key, val in rdn if key in ("organizationName", "commonName")]
                    fields.append(label + "=" + redact(" / ".join(names))[:300])
                chain.append("; ".join(fields))
            return chain
    except (AttributeError, TypeError, ValueError, ssl.SSLError):
        pass
    return "validated against local CA store; chain enumeration unavailable on this Python"


def service_json(host, path, payload=None):
    # These services are fixed constants, never supplied by a site or an advisory URL.
    if not ((host == "cloudflare-dns.com" and path.startswith("/dns-query?")) or
            (host == "api.osv.dev" and (path == "/v1/querybatch" or re.fullmatch(r"/v1/vulns/[A-Za-z0-9:_.-]+", path)))):
        raise CheckError("Service endpoint refused")
    conn = http.client.HTTPSConnection(host, timeout=TIMEOUT, context=ssl.create_default_context())
    conn._create_connection = service_connection
    headers = {"User-Agent": UA, "Accept": "application/dns-json" if host == "cloudflare-dns.com" else "application/json",
               "Accept-Encoding": "identity"}
    body = json.dumps(payload).encode() if payload is not None else None
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        conn.request("POST" if body else "GET", path, body=body, headers=headers)
        response = conn.getresponse()
        if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
            raise CheckError("Service response unavailable")
        raw, truncated = bounded_body(response, SERVICE_LIMIT, time.monotonic() + TIMEOUT)
        if truncated:
            raise CheckError("Service response exceeded limit")
        return json.loads(raw)
    finally:
        conn.close()


class Transport:
    def __init__(self, scope, digest, ownership):
        self.urls = validate_scope(scope, digest, ownership)
        self.hosts = {urlsplit(u).hostname for u in self.urls}
        self.calls, self.dns_cache, self.addresses = [], {}, {}
        self.page_used, self.http_used, self.bundle_used, self.legacy_used = set(), set(), {}, set()
        self.asset_used, self.map_targets, self.map_used = {}, {}, set()
        self.last_site_request = 0

    def pause(self):
        time.sleep(max(0, 0.15 - (time.monotonic() - self.last_site_request)))
        self.last_site_request = time.monotonic()

    def dns(self, name, kind):
        name = name.rstrip(".").lower()
        if kind not in ("A", "AAAA", "TXT") or not re.fullmatch(r"[a-z0-9_.-]{1,253}", name):
            raise CheckError("DNS request refused")
        key = (name, kind)
        if key not in self.dns_cache:
            self.calls.append({"type": "DoH " + kind, "name": name})
            try:
                value = service_json("cloudflare-dns.com", "/dns-query?name=" + quote(name) + "&type=" + kind)
                self.dns_cache[key] = value
            except (OSError, ValueError, CheckError, http.client.HTTPException) as exc:
                self.dns_cache[key] = {"error": error_code(exc)}
        return self.dns_cache[key]

    def resolve(self, host):
        if host not in self.hosts:
            raise CheckError("Unconfirmed host")
        if host not in self.addresses:
            answers = self.dns(host, "A").get("Answer", []) + self.dns(host, "AAAA").get("Answer", [])
            ips = [x.get("data", "") for x in answers if x.get("type") in (1, 28)]
            try:
                if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
                    raise CheckError("Public address unavailable")
            except ValueError:
                raise CheckError("Invalid public address") from None
            self.addresses[host] = sorted(set(ips), key=lambda ip: (":" in ip, ip))
        return self.addresses[host][0]  # Pin the checked IP. No resolver retry / DNS rebinding.

    def request(self, url, purpose, parent=None, discovered=()):
        u = urlsplit(url)
        host = u.hostname
        if host not in self.hosts or u.username or u.password or u.fragment or u.port not in (None, 80, 443):
            raise CheckError("Unconfirmed request")
        if backend_host(host) or secrets(unquote(url), "/") or "/webhook/" in unquote(u.path).lower() or re.search(r"(?:^|&)(?:api[_-]?key|key|token|access_token|authorization|signature|secret)=", u.query, re.I):
            raise CheckError("Backend or credential-bearing request refused")
        if purpose == "page":
            if url not in self.urls or url in self.page_used or u.scheme != "https":
                raise CheckError("Page budget/scope exceeded")
            self.page_used.add(url)
        elif purpose == "http":
            if host in self.http_used or u.scheme != "http" or u.path != "/" or u.query:
                raise CheckError("HTTP budget exceeded")
            self.http_used.add(host)
        elif purpose == "bundle":
            if parent not in self.page_used or url not in discovered or u.scheme != "https" or not re.search(r"\.(?:m?js)$", u.path, re.I) or (u.scheme, u.netloc) != (urlsplit(parent).scheme, urlsplit(parent).netloc):
                raise CheckError("Bundle was not in the confirmed page or is cross-origin")
            if self.bundle_used.get(host, 0) >= 2:
                raise CheckError("Bundle budget exceeded")
            if self.asset_used.get(host, 0) >= 2:
                raise CheckError("Shared bundle/source-map asset budget exceeded")
            self.bundle_used[host] = self.bundle_used.get(host, 0) + 1
            self.asset_used[host] = self.asset_used.get(host, 0) + 1
        elif purpose == "source-map":
            if self.map_targets.get(parent) != url or url in self.map_used or u.scheme != "https" or u.query:
                raise CheckError("Source map lacks a fetched bundle directive or was already checked")
            if self.asset_used.get(host, 0) >= 2:
                raise CheckError("Shared bundle/source-map asset budget exceeded")
            self.asset_used[host] = self.asset_used.get(host, 0) + 1
            self.map_used.add(url)
        else:
            raise CheckError("Request purpose refused")
        ip = self.resolve(host)
        self.pause()
        method = "HEAD" if purpose == "source-map" else "GET"
        self.calls.append({"type": method + " " + purpose, "url": safe_url(url)})
        conn = http.client.HTTPConnection(host, timeout=TIMEOUT)
        sock = None
        try:
            sock = socket.create_connection((ip, 443 if u.scheme == "https" else 80), TIMEOUT)
            tls = None
            if u.scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                cert = sock.getpeercert()
                issuer = [val for rdn in cert.get("issuer", ()) for key, val in rdn if key in ("organizationName", "commonName")]
                from parsers import redact
                tls = {"issuer": redact(" / ".join(issuer))[:300], "expiry": cert.get("notAfter"),
                       "protocol": sock.version(), "chain_verified": True,
                       "chain": certificate_chain(sock)}
            conn.sock = sock
            path = urlunsplit(("", "", u.path or "/", u.query, ""))
            conn.request(method, path, headers={"User-Agent": UA, "Accept-Encoding": "identity",
                                              "Accept": "*/*", "Connection": "close"})
            response = conn.getresponse()
            facts = header_facts(response.getheaders())
            facts.update({"status": response.status, "url": safe_url(url), "tls": tls})
            # No body for redirects: do not follow login links, redirects, or send any cookies.
            if 300 <= response.status < 400 or purpose in ("http", "source-map"):
                body, truncated = b"", False
            elif response.getheader("Content-Encoding", "identity") != "identity":
                body, truncated = b"", False
                facts["body_skipped"] = "server ignored identity encoding"
            else:
                body, truncated = bounded_body(response, BODY_LIMIT, time.monotonic() + TIMEOUT)
            facts["body_truncated"] = truncated
            # Keep the original Location in memory for classifying scheme/login only.
            location = response.getheader("Location", "")
            text = body.decode("utf-8", "replace")
            if purpose == "bundle" and response.status == 200 and not truncated and not facts.get("body_skipped"):
                target, reason = source_map(text, url)
                if target:
                    self.map_targets[url] = target
                facts["source_map_status"] = reason
            return facts, text, location
        finally:
            conn.close()
            if sock:
                sock.close()

    def legacy_tls(self, host, version):
        key = (host, version)
        if host not in self.hosts or key in self.legacy_used or version not in ("1.0", "1.1"):
            raise CheckError("TLS scope/budget exceeded")
        self.legacy_used.add(key)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE  # Protocol-only probe, never used to establish cert trust.
                ctx.set_ciphers("ALL:@SECLEVEL=0")
                protocol = ssl.TLSVersion.TLSv1 if version == "1.0" else ssl.TLSVersion.TLSv1_1
                ctx.minimum_version = ctx.maximum_version = protocol
            ip = self.resolve(host)
            self.pause()
            self.calls.append({"type": "TLS " + version, "host": host})
            with socket.create_connection((ip, 443), TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as conn:
                    negotiated = conn.version()
                    return "ACCEPTED " + negotiated if negotiated in ("TLSv1", "TLSv1.1") else "inconclusive"
        except ssl.SSLError as exc:
            reason = getattr(exc, "reason", "")
            if reason in ("TLSV1_ALERT_PROTOCOL_VERSION", "UNSUPPORTED_PROTOCOL"):
                # UNSUPPORTED_PROTOCOL may originate locally, so only the peer alert is conclusive.
                return "rejected (peer protocol_version alert)" if reason == "TLSV1_ALERT_PROTOCOL_VERSION" else "not tested on this machine"
            return "not tested on this machine / inconclusive handshake"
        except (OSError, ValueError, AttributeError, CheckError):
            return "not tested on this machine / connection unavailable"
