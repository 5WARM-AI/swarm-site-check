"""Pure, bounded parsers. Source bodies stay in memory; only facts leave these functions."""
import base64
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, unquote, urljoin, urlsplit, urlunsplit

VERSION = r"\d{1,4}\.\d{1,4}(?:\.\d{1,4})?(?:-[a-zA-Z0-9.-]{1,40})?"
SECRET_PATTERNS = [
    ("private key", r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|$)"),
    ("Anthropic secret", r"\bsk-ant-[A-Za-z0-9_-]{12,}"),
    ("Stripe secret", r"\bsk_(?:live|test)_[A-Za-z0-9]{12,}"),
    ("OpenAI secret", r"\bsk-(?!ant-)[A-Za-z0-9_-]{16,}"),
    ("AWS access key ID", r"\bAKIA[A-Z0-9]{16}\b"),
    ("Google API key", r"\bAIza[A-Za-z0-9_-]{20,}"),
    ("Supabase secret", r"\bsb_secret_[A-Za-z0-9_-]{10,}"),
    ("Supabase publishable (public)", r"\bsb_publishable_[A-Za-z0-9_-]{10,}"),
    ("GitHub token", r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{12,}"),
    ("Slack token", r"\bxox[a-z]-[A-Za-z0-9-]{10,}"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ("n8n webhook URL", r"(?:https?://[^\s\"'<>`\\]+)?/webhook/[^\s\"'<>`\\]+"),
    ("client-side password hash", r"(?i)\b(?:password_?hash|hashed_?password)\s*[:=]\s*[\"']([a-f0-9]{32,128})[\"']"),
]
COMPILED_SECRETS = [(kind, re.compile(pattern)) for kind, pattern in SECRET_PATTERNS]


def decode_b64(value):
    if len(value) > 65536:
        raise ValueError("encoded value too long")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def secrets(text, source):
    """Return type, byte/character length and location, never values or JWT claims."""
    found, spans = [], []
    for kind, pattern in COMPILED_SECRETS:
        for match in pattern.finditer(text):
            if any(a <= match.start() < b for a, b in spans):
                continue
            spans.append(match.span())
            value = match.group(1) if kind == "client-side password hash" else match.group()
            item = {"type": kind, "length": len(value), "file": safe_url(source),
                    "line": text.count("\n", 0, match.start()) + 1, "offset": match.start()}
            if kind == "JWT":
                try:
                    role = json.loads(decode_b64(value.split(".")[1])).get("role")
                    item["role"] = role if role in ("anon", "service_role", "authenticated") else "other/absent"
                except (ValueError, TypeError, AttributeError, UnicodeError):
                    item["role"] = "undecodable"
            if kind == "n8n webhook URL":
                item["path"] = "/webhook/[REDACTED]"
            found.append(item)
            if len(found) >= 500:
                return found
    return found


def redact(text):
    """Defense in depth for controlled evidence strings; bodies are never persisted."""
    for kind, pattern in COMPILED_SECRETS:
        replacement = "/webhook/[REDACTED]" if kind == "n8n webhook URL" else "[REDACTED:" + kind + "]"
        text = pattern.sub(lambda m: replacement, text)
    text = re.sub(r"(?i)(?:nonce|sha256|sha384|sha512)-[A-Za-z0-9+/=_-]+", "[CSP token redacted]", text)
    text = re.sub(r"(?i)\b(password|token|secret|api[_-]?key|authorization)\s*[:=]\s*[^\s;,]+", r"\1=[REDACTED]", text)
    # Do not span path separators: long ordinary asset paths are useful evidence.
    text = re.sub(r"\b[A-Za-z0-9_+=-]{64,}\b", "[opaque value redacted]", text)
    return text


def safe_url(value):
    """Retain file identity, remove all query values, credentials and opaque path segments."""
    try:
        u = urlsplit(value)
        host = u.hostname or ""
        path = re.sub(r"(?i)(/webhook/).*", r"\1[REDACTED]", u.path)
        path = re.sub(r"[^/]{64,}", "[opaque-segment]", path)
        path = redact(unquote(path))
        return urlunsplit((u.scheme, redact(host), path, "[query omitted]" if u.query else "", ""))
    except ValueError:
        return "[invalid URL]"


def cookie_flags(value):
    parts = value.split(";")
    name = parts[0].split("=", 1)[0].strip()
    # Cookie names are arbitrary input too; retain short ordinary names only.
    name = name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", name) else "[cookie]"
    attrs = {}
    for part in parts[1:]:
        key, _, val = part.strip().partition("=")
        attrs[key.lower()] = val.strip().lower()
    return {"name": redact(name), "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": attrs.get("samesite") if attrs.get("samesite") in ("strict", "lax", "none") else None}


def header_facts(pairs):
    """Preserve duplicate headers. No Set-Cookie value or unknown header value survives."""
    headers, cookies = {}, []
    allowed = {"strict-transport-security", "content-security-policy", "x-frame-options",
               "x-content-type-options", "referrer-policy", "server", "x-powered-by",
               "content-type", "x-robots-tag", "last-modified"}
    for key, value in pairs:
        key = key.lower()
        if key == "set-cookie":
            cookies.append(cookie_flags(value))
        elif key == "location":
            headers.setdefault(key, []).append(safe_url(value))
        elif key in allowed:
            # Strip URLs' parameters and CSP embedded tokens before retaining a line.
            value = re.sub(r"https?://[^\s;,\"']+", lambda m: safe_url(m.group()), value)
            headers.setdefault(key, []).append(redact(value)[:2000])
    return {"headers": headers, "cookies": cookies,
            "header_names": sorted({redact(k.lower()) for k, _ in pairs if re.fullmatch(r"[\w-]{1,60}", k)})}


def n8n_release(encoded):
    try:
        data = json.loads(decode_b64(encoded))
        release = data.get("release", "")
        match = re.fullmatch(r"n8n@(" + VERSION + r")", release)
        return match.group(1) if match else None
    except (ValueError, TypeError, AttributeError, UnicodeError):
        return None


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.scripts, self.assets, self.links, self.meta = [], [], [], []
        self.password = False
        self.inline_scripts = []
        self._inline = False
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            self._inline = not a.get("src") and a.get("type", "").lower() in ("", "module", "text/javascript", "application/javascript")
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        if tag in ("script", "link", "img"):
            self.assets.append(a.get("src") or a.get("href") or "")
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag == "meta":
            self.meta.append(a)
        if tag == "input" and a.get("type", "").lower() == "password":
            self.password = True

    def handle_data(self, data):
        if self._inline:
            self.inline_scripts.append(data)

    def handle_endtag(self, tag):
        if tag == "script":
            self._inline = False


def wp_versions(assets):
    result = []
    for asset in assets:
        u = urlsplit(asset)
        version = parse_qs(u.query).get("ver", [""])[0]
        if not re.fullmatch(VERSION, version):
            continue
        plugin = re.search(r"/wp-content/plugins/([a-zA-Z0-9_-]+)/", u.path)
        theme = re.search(r"/wp-content/themes/([a-zA-Z0-9_-]+)/", u.path)
        if plugin:
            package, kind = plugin.group(1), "wordpress-plugin"
        elif theme:
            package, kind = theme.group(1), "wordpress-theme"
        elif re.search(r"/wp-includes/(?:js/wp-embed(?:\.min)?\.js|css/)", u.path):
            package, kind = "wordpress", "wordpress-core"
        else:
            continue  # jQuery and other vendored libraries' ver= is not the core release.
        result.append({"product": package, "kind": kind, "version": version,
                       "evidence": safe_url(asset).split("?", 1)[0] + "?ver=" + version,
                       "confidence": "asset hint; owner must confirm installed version"})
    return result


def version_facts(text, source, is_html=False, headers=None):
    versions, markers = [], set()

    def add(product, version, evidence, kind="npm", confidence="explicit public string"):
        versions.append({"product": product, "kind": kind, "version": version,
                         "evidence": evidence, "file": safe_url(source), "confidence": confidence})

    for key in ("server", "x-powered-by"):
        for value in (headers or {}).get(key, []):
            for product, version in re.findall(r"(?i)\b(nginx|apache|php|express|next(?:\.js)?|node(?:\.js)?)/?\s*(" + VERSION + ")", value):
                product = {"next.js": "next", "node.js": "node"}.get(product.lower(), product.lower())
                add(product, version, key + ": " + product + "/" + version,
                    "npm" if product in ("next", "express") else "runtime")
    if is_html:
        page = Page(text)
        for meta in page.meta:
            if meta.get("name", "").lower() == "n8n:config:sentry":
                version = n8n_release(meta.get("content", ""))
                if version:
                    add("n8n", version, 'meta n8n:config:sentry decoded release="n8n@' + version + '"')
            if meta.get("name", "").lower() == "generator":
                for product, version in re.findall(r"(?i)\b(WordPress|Drupal|Next\.js|Vite|React|n8n)\s*[v@/]?\s*(" + VERSION + ")", meta.get("content", "")):
                    product = product.lower().replace("next.js", "next")
                    add(product, version, "meta generator: " + product + " " + version,
                        "wordpress-core" if product == "wordpress" else "packagist" if product == "drupal" else "npm")
        for item in wp_versions(page.assets):
            item["file"] = safe_url(source)
            versions.append(item)
    for marker, pattern in [("next", r"__NEXT_DATA__|/_next/static/|self\.__next_f"),
                            ("vite", r"__vite__|/@vite/|modulepreload"),
                            ("react", r"react\.production|react\.element|react\.transitional\.element")]:
        if re.search(pattern, text):
            markers.add(marker)
    patterns = [
        ("next", r"(?:Next\.js\s*(?:v|@)?|next(?:Version|_VERSION)\s*[:=]\s*[\"'])"),
        ("vite", r"(?:vite(?:Version|_VERSION)\s*[:=]\s*[\"']|Vite v)"),
        ("react", r"(?:React\s*=\s*\{\s*version\s*:\s*[\"']|React(?:\.version)?\s*[:=@]\s*[\"']?|react@)")]
    for product, prefix in patterns:
        for m in re.finditer(prefix + "(" + VERSION + ")", text):
            add(product, m.group(1), product + " version string " + m.group(1))
    # Bind React exports.version to the same export object as createElement. A generic
    # .version elsewhere in a combined bundle can belong to an unrelated library.
    if "react" in markers:
        for m in re.finditer(r"\b\w{1,30}\.version\s*=\s*[\"'](" + VERSION + r")[\"']", text):
            obj = m.group().split(".", 1)[0]
            if re.search(r"\b" + re.escape(obj) + r"\.createElement\s*=", text):
                add("react", m.group(1), "React marker + createElement export + exports.version=" + m.group(1), confidence="bundle association; verify package")
    unique = {(x["product"], x["version"], x["kind"], x["evidence"]): x for x in versions}
    return list(unique.values()), sorted(markers)


def osv_package(item):
    kind, product = item["kind"], item["product"]
    if kind == "npm" and product in ("next", "react", "vite", "n8n", "express"):
        return {"ecosystem": "npm", "name": product}
    if kind == "packagist" and product == "drupal":
        return {"ecosystem": "Packagist", "name": "drupal/core"}
    if kind.startswith("wordpress-"):
        return {"ecosystem": {"wordpress-core": "WordPress:Core", "wordpress-plugin": "WordPress:Plugin",
                              "wordpress-theme": "WordPress:Theme"}[kind], "name": product}
    return None


class SuffixList:
    def __init__(self, path=None):
        self.rules = set()
        for line in Path(path or Path(__file__).with_name("public_suffix_list.dat")).read_text().splitlines():
            if line and not line.startswith("//"):
                self.rules.add(line.encode("idna").decode("ascii"))

    def apex(self, host):
        labels = host.lower().split(".")
        suffix = 1
        for i in range(len(labels)):
            tail = ".".join(labels[i:])
            if "!" + tail in self.rules:
                suffix = len(labels) - i - 1
                break
            if tail in self.rules or (i + 1 < len(labels) and "*." + ".".join(labels[i + 1:]) in self.rules):
                suffix = max(suffix, len(labels) - i)
        return ".".join(labels[-(suffix + 1):]) if len(labels) > suffix else None
