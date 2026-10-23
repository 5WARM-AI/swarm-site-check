"""Bounded public-code hints. These parsers never contact a backend or return key values."""
import re
from urllib.parse import unquote, urljoin, urlsplit

from parsers import Page, secrets


def platform_hints(source, body="", headers=None, header_names=()):
    headers = headers or {}
    names = set(header_names) | set(headers)
    host = urlsplit(source).hostname or ""
    server = " ".join(headers.get("server", [])).lower()
    hints = {}
    rules = {
        "Vercel": ("vercel" in server or "x-vercel-id" in names or "x-vercel-cache" in names or host.endswith(".vercel.app")),
        "Netlify": ("netlify" in server or "x-nf-request-id" in names or host.endswith(".netlify.app")),
        "Cloudflare": ("cloudflare" in server or "cf-ray" in names),
        "Cloudflare Pages": host.endswith(".pages.dev"),
        "Cloudflare Workers": host.endswith(".workers.dev"),
        "Cloudflare Tunnel": host.endswith(".trycloudflare.com"),
        "Replit": (host.endswith((".replit.app", ".repl.co")) or any(n.startswith("x-replit-") for n in names)),
    }
    for platform, matched in rules.items():
        if matched:
            hints[platform] = "public hostname or server/header marker"
    for meta in Page(body).meta if "<" in body else []:
        value = meta.get("content", "").strip().lower()
        if meta.get("name", "").lower() == "generator":
            for platform in ("Lovable", "Bolt", "Replit", "Vercel", "Netlify", "Cloudflare Pages"):
                if value in (platform.lower(), platform.lower() + ".new", platform.lower() + ".dev"):
                    hints[platform] = "meta generator=" + platform
    for platform, pattern, label in (
        ("Lovable", r"\blovable-tagger\b|https://(?:www\.)?lovable\.dev/[^\s\"']*badge", "lovable-tagger or builder badge marker"),
        ("Bolt", r"\bdata-bolt(?:-badge)?\s*=|https://bolt\.new/[^\s\"']*badge", "Bolt builder badge marker"),
        ("Replit", r"https://replit\.com/public/js/replit-badge", "Replit badge script marker"),
    ):
        if re.search(pattern, body, re.I):
            hints[platform] = label
    return hints


def firebase_config(text):
    """Recognize a bounded config object; identify only its own API-key span."""
    configs = []
    for obj in re.finditer(r"\{[^{}]{1,6000}\}", text):
        fields = {}
        for match in re.finditer(r'''["']?\b(apiKey|projectId|authDomain|databaseURL|storageBucket|appId)["']?\s*:\s*(["'])([^"'\r\n]{1,300})\2''', obj.group()):
            fields[match.group(1)] = (match.group(3), obj.start() + match.start(3), obj.start() + match.end(3))
        if not {"apiKey", "projectId"} <= fields.keys():
            continue
        provider = any(re.search(r"(?:\.firebaseapp\.com|\.firebaseio\.com|\.firebasedatabase\.app|\.appspot\.com|\.firebasestorage\.app)(?:/|$)", fields[k][0])
                       for k in ("authDomain", "databaseURL", "storageBucket") if k in fields)
        app_id = "appId" in fields and bool(re.fullmatch(r"1:\d+:web:[A-Za-z0-9_-]+", fields["appId"][0]))
        if provider or app_id:
            configs.append({"fields": sorted(fields), "key_span": fields["apiKey"][1:],
                            "line": text.count("\n", 0, obj.start()) + 1})
    return configs


def supabase_config(text, found):
    # The endpoint is never retained or visited. Its presence plus a public key is evidence.
    endpoint = re.search(r"https://[a-z0-9-]+\.supabase\.(?:co|in)\b", text, re.I)
    public = any(x["type"] == "Supabase publishable (public)" or
                 (x["type"] == "JWT" and x.get("role") == "anon") for x in found)
    return bool(endpoint and public)


def client_gates(js):
    """Return only pattern/line/length, with backend uncertainty explicit."""
    found = []
    server_hint = bool(re.search(r"\bfetch\s*\(|XMLHttpRequest|\baxios\s*[.(]|\bsignIn\w*\s*\(|\.auth\b", js))

    def add(kind, match, length=None):
        item = {"pattern": kind, "line": js.count("\n", 0, match.start()) + 1,
                "server_request_marker": server_hint}
        if length is not None:
            item["length"] = length
        if item not in found:
            found.append(item)

    assignments = re.finditer(r'''\b([\w$]*(?:password|passcode|passwd|passwordHash|hashedPassword)[\w$]*)\s*[:=]\s*(["'])([^"'\r\n]{1,256})\2''', js, re.I)
    for match in assignments:
        name = re.escape(match.group(1))
        if re.search(r"\b" + name + r"\b\s*[!=]==?|[!=]==?\s*\b" + name + r"\b", js):
            add("password/hash literal compared in browser JavaScript", match, len(match.group(3)))
    for match in re.finditer(r'''\b(?:password|passcode|passwd)(?:\.value)?\s*[!=]==?\s*(["'])([^"'\r\n]{1,256})\1''', js, re.I):
        add("password literal compared in browser JavaScript", match, len(match.group(2)))
    auth_name = r"(?:[A-Za-z0-9_-]*_)?(?:auth|authenticated|isAuthenticated|isLoggedIn|loggedIn|logged_in|is_auth|isAdmin)(?:_[A-Za-z0-9_-]*)?"
    storage = r'''(?:window\.)?(?:sessionStorage|localStorage)(?:\.getItem\(\s*["']''' + auth_name + r'''["']\s*\)|\.''' + auth_name + r'''\b|\[\s*["']''' + auth_name + r'''["']\s*\])'''
    for match in re.finditer(storage, js, re.I):
        # Read used by a condition, assignment or logical branch; writes alone are not gates.
        before, after = js[max(0, match.start()-100):match.start()], js[match.end():match.end()+100]
        if re.search(r"(?:if\s*\([^;{}]*|(?:const|let|var)\s+\w+\s*=\s*(?:!{1,2}|Boolean\s*\()?\s*|return\s+)$", before) or re.match(r"\s*(?:[!=]==?|&&|\|\||\?)", after):
            add("browser storage auth flag read by access logic", match)
    return found[:100]


def noindex_marker(body, headers):
    page = Page(body)
    robots = " ".join(x.get("content", "") for x in page.meta if x.get("name", "").lower() in ("robots", "googlebot"))
    robots += " " + " ".join(headers.get("x-robots-tag", []))
    return bool(re.search(r"\b(?:noindex|none)\b", robots, re.I))


def preview_posture(source, body, headers, status):
    if status != 200:
        return None
    page = Page(body)
    noindex = noindex_marker(body, headers)
    login = page.password or bool(re.search(r"<(?:form|a)\b[^>]*(?:action|href)=[\"'][^\"']*/(?:login|sign-?in|oauth/authorize)(?:[/?\"'])", body, re.I))
    u = urlsplit(source)
    preview = bool(re.search(r"(?:^|[./_-])(?:preview|review|staging|stage|demo|test)(?:$|[./_-])", (u.hostname or "") + u.path, re.I))
    hosted = (u.hostname or "").endswith((".pages.dev", ".vercel.app", ".netlify.app", ".replit.app", ".repl.co"))
    admin = bool(re.search(r"(?:^|[./_-])(?:admin|dashboard|ops)(?:$|[./_-])", (u.hostname or "") + u.path, re.I))
    if not login and (admin or (not noindex and (preview or hosted))):
        return "admin-looking" if admin else "preview/staging-looking" if preview else "public project"
    return None


def source_map(js, bundle):
    """Accept an actual final directive comment, skipping quoted strings and templates.

    This deliberately conservative lexer ignores template expressions and ambiguous
    regex/comment constructs; an absent match never establishes absence of a map.
    """
    comments, i, size = [], 0, len(js)
    while i < size:
        ch = js[i]
        if ch in "\"'`":
            quote, i = ch, i + 1
            while i < size:
                if js[i] == "\\":
                    i += 2
                elif js[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
        elif js.startswith("//", i):
            end = js.find("\n", i)
            end = size if end < 0 else end
            comments.append((js[i:end], end))
            i = end
        elif js.startswith("/*", i):
            end = js.find("*/", i + 2)
            if end < 0:
                break
            comments.append((js[i:end+2], end+2))
            i = end+2
        elif ch == "/" and (i == 0 or js[max(0, i-100):i].rstrip()[-1:] in "=(:,![{;?&|"):
            # Skip regular expression literals, including their character classes.
            i, in_class = i + 1, False
            while i < size:
                if js[i] == "\\":
                    i += 2
                    continue
                if js[i] == "[":
                    in_class = True
                elif js[i] == "]":
                    in_class = False
                elif js[i] == "/" and not in_class:
                    i += 1
                    break
                i += 1
        else:
            i += 1
    for comment, end in reversed(comments):
        match = re.fullmatch(r"(?://[#@]\s*sourceMappingURL=([^\s]+)\s*|/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*/)", comment)
        if not match or js[end:].strip():
            continue
        value = match.group(1) or match.group(2)
        if len(value) > 2048 or any(ord(c) < 33 for c in value) or "\\" in value:
            return None, "sourceMappingURL refused: invalid URL"
        try:
            target = urljoin(bundle, value)
            u, parent = urlsplit(target), urlsplit(bundle)
            if (u.scheme, u.netloc) != ("https", parent.netloc) or u.username or u.password or u.query or u.fragment:
                return None, "sourceMappingURL skipped: cross-origin, inline or parameterized URL"
            if secrets(unquote(target), "/") or "/webhook/" in unquote(u.path).lower():
                return None, "sourceMappingURL refused: credential-bearing URL"
            return target, "explicit bundle sourceMappingURL"
        except ValueError:
            return None, "sourceMappingURL refused: invalid URL"
    return None, "no unambiguous final sourceMappingURL found"
