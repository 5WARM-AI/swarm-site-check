#!/usr/bin/env python3
"""Offline release audit. Print counts only; never copy a supplied private host list."""
import argparse
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


def audit(repo, hosts):
    paths = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=repo).split(b"\0")
    paths = sorted(set(p for p in paths if p))
    patterns = [re.compile(rb"(?<![a-z0-9-])" + re.escape(h.lower().encode()) + rb"(?![a-z0-9-]|\.[a-z0-9-])") for h in sorted(set(hosts))]
    count, files = 0, 0
    for name in paths:
        path = Path(repo) / name.decode()
        if not path.is_file():
            continue
        body = path.read_bytes().lower()
        hits = sum(len(pattern.findall(body)) for pattern in patterns)
        count += hits
        files += bool(hits)
    return {"private_hostnames_checked": len(patterns), "repository_files_checked": len(paths),
            "private_hostname_occurrences": count, "files_with_private_hostnames": files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts-file", type=Path, required=True)
    parser.add_argument("--allow-brand", action="append", default=[])
    args = parser.parse_args()
    hosts = set()
    for line in args.hosts_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            host = urlsplit(line if "://" in line else "https://" + line).hostname
            if host:
                hosts.add(host.lower())
    result = audit(Path(__file__).resolve().parents[1], hosts - set(args.allow_brand))
    print(json.dumps(result, sort_keys=True))
    return bool(result["private_hostname_occurrences"])


if __name__ == "__main__":
    raise SystemExit(main())
