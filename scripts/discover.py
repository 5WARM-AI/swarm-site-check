"""Optional, user-requested read-only inventory. No tokens or raw CLI output are stored."""
import re
import shutil
import subprocess
import sys

COMMANDS = {"wrangler": ["wrangler", "pages", "project", "list"],
            "vercel": ["vercel", "project", "ls"]}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        print("Usage: discover.sh wrangler|vercel", file=sys.stderr)
        return 2
    command = COMMANDS[sys.argv[1]]
    if not shutil.which(command[0]):
        print("CLI is not already installed. Supply a hosts file instead.")
        return 2
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=20, text=True, check=False)
    except (OSError, subprocess.TimeoutExpired):
        print("Read-only discovery unavailable. Supply a hosts file instead.")
        return 2
    if result.returncode:
        print("Discovery unavailable or CLI is not logged in. Supply a hosts file instead; no login attempted.")
        return 2
    # Emit domain suggestions only; CLI output can contain account details or errors.
    output = result.stdout + "\n" + result.stderr
    domains = sorted(set(re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.(?:pages\.dev|vercel\.app)\b", output)))
    if domains:
        print("Suggested public project domains (ownership still needs confirmation):")
        print("\n".join(domains))
    else:
        print("No public project domains found in CLI output. Supply the domains or an exported hosts file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
