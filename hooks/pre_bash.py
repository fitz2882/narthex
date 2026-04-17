#!/usr/bin/env python3
"""
Narthex PreToolUse hook for Bash.

Blocks compositional exfiltration patterns — the attack shape, not the
ingredients. Reading a credential file or running curl is fine on its
own; combining them in a single pipeline (or obfuscating execution) is
what gets blocked.

Hook protocol:
  - Receives a JSON payload on stdin with tool_name="Bash" and
    tool_input.command set to the shell command about to run.
  - Exit 0  -> allow
  - Exit 2  -> block; stderr is surfaced to the assistant as the reason.
"""

from __future__ import annotations

import json
import re
import sys

SECRET_PATTERNS = [
    r"~/\.ssh\b",
    r"\$HOME/\.ssh\b",
    r"(?:^|/)\.ssh/(?:id_|authorized_keys|known_hosts)",
    r"\bid_(?:rsa|ed25519|ecdsa|dsa)\b",
    r"~/\.aws\b",
    r"(?:^|/)\.aws/(?:credentials|config)\b",
    r"~/\.config/gh\b",
    r"(?:^|/)gh/hosts\.yml\b",
    r"~/\.netrc\b",
    r"(?:^|/)\.netrc\b",
    r"(?:^|/|\s)\.env(?:\.[a-zA-Z0-9_-]+)?(?=\b|$)",
    r"~/\.docker/config\.json",
    r"~/\.kube/config\b",
    r"~/\.npmrc\b",
    r"(?:^|/)\.npmrc\b",
    r"~/\.pypirc\b",
    r"~/\.gnupg\b",
    r"/etc/shadow\b",
    r"~/Library/Keychains\b",
]

NETWORK_TOOLS = [
    "curl", "wget", "nc", "ncat", "netcat",
    "scp", "rsync", "sftp", "ftp", "tftp",
    "http", "https", "httpie", "xh",
    "mail", "sendmail", "mutt",
]

ENV_DUMPERS = ["env", "printenv", "export", "declare", "set"]

SHELLS = ["bash", "sh", "zsh", "dash", "ksh", "fish"]

EVAL_INTERPRETERS = ["bash", "sh", "zsh", "python", "python3", "perl", "ruby", "node"]


def _any(patterns: list[str], text: str, flags: int = 0) -> bool:
    return any(re.search(p, text, flags) for p in patterns)


def _word(words: list[str]) -> str:
    return r"(?<![\w/.-])(?:" + "|".join(re.escape(w) for w in words) + r")\b"


def check(cmd: str) -> list[str]:
    """Return a list of block reasons. Empty list = allow."""
    reasons: list[str] = []

    has_secret = _any(SECRET_PATTERNS, cmd, re.IGNORECASE)
    has_network = bool(re.search(_word(NETWORK_TOOLS), cmd))
    has_env_dump = bool(re.search(_word(ENV_DUMPERS), cmd))

    if has_secret and has_network:
        reasons.append(
            "command references a credential path and a network tool in the "
            "same invocation (exfiltration pattern)"
        )

    if has_env_dump and has_network:
        if re.search(
            rf"{_word(ENV_DUMPERS)}.*?(\||;|&&|\$\(|`).*?{_word(NETWORK_TOOLS)}",
            cmd,
            re.DOTALL,
        ):
            reasons.append("environment dump piped into a network tool")

    if re.search(r"\bbase64\b", cmd) and has_network:
        if re.search(
            rf"\bbase64\b.*?(\||;|&&|\$\(|`).*?{_word(NETWORK_TOOLS)}",
            cmd,
            re.DOTALL,
        ):
            reasons.append("base64 output piped into a network tool")

    if re.search(
        rf"{_word(['curl', 'wget'])}.*?\|\s*(?:sudo\s+)?{_word(SHELLS)}",
        cmd,
        re.DOTALL,
    ):
        reasons.append("curl/wget piped into a shell (remote code execution)")

    if re.search(r"\bbase64\b\s+(?:-d|--decode|-D)", cmd) and re.search(
        rf"\|\s*{_word(EVAL_INTERPRETERS)}", cmd
    ):
        reasons.append("base64-decoded content piped into an interpreter (obfuscated execution)")

    if "/dev/tcp/" in cmd or "/dev/udp/" in cmd:
        reasons.append("reverse-shell pattern (/dev/tcp or /dev/udp)")
    if re.search(r"\bbash\b\s+-i\b.*>&", cmd):
        reasons.append("interactive bash redirected to a socket (reverse shell)")

    if re.search(
        r"(?:curl|wget|http|httpie|xh)[^|;&]*"
        r"(?:--data-binary|-d|--upload-file|-T|@)\s*@?[^\s]*"
        r"(?:\.ssh|\.aws|\.env|id_rsa|credentials|netrc)",
        cmd,
        re.IGNORECASE,
    ):
        reasons.append("secret file being sent as request body/upload")

    return reasons


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    if payload.get("tool_name") != "Bash":
        sys.exit(0)

    cmd = payload.get("tool_input", {}).get("command", "")
    if not cmd:
        sys.exit(0)

    reasons = check(cmd)
    if reasons:
        msg = "NARTHEX blocked this Bash command. Reason(s):\n  - " + "\n  - ".join(reasons)
        msg += (
            "\n\nIf this is legitimate, rewrite the command to separate the "
            "flagged components, or edit ~/.claude/narthex/hooks/pre_bash.py."
        )
        print(msg, file=sys.stderr)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
