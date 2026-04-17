#!/usr/bin/env python3
"""
Narthex PreToolUse hook for Bash.

Blocks compositional exfiltration patterns -- the attack shape, not the
ingredients. Reading a credential file or running curl is fine on its
own; combining them in a single pipeline (or obfuscating execution) is
what gets blocked.

When `bashlex` is installed, the hook parses the command into an AST
and checks pipeline structure, which eliminates false positives from
quoted-string arguments (e.g. `gh repo edit --description "... curl | sh
is bad ..."`) while still catching shell code smuggled through
`bash -c`, `eval`, `$(...)`, and heredocs feeding interpreters.

Without bashlex, the hook falls back to regex-on-raw-text. Install for
higher precision:

    pip install --user bashlex

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
from typing import Iterable

try:
    import bashlex  # type: ignore
    _HAVE_BASHLEX = True
except Exception:
    _HAVE_BASHLEX = False

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

NETWORK_TOOLS = {
    "curl", "wget", "nc", "ncat", "netcat",
    "scp", "rsync", "sftp", "ftp", "tftp",
    "http", "https", "httpie", "xh",
    "mail", "sendmail", "mutt",
}

ENV_DUMPERS = {"env", "printenv", "export", "declare", "set"}

SHELL_INTERPRETERS = {"bash", "sh", "zsh", "dash", "ksh"}

EVAL_INTERPRETERS = {"bash", "sh", "zsh", "python", "python3", "perl", "ruby", "node"}

DEV_SOCKET_RE = re.compile(r"/dev/(?:tcp|udp)/")


def _word(words: Iterable[str]) -> str:
    return r"(?<![\w/.-])(?:" + "|".join(re.escape(w) for w in words) + r")\b"


def _any(patterns: Iterable[str], text: str, flags: int = 0) -> bool:
    return any(re.search(p, text, flags) for p in patterns)


# ---------------------------------------------------------------------------
# AST-based structural extraction
# ---------------------------------------------------------------------------

class Structural:
    """Structural view of a command: pipelines + redirect targets.

    A pipeline is a list of commands (each command is a list of word
    strings). Single commands become one-element pipelines. Commands
    smuggled through `bash -c`, `eval`, `$(...)`, and heredocs feeding
    interpreters are added by recursive parsing.
    """

    def __init__(self) -> None:
        self.pipelines: list[list[list[str]]] = []
        self.redirect_targets: list[str] = []

    def command_appears(self, name: str) -> bool:
        return any(
            pipeline and pipeline[0] and pipeline[0][0] == name
            for pipeline in self.pipelines
            for _ in [None]
        )

    def pipe_sequence(self, left: set[str], right: set[str]) -> bool:
        """True if any pipeline has a left-cmd immediately piping to a right-cmd."""
        for pipeline in self.pipelines:
            for i in range(len(pipeline) - 1):
                a = pipeline[i]
                b = pipeline[i + 1]
                if a and b and a[0] in left and b[0] in right:
                    return True
        return False

    def pipe_sequence_with_flag(
        self, left: set[str], left_flag_re: str, right: set[str]
    ) -> bool:
        """Like pipe_sequence but require a flag match on the left command."""
        for pipeline in self.pipelines:
            for i in range(len(pipeline) - 1):
                a = pipeline[i]
                b = pipeline[i + 1]
                if not (a and b and a[0] in left and b[0] in right):
                    continue
                argstr = " ".join(a[1:])
                if re.search(left_flag_re, argstr):
                    return True
        return False

    def has_redirect_to_dev_socket(self) -> bool:
        return any(DEV_SOCKET_RE.search(t) for t in self.redirect_targets)


def _word_literal(word_node) -> str:
    """Best-effort literal for a bashlex word node."""
    w = getattr(word_node, "word", None)
    return w if isinstance(w, str) else ""


def _argv(cmd_node) -> list[str]:
    parts = getattr(cmd_node, "parts", []) or []
    return [_word_literal(p) for p in parts if getattr(p, "kind", None) == "word"]


def _walk(node, s: Structural, depth: int = 0) -> None:
    if depth > 20:  # guard against pathological nesting
        return
    kind = getattr(node, "kind", None)

    if kind == "list":
        for part in getattr(node, "parts", []) or []:
            _walk(part, s, depth)
        return

    if kind == "pipeline":
        commands: list[list[str]] = []
        for part in getattr(node, "parts", []) or []:
            if getattr(part, "kind", None) == "command":
                commands.append(_argv(part))
                _inspect_command(part, s, depth)
            elif getattr(part, "kind", None) == "compound":
                # A compound inside a pipeline -- flatten conservatively.
                _walk(part, s, depth + 1)
        if commands:
            s.pipelines.append(commands)
        return

    if kind == "command":
        s.pipelines.append([_argv(node)])
        _inspect_command(node, s, depth)
        return

    if kind == "compound":
        for part in getattr(node, "list", []) or []:
            _walk(part, s, depth + 1)
        return

    # Fallback: recurse through any children we can find.
    for attr in ("parts", "list"):
        for child in getattr(node, attr, []) or []:
            _walk(child, s, depth + 1)


def _inspect_command(cmd_node, s: Structural, depth: int) -> None:
    """Handle redirects, command substitutions, and smuggled shell code."""
    argv = _argv(cmd_node)

    for part in getattr(cmd_node, "parts", []) or []:
        pkind = getattr(part, "kind", None)

        if pkind == "redirect":
            out = getattr(part, "output", None)
            if out is not None:
                target = _word_literal(out) or getattr(out, "word", "") or ""
                if target:
                    s.redirect_targets.append(target)
            # Heredoc body
            heredoc = getattr(part, "heredoc", None)
            if heredoc is not None and argv and argv[0] in EVAL_INTERPRETERS:
                body = _word_literal(heredoc)
                if body and argv[0] in SHELL_INTERPRETERS:
                    _reparse(body, s, depth)

        if pkind == "word":
            # Words may contain $(...) substitutions as nested parts.
            for sub in getattr(part, "parts", []) or []:
                if getattr(sub, "kind", None) == "commandsubstitution":
                    inner = getattr(sub, "command", None)
                    if inner is not None:
                        _walk(inner, s, depth + 1)

    # bash -c "STRING" / sh -c "STRING" / eval "STRING"
    if len(argv) >= 3 and argv[0] in SHELL_INTERPRETERS and argv[1] == "-c":
        _reparse(argv[2], s, depth)
    elif argv and argv[0] == "eval" and len(argv) > 1:
        _reparse(" ".join(argv[1:]), s, depth)


def _reparse(code: str, s: Structural, depth: int) -> None:
    if not code or depth > 20:
        return
    try:
        trees = bashlex.parse(code)
    except Exception:
        return
    for t in trees:
        _walk(t, s, depth + 1)


def _parse_structural(cmd: str) -> Structural | None:
    if not _HAVE_BASHLEX:
        return None
    try:
        trees = bashlex.parse(cmd)
    except Exception:
        return None
    s = Structural()
    for t in trees:
        _walk(t, s)
    return s


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def _check_structural(cmd: str, s: Structural) -> list[str]:
    reasons: list[str] = []

    # has_secret: any token references a secret path (check literal words + raw cmd).
    # We intentionally keep this broad -- a secret path anywhere in the line,
    # plus any network tool anywhere, is suspicious.
    has_secret = _any(SECRET_PATTERNS, cmd, re.IGNORECASE)
    network_commands = any(
        pipeline and pipeline[0] and pipeline[0][0] in NETWORK_TOOLS
        for pipeline in s.pipelines
    )
    has_network = network_commands or bool(re.search(_word(NETWORK_TOOLS), cmd))

    if has_secret and has_network:
        reasons.append(
            "command references a credential path and a network tool in the "
            "same invocation (exfiltration pattern)"
        )

    if s.pipe_sequence(ENV_DUMPERS, NETWORK_TOOLS):
        reasons.append("environment dump piped into a network tool")

    if s.pipe_sequence({"base64"}, NETWORK_TOOLS):
        reasons.append("base64 output piped into a network tool")

    if s.pipe_sequence({"curl", "wget"}, SHELL_INTERPRETERS):
        reasons.append("curl/wget piped into a shell (remote code execution)")

    if s.pipe_sequence_with_flag(
        {"base64"}, r"(?:^|\s)(?:-d|--decode|-D)(?:\s|$)", EVAL_INTERPRETERS
    ):
        reasons.append("base64-decoded content piped into an interpreter (obfuscated execution)")

    if s.has_redirect_to_dev_socket() or any(
        DEV_SOCKET_RE.search(w)
        for pipeline in s.pipelines
        for cmd_argv in pipeline
        for w in cmd_argv
    ):
        reasons.append("reverse-shell pattern (/dev/tcp or /dev/udp)")

    # `bash -i >& socket` -- argv has bash with -i, redirect target is a socket.
    for pipeline in s.pipelines:
        for cmd_argv in pipeline:
            if cmd_argv and cmd_argv[0] == "bash" and "-i" in cmd_argv:
                if any(DEV_SOCKET_RE.search(t) for t in s.redirect_targets):
                    reasons.append("interactive bash redirected to a socket (reverse shell)")
                    break

    # Secret uploaded as request body. Check per-command argv.
    for pipeline in s.pipelines:
        for cmd_argv in pipeline:
            if not cmd_argv or cmd_argv[0] not in NETWORK_TOOLS:
                continue
            argstr = " ".join(cmd_argv[1:])
            if re.search(
                r"(?:--data-binary|(?<!\w)-d|--upload-file|(?<!\w)-T|@)\s*@?[^\s]*"
                r"(?:\.ssh|\.aws|\.env|id_rsa|credentials|netrc)",
                argstr,
                re.IGNORECASE,
            ):
                reasons.append("secret file being sent as request body/upload")
                break
        else:
            continue
        break

    # Deduplicate while preserving order.
    return list(dict.fromkeys(reasons))


def _check_regex(cmd: str) -> list[str]:
    """Regex fallback used when bashlex isn't available or parsing failed."""
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
        rf"{_word({'curl', 'wget'})}.*?\|\s*(?:sudo\s+)?{_word(SHELL_INTERPRETERS)}",
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

    return list(dict.fromkeys(reasons))


def check(cmd: str) -> list[str]:
    """Return a list of block reasons. Empty list = allow."""
    s = _parse_structural(cmd)
    if s is not None:
        return _check_structural(cmd, s)
    return _check_regex(cmd)


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
