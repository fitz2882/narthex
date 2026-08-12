#!/usr/bin/env python3
"""
Resolves Narthex's policy from a policy server, so several tools can enforce one list.

Narthex's rules are useful on their own, but a machine usually has more than one thing
watching it -- an editor hook, an agent runtime, a CI gate -- and each keeping its own copy of
"what counts as sensitive here" guarantees they drift. The one that is wrong is always the one
you are not looking at. So Narthex can be pointed at a server that owns the policy, and asks
it, rather than holding a second copy.

Configuration is entirely local and entirely optional. With nothing configured, Narthex uses
its built-in defaults and never touches the network -- no server, no timeout, no behaviour
change from having this file at all.

Configure with environment variables, or with a JSON file at ~/.claude/narthex/policy.json:

    {
      "url":       "http://127.0.0.1:8080/api/policy",
      "token_file": "~/.config/your-tool/api-token",
      "canary_url": "http://127.0.0.1:8080/api/canaries/tokens"
    }

Environment equivalents, which take precedence:

    NARTHEX_POLICY_URL, NARTHEX_POLICY_TOKEN, NARTHEX_POLICY_TOKEN_FILE, NARTHEX_CANARY_URL

THE CONTRACT a policy server implements. `GET <url>?workspace=<absolute path>` returning JSON:

    {
      "enabled":                 true,          // false disables Narthex's own findings
      "onCritical":              "block",       // "block" | "warn"
      "additionalSensitivePaths": ["terraform.tfstate"],
      "trackTaint":              true,          // follow a credential read to where it lands
      "acknowledgements": [                     // known-benign findings, suppressed until they expire
        {
          "rule":        "sensitive-path",
          "subjectGlob": "*tests/fixtures*",
          "reason":      "Fixtures assert the detector catches this shape.",
          "expiresAt":   1786000000000          // epoch ms; past entries are ignored
        }
      ]
    }

Every field is optional; anything missing falls back to the built-in default. A server that
returns `{}` is a server that says "use your own judgement".

`GET <canary_url>` returning `{"tokens": ["..."]}` supplies canary credentials -- values that
exist only to be stolen, so any use of one is unambiguous. Narthex only matches against them;
it never mints or stores them.

Offline behaviour is deliberate. When the server is unreachable this falls back to the last
policy it served, and with no cache it returns built-in defaults rather than an empty policy.
An empty policy would mean "nothing is sensitive", which reads as a clean session and is the
worst possible failure for a security control -- the same shape of bug as a commit gate that
passes because it had no checks to run.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

CONFIG_PATH = os.path.expanduser("~/.claude/narthex/policy.json")
CACHE_DIR = os.path.expanduser("~/.claude/narthex/policy-cache")
TIMEOUT_SECONDS = 2.0

# Used when no server is configured or none has ever been reached. Conservative rather than
# empty: a security control whose default is "nothing matters" is worse than one that is
# occasionally noisy.
DEFAULT_POLICY = {
    "enabled": True,
    "onCritical": "block",
    "additionalSensitivePaths": [],
    "trackTaint": True,
    "acknowledgements": [],
    "source": "built-in defaults",
}


def _config() -> dict:
    """Local configuration, if any. Environment wins over the file; both are optional."""
    settings: dict = {}
    try:
        with open(CONFIG_PATH) as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            settings = loaded
    except (OSError, ValueError):
        pass
    for key, variable in (
        ("url", "NARTHEX_POLICY_URL"),
        ("token", "NARTHEX_POLICY_TOKEN"),
        ("token_file", "NARTHEX_POLICY_TOKEN_FILE"),
        ("canary_url", "NARTHEX_CANARY_URL"),
    ):
        value = os.environ.get(variable)
        if value:
            settings[key] = value
    return settings


def _token(settings: dict) -> str:
    token = settings.get("token")
    if token:
        return str(token)
    path = settings.get("token_file")
    if not path:
        return ""
    try:
        with open(os.path.expanduser(str(path))) as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _workspace() -> str:
    """The repository root, which is the natural scope for a per-project policy."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=2, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    return os.getcwd()


def _cache_path(url: str, workspace: str) -> str:
    digest = hashlib.sha256(f"{url}\n{workspace}".encode("utf-8")).hexdigest()[:32]
    return os.path.join(CACHE_DIR, f"{digest}.json")


def _fetch(url: str, token: str) -> dict | None:
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return payload if isinstance(payload, dict) else None
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


def resolve(workspace: str | None = None) -> dict:
    """The live policy, the last one served, or built-in defaults -- in that order."""
    settings = _config()
    url = settings.get("url")
    if not url:
        return dict(DEFAULT_POLICY)

    workspace = workspace or _workspace()
    cache = _cache_path(str(url), workspace)
    query = urllib.parse.urlencode({"workspace": workspace})
    separator = "&" if "?" in str(url) else "?"

    policy = _fetch(f"{url}{separator}{query}", _token(settings))
    if policy is not None:
        policy["source"] = "policy server"
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(cache, "w") as handle:
                json.dump(policy, handle)
        except OSError:
            pass
        return policy

    try:
        with open(cache) as handle:
            policy = json.load(handle)
        policy["source"] = "cached (policy server unreachable)"
        return policy
    except (OSError, ValueError):
        return dict(DEFAULT_POLICY)


def canary_tokens() -> list[str]:
    """Canary credentials to match against, if a source is configured.

    Every other check in Narthex asks whether a command looks dangerous and can be wrong in
    both directions. A canary asks whether a credential with no legitimate purpose was used,
    and that question has one answer.
    """
    settings = _config()
    url = settings.get("canary_url")
    if not url:
        return []
    payload = _fetch(str(url), _token(settings))
    tokens = (payload or {}).get("tokens")
    return [str(token) for token in tokens] if isinstance(tokens, list) else []


def _glob_matches(glob: str, subject: str) -> bool:
    """`*` matches any run of characters, including `/` and spaces.

    A finding's subject is a path for some rules and an entire shell command for others, so
    path-segment semantics would silently fail to match anything containing a URL. Splitting on
    `*` and escaping each literal chunk also avoids the trap of using a placeholder character
    to survive escaping, which breaks the moment a glob legitimately contains that character.
    """
    pattern = ".*".join(re.escape(chunk) for chunk in glob.split("*"))
    return re.match(f"^{pattern}$", subject, re.DOTALL) is not None


def acknowledgement_for(policy: dict, rule: str, subject: str, now_ms: float) -> dict | None:
    """The live acknowledgement covering a finding, if there is one.

    Expired entries are ignored rather than deleted, so an expiry shows up as the finding
    coming back -- which is the review the expiry existed to force.
    """
    for entry in policy.get("acknowledgements") or []:
        if entry.get("rule") != rule:
            continue
        if float(entry.get("expiresAt") or 0) <= now_ms:
            continue
        if _glob_matches(str(entry.get("subjectGlob") or ""), subject):
            return entry
    return None


def extra_sensitive_paths(policy: dict) -> list[str]:
    return [str(path) for path in (policy.get("additionalSensitivePaths") or []) if str(path).strip()]


if __name__ == "__main__":
    print(json.dumps(resolve(), indent=2))
