#!/usr/bin/env python3
"""
Narthex installer.

Copies hooks and the MCP server into ~/.claude/narthex/, and patches
~/.claude/settings.json and ~/.claude.json to wire them up.

Idempotent: re-running only adds missing entries. Makes timestamped
backups of both config files on first run as *.pre-narthex.

Usage:
    python3 install.py [--dry-run] [--home DIR]

  --dry-run   Print what would happen without touching the filesystem.
  --home DIR  Override the Claude Code config directory. Defaults to
              ~/.claude.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent

DEFAULT_ALLOW = [
    "mcp__narthex",
    "WebFetch(domain:docs.anthropic.com)",
    "WebFetch(domain:github.com)",
    "WebFetch(domain:raw.githubusercontent.com)",
    "WebFetch(domain:gist.githubusercontent.com)",
    "WebFetch(domain:api.github.com)",
    "WebFetch(domain:registry.npmjs.org)",
    "WebFetch(domain:www.npmjs.com)",
    "WebFetch(domain:pypi.org)",
    "WebFetch(domain:files.pythonhosted.org)",
    "WebFetch(domain:crates.io)",
    "WebFetch(domain:go.dev)",
    "WebFetch(domain:pkg.go.dev)",
    "WebFetch(domain:developer.mozilla.org)",
    "WebFetch(domain:stackoverflow.com)",
]

DEFAULT_ASK = [
    "WebFetch",
    "Bash(curl:*)",
    "Bash(wget:*)",
    "Bash(nc:*)",
    "Bash(ncat:*)",
    "Bash(netcat:*)",
    "Bash(scp:*)",
    "Bash(sftp:*)",
    "Bash(ftp:*)",
    "Bash(httpie:*)",
    "Bash(http:*)",
    "Bash(xh:*)",
]


def log(msg: str) -> None:
    print(f"[narthex] {msg}")


def find_uv() -> str:
    uv = shutil.which("uv")
    if uv:
        return uv
    log("ERROR: `uv` not found on PATH. Install from https://github.com/astral-sh/uv and re-run.")
    sys.exit(1)


def copy_files(dest: Path, dry_run: bool) -> None:
    for sub in ("hooks", "mcp"):
        target = dest / sub
        source = REPO / sub
        if not source.is_dir():
            log(f"ERROR: missing source directory {source}")
            sys.exit(1)
        if dry_run:
            log(f"would copy {source} -> {target}")
            continue
        target.mkdir(parents=True, exist_ok=True)
        for item in source.iterdir():
            if item.name.startswith(".") or item.suffix == ".pyc":
                continue
            shutil.copy2(item, target / item.name)
            if item.suffix == ".py":
                (target / item.name).chmod(0o755)
        log(f"copied {sub}/ -> {target}")


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open() as f:
        return json.load(f)


def save_json(path: Path, data: dict) -> None:
    with path.open("w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def backup_once(path: Path, dry_run: bool) -> None:
    if not path.exists():
        return
    backup = path.with_suffix(path.suffix + ".pre-narthex")
    if backup.exists():
        return
    if dry_run:
        log(f"would back up {path} -> {backup}")
        return
    shutil.copy2(path, backup)
    log(f"backed up {path.name} -> {backup.name}")


def patch_settings(settings_path: Path, claude_home: Path, dry_run: bool) -> None:
    cfg = load_json(settings_path)
    perms = cfg.setdefault("permissions", {})
    allow = perms.setdefault("allow", [])
    ask = perms.setdefault("ask", [])
    for rule in DEFAULT_ALLOW:
        if rule not in allow:
            allow.append(rule)
    for rule in DEFAULT_ASK:
        if rule not in ask:
            ask.append(rule)

    hooks = cfg.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    post = hooks.setdefault("PostToolUse", [])

    pre_cmd = f"python3 {claude_home}/narthex/hooks/pre_bash.py"
    post_cmd = f"python3 {claude_home}/narthex/hooks/audit.py"

    def has_hook(arr: list, cmd: str) -> bool:
        for entry in arr:
            for h in entry.get("hooks", []):
                if h.get("command", "").strip() == cmd:
                    return True
        return False

    if not has_hook(pre, pre_cmd):
        pre.append(
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": pre_cmd}],
            }
        )
        log("added PreToolUse Bash hook")
    else:
        log("PreToolUse Bash hook already present — skipping")

    if not has_hook(post, post_cmd):
        post.append(
            {
                "matcher": "Bash|WebFetch",
                "hooks": [{"type": "command", "command": post_cmd}],
            }
        )
        log("added PostToolUse audit hook")
    else:
        log("PostToolUse audit hook already present — skipping")

    if dry_run:
        log(f"would write {settings_path}")
        return
    save_json(settings_path, cfg)
    log(f"wrote {settings_path}")


def patch_mcp_config(mcp_path: Path, claude_home: Path, uv_path: str, dry_run: bool) -> None:
    cfg = load_json(mcp_path)
    servers = cfg.setdefault("mcpServers", {})
    server_script = str(claude_home / "narthex" / "mcp" / "server.py")
    entry = {
        "command": uv_path,
        "args": ["run", "--quiet", "--script", server_script],
    }
    if servers.get("narthex") == entry:
        log("narthex MCP server already registered — skipping")
    else:
        servers["narthex"] = entry
        log("registered narthex MCP server")

    if dry_run:
        log(f"would write {mcp_path}")
        return
    save_json(mcp_path, cfg)
    log(f"wrote {mcp_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Install Narthex into Claude Code.")
    parser.add_argument("--dry-run", action="store_true", help="print actions without making changes")
    parser.add_argument("--home", default=None, help="Claude Code config directory (default: ~/.claude)")
    args = parser.parse_args()

    claude_home = Path(args.home).expanduser() if args.home else Path.home() / ".claude"
    if not claude_home.is_dir():
        log(f"ERROR: Claude Code config directory not found at {claude_home}")
        log("Install Claude Code first: https://code.claude.com/")
        return 1

    uv_path = find_uv()
    log(f"using uv: {uv_path}")
    log(f"Claude Code config directory: {claude_home}")
    if args.dry_run:
        log("DRY RUN — no filesystem changes will be made")

    settings_path = claude_home / "settings.json"
    # Claude Code reads its global MCP registry from ~/.claude.json (top-level,
    # sibling to the config dir), NOT ~/.claude/mcp_config.json (which is
    # Claude Desktop's format and ignored by Claude Code).
    mcp_path = claude_home.parent / (claude_home.name + ".json")

    backup_once(settings_path, args.dry_run)
    backup_once(mcp_path, args.dry_run)

    narthex_dir = claude_home / "narthex"
    if args.dry_run:
        log(f"would create {narthex_dir}")
    else:
        narthex_dir.mkdir(parents=True, exist_ok=True)

    copy_files(narthex_dir, args.dry_run)
    patch_settings(settings_path, claude_home, args.dry_run)
    patch_mcp_config(mcp_path, claude_home, uv_path, args.dry_run)

    log("")
    log("Installation complete.")
    log("Restart Claude Code for the MCP registration to take effect.")
    log("The Bash exfiltration hook is active immediately in new sessions.")
    log("")
    log(f"Run tests:   python3 {REPO}/tests/test_pre_bash.py")
    log(f"Audit log:   {narthex_dir}/audit.log")
    log(f"Uninstall:   python3 {REPO}/uninstall.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
