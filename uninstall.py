#!/usr/bin/env python3
"""
Narthex uninstaller.

Removes ~/.claude/narthex/ and strips Narthex-owned entries from
~/.claude/settings.json and ~/.claude.json. Does NOT roll the config
files back to their pre-install state — use the *.pre-narthex backups
for that if you haven't made other changes since install.

Usage:
    python3 uninstall.py [--dry-run] [--home DIR] [--keep-files]

  --dry-run     Print what would happen without touching the filesystem.
  --home DIR    Override the Claude Code config directory (default: ~/.claude).
  --keep-files  Leave ~/.claude/narthex/ in place; only unwire the config.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

DEFAULT_ALLOW = {
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
}

DEFAULT_ASK = {
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
}


def log(msg: str) -> None:
    print(f"[narthex] {msg}")


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open() as f:
        return json.load(f)


def save_json(path: Path, data: dict) -> None:
    with path.open("w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def strip_hooks(cfg: dict) -> int:
    """Remove hook entries that invoke narthex/hooks/*.py. Returns count removed."""
    removed = 0
    hooks = cfg.get("hooks", {})
    for event_name, entries in hooks.items():
        kept = []
        for entry in entries:
            filtered_hooks = [
                h
                for h in entry.get("hooks", [])
                if "narthex/hooks/" not in h.get("command", "")
            ]
            if filtered_hooks:
                entry["hooks"] = filtered_hooks
                kept.append(entry)
            else:
                removed += 1
        hooks[event_name] = kept
    return removed


def strip_permissions(cfg: dict) -> int:
    perms = cfg.get("permissions", {})
    removed = 0
    for key, defaults in (("allow", DEFAULT_ALLOW), ("ask", set(DEFAULT_ASK))):
        arr = perms.get(key)
        if not isinstance(arr, list):
            continue
        new = [item for item in arr if item not in defaults]
        removed += len(arr) - len(new)
        perms[key] = new
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description="Uninstall Narthex.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--home", default=None)
    parser.add_argument("--keep-files", action="store_true")
    args = parser.parse_args()

    claude_home = Path(args.home).expanduser() if args.home else Path.home() / ".claude"
    if not claude_home.is_dir():
        log(f"ERROR: {claude_home} not found")
        return 1
    if args.dry_run:
        log("DRY RUN — no filesystem changes will be made")

    # 1. Strip settings.json
    settings_path = claude_home / "settings.json"
    if settings_path.exists():
        cfg = load_json(settings_path)
        hook_count = strip_hooks(cfg)
        perm_count = strip_permissions(cfg)
        log(f"settings.json: removed {hook_count} hook entries, {perm_count} permission rules")
        if not args.dry_run:
            save_json(settings_path, cfg)

    # 2. Strip ~/.claude.json (Claude Code's global MCP registry)
    mcp_path = claude_home.parent / (claude_home.name + ".json")
    if mcp_path.exists():
        cfg = load_json(mcp_path)
        servers = cfg.get("mcpServers", {})
        if "narthex" in servers:
            if not args.dry_run:
                del servers["narthex"]
                save_json(mcp_path, cfg)
            log(f"{mcp_path.name}: removed narthex server")
        else:
            log(f"{mcp_path.name}: narthex server not present — skipping")

    # 3. Remove ~/.claude/narthex/
    narthex_dir = claude_home / "narthex"
    if narthex_dir.exists():
        if args.keep_files:
            log(f"keeping {narthex_dir} (--keep-files)")
        else:
            if args.dry_run:
                log(f"would remove {narthex_dir}")
            else:
                shutil.rmtree(narthex_dir)
                log(f"removed {narthex_dir}")

    log("")
    log("Uninstall complete. Restart Claude Code to release the MCP server.")
    log("Backups of pre-install config files remain at *.pre-narthex.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
