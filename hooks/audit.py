#!/usr/bin/env python3
"""
Narthex audit logger.

Appends every Bash / WebFetch tool call to ~/.claude/narthex/audit.log as
JSONL. Never blocks — logging must not break the session.
"""

from __future__ import annotations

import datetime
import json
import os
import sys

LOG_PATH = os.path.expanduser("~/.claude/narthex/audit.log")
MAX_INPUT_CHARS = 4000


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        trimmed = {}
        for k, v in tool_input.items():
            if isinstance(v, str) and len(v) > MAX_INPUT_CHARS:
                trimmed[k] = v[:MAX_INPUT_CHARS] + f"...[truncated {len(v) - MAX_INPUT_CHARS} chars]"
            else:
                trimmed[k] = v
        tool_input = trimmed

    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": payload.get("hook_event_name"),
        "tool": payload.get("tool_name"),
        "session": payload.get("session_id"),
        "cwd": payload.get("cwd"),
        "input": tool_input,
    }

    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass

    sys.exit(0)


if __name__ == "__main__":
    main()
