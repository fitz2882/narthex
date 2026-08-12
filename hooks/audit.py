#!/usr/bin/env python3
"""
Narthex audit logger.

Appends every Bash / WebFetch tool call to ~/.claude/narthex/audit.log as a hash-chained
JSONL entry. Never blocks -- logging must not break the session.

Entries are chained through `ledger.append`, so removing or editing one after the fact is
detectable rather than silent. See hooks/ledger.py for why that matters.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ledger  # noqa: E402

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

    ledger.append(
        {
            "event": payload.get("hook_event_name"),
            "tool": payload.get("tool_name"),
            "session": payload.get("session_id"),
            "cwd": payload.get("cwd"),
            "input": tool_input,
        }
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
