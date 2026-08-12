#!/usr/bin/env python3
"""
Narthex audit ledger: append-only, hash-chained, and verifiable.

The audit log used to be plain JSONL. Anything that could write a file could rewrite it, and
nothing downstream could tell. That is not a hypothetical: an assistant editing this very log
with a loose substring match deleted eighteen entries in one command, and the only reason
anyone knew is that it said so afterwards. An audit log the observed party can silently
rewrite is not an audit log -- it is a convenience file that happens to contain findings.

Each entry now carries `prev`, the hash of the entry before it, and `hash`, the hash of this
entry's content chained to that. Deleting or editing a line breaks the chain from that point
on, and `verify()` reports where. This does not *prevent* tampering -- nothing running with
the same permissions can prevent it -- but it converts silent tampering into loud tampering,
which is the property an audit log actually needs.

Deliberately not attempted:
  - Signing. A key readable by this process is a key readable by anything that can edit the
    log, so a signature would prove no more than the chain does while implying much more.
  - Locking. Hooks are short-lived and concurrent; the append is a single atomic `write()` of
    one line, which is what keeps interleaved writers from corrupting each other.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from typing import Any, Iterator

LOG_PATH = os.path.expanduser("~/.claude/narthex/audit.log")
GENESIS = "0" * 64


def _canonical(entry: dict) -> str:
    """Stable serialisation, so the hash depends on content and not on key order."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)


def entry_hash(entry: dict) -> str:
    """Hash of an entry's content chained to its predecessor.

    `hash` itself is excluded, since it cannot be an input to its own computation. `prev` is
    included, which is what makes this a chain rather than a set of independent checksums.
    """
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


def _last_hash(path: str) -> str:
    """The hash of the final entry, or the genesis value for an empty or absent log.

    Reads backwards from the end of the file so that appending stays cheap on a log that has
    grown to tens of megabytes -- reading the whole file on every tool call would make the
    hook slow enough that someone would eventually turn it off.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return GENESIS
    if size == 0:
        return GENESIS

    window = min(size, 8192)
    with open(path, "rb") as handle:
        while True:
            handle.seek(max(0, size - window))
            tail = handle.read().splitlines()
            for line in reversed(tail):
                if not line.strip():
                    continue
                try:
                    return json.loads(line).get("hash") or GENESIS
                except Exception:
                    # A corrupt final line is itself a break in the chain; treat the log as
                    # discontinuous from here rather than pretending it ended cleanly.
                    return GENESIS
            if window >= size:
                return GENESIS
            window = min(size, window * 4)


def append(entry: dict, path: str = LOG_PATH) -> dict:
    """Appends one chained entry. Never raises -- logging must not break a session."""
    entry = dict(entry)
    entry.setdefault("ts", datetime.datetime.now(datetime.timezone.utc).isoformat())
    try:
        entry["prev"] = _last_hash(path)
        entry["hash"] = entry_hash(entry)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # One `write` of one line, opened in append mode: the kernel keeps concurrent hooks
        # from interleaving partial lines, which is why no lock is taken.
        with open(path, "a") as handle:
            handle.write(json.dumps(entry, default=str) + "\n")
    except Exception:
        pass
    return entry


def read_entries(path: str = LOG_PATH) -> Iterator[tuple[int, dict | None, str]]:
    """Yields `(line_number, parsed_entry_or_None, raw_line)` for every non-empty line."""
    try:
        with open(path, "r") as handle:
            for number, raw in enumerate(handle, start=1):
                if not raw.strip():
                    continue
                try:
                    yield number, json.loads(raw), raw
                except Exception:
                    yield number, None, raw
    except OSError:
        return


def verify(path: str = LOG_PATH) -> dict[str, Any]:
    """Walks the chain and reports the first place it stops making sense.

    Three distinct failures, reported separately because they mean different things:
      - `unparsable`: a line that is not JSON at all.
      - `content-altered`: an entry whose recorded hash does not match its content.
      - `chain-broken`: an entry whose `prev` is not the previous entry's hash, which is what
        a deletion looks like -- the surrounding entries are individually intact.

    Entries written before chaining existed have no `hash`, and are reported as `unchained`
    rather than as tampering. Calling honest history "broken" would train someone to ignore
    the output, which costs more than the unchained prefix does.
    """
    problems: list[dict] = []
    restarts: list[dict] = []
    total = 0
    unchained = 0
    expected_prev = GENESIS
    started = False
    unchained_since_last_link = False

    for number, entry, raw in read_entries(path):
        total += 1
        if entry is None:
            problems.append({"line": number, "kind": "unparsable", "detail": raw[:200].rstrip()})
            continue
        if "hash" not in entry:
            unchained += 1
            unchained_since_last_link = True
            continue
        if not started:
            # The chain begins at the first entry that has one; the unchained prefix is
            # history from before this existed, not evidence of anything.
            expected_prev = entry.get("prev", GENESIS)
            started = True

        if entry_hash(entry) != entry.get("hash"):
            problems.append({"line": number, "kind": "content-altered", "detail": "recorded hash does not match this entry's content"})
        elif entry.get("prev") != expected_prev:
            # A restart from genesis directly after unchained entries is what an upgrade looks
            # like: `append` reads the last line, finds no hash, and legitimately starts over.
            # Reporting that as tampering is how a tool teaches you to ignore it -- the real
            # log did exactly this across two hooks being updated minutes apart.
            #
            # It is NOT free: an attacker who deletes entries could insert one unchained line
            # and a genesis restart to mask the gap. So a restart is surfaced rather than
            # swallowed. Expected during an upgrade, worth a look at any other time.
            if unchained_since_last_link and entry.get("prev") == GENESIS:
                restarts.append({"line": number, "kind": "chain-restarted", "detail": "chain restarts here, directly after unchained entries — expected where hooks were upgraded mid-log"})
            else:
                problems.append({"line": number, "kind": "chain-broken", "detail": "previous hash does not match the entry above; something was removed or reordered"})
        expected_prev = entry.get("hash", expected_prev)
        unchained_since_last_link = False

    return {
        "path": path,
        "entries": total,
        "unchained": unchained,
        "restarts": restarts,
        "problems": problems,
        "ok": not problems,
    }


if __name__ == "__main__":
    import sys

    report = verify(sys.argv[1] if len(sys.argv) > 1 else LOG_PATH)
    print(json.dumps(report, indent=2))
    if report["restarts"]:
        print(
            f"\n{len(report['restarts'])} chain restart(s). Expected where the hooks were upgraded mid-log; "
            "anywhere else, check what happened at those lines.",
            file=sys.stderr,
        )
    if not report["ok"]:
        print(
            f"\n{len(report['problems'])} problem(s). A chain break means entries were removed or reordered "
            "after they were written; the entries themselves may still be individually intact.",
            file=sys.stderr,
        )
    sys.exit(0 if report["ok"] else 1)
