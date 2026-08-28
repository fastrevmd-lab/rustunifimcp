#!/bin/sh
# scripts/audit-legacy-usage.sh
# Count INVOCATIONS of the legacy unifi-mcp tools across Claude Code session
# history. Output is TSV: count, tool name. Sorted most-used first.
#
# The legacy server is enuno/unifi-mcp-server on LXC 980; its tools appear in
# transcripts as mcp__unifi-mcp__<name>.
#
# A plain `grep -o mcp__unifi-mcp__[a-z_]*` DOES NOT WORK and is the reason this
# script parses JSON instead. Every session transcript embeds the server's full
# tool list in its prompt, so grep counts tool *availability*: it returns all
# ~198 registered tools at a near-uniform ~1,790 hits each (one per session).
# That sets the parity bar to "everything" and defeats the audit. Only a
# `"type":"tool_use"` block is an actual call.
set -eu

HISTORY_ROOT="${HISTORY_ROOT:-$HOME/.claude}"

find "$HISTORY_ROOT" -name '*.jsonl' -type f -print0 2>/dev/null \
  | xargs -0 cat 2>/dev/null \
  | python3 -c '
import json, sys, collections

calls = collections.Counter()

def walk(node):
    """Transcript records nest tool_use blocks at varying depths."""
    if isinstance(node, dict):
        if node.get("type") == "tool_use" and str(node.get("name", "")).startswith(
            "mcp__unifi-mcp__"
        ):
            calls[node["name"].removeprefix("mcp__unifi-mcp__")] += 1
        for value in node.values():
            walk(value)
    elif isinstance(node, list):
        for value in node:
            walk(value)

for line in sys.stdin:
    try:
        walk(json.loads(line))
    except Exception:
        continue

for name, count in calls.most_common():
    print(f"{count}\t{name}")
'
