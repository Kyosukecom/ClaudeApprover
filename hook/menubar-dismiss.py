#!/usr/bin/env python3
"""
Claude Code PostToolUse hook: dismisses the specific notification after tool execution.
Sends the tool_use_id so only the matching notification is removed.
"""
import json
import sys
import urllib.request

try:
    raw = sys.stdin.read()
    hook_input = json.loads(raw) if raw.strip() else {}
    tool_use_id = hook_input.get("tool_use_id", "")

    payload = json.dumps({"tool_use_id": tool_use_id}).encode()
    req = urllib.request.Request(
        "http://localhost:19482/api/dismiss",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=2)
except Exception:
    pass  # ClaudeApprover not running — ignore silently
