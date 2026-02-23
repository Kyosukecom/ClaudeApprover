#!/usr/bin/env python3
"""
Claude Code PostToolUse hook: dismisses ClaudeApprover notification after tool execution.
When the user approves a command in the terminal, this hook fires and tells
ClaudeApprover to close the notification panel.
"""
import urllib.request

try:
    req = urllib.request.Request(
        "http://localhost:19482/api/dismiss",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=2)
except Exception:
    pass  # ClaudeApprover not running — ignore silently
