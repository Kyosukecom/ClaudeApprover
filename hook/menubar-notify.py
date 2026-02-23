#!/usr/bin/env python3
"""
Claude Code Notification hook: shows completion/status notifications in ClaudeApprover.
Fires when Claude finishes a task and waits for user input.
"""
import json
import sys
import urllib.request

APPROVER_URL = "http://localhost:19482/api/notify"

def main():
    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit(0)

    hook_input = json.loads(raw)
    message = hook_input.get("message", "")
    title = hook_input.get("title", "")
    session_id = hook_input.get("session_id", "")
    tool_use_id = hook_input.get("tool_use_id", "") or f"notif-{session_id}"

    payload = json.dumps({
        "tool_name": "Notification",
        "tool_input": {},
        "summary": message,
        "risk_level": "done",
        "risk_action": title or "タスク完了",
        "risk_description": message,
        "claude_description": "",
        "context": "",
        "tool_use_id": tool_use_id,
        "session_id": session_id,
    }).encode()

    req = urllib.request.Request(
        APPROVER_URL, data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass

    sys.exit(0)

if __name__ == "__main__":
    main()
