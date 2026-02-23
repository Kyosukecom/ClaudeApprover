#!/usr/bin/env python3
"""
Claude Code Notification hook: shows task completion in ClaudeApprover.
Only fires for genuine "Claude finished, waiting for input" events.
Skips permission_prompt (already handled by PreToolUse hook).
"""
import json
import sys
import urllib.request

APPROVER_URL = "http://localhost:19482/api/notify"

# Notification types to IGNORE (handled elsewhere or not useful)
IGNORE_TYPES = {
    "permission_prompt",  # Handled by PreToolUse hook
    "auth_success",       # Login success, not interesting
}


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit(0)

    hook_input = json.loads(raw)
    notification_type = hook_input.get("notification_type", "")
    message = hook_input.get("message", "")
    title = hook_input.get("title", "")
    session_id = hook_input.get("session_id", "")

    # Skip ignored notification types
    if notification_type in IGNORE_TYPES:
        sys.exit(0)

    # Skip empty messages
    if not message.strip():
        sys.exit(0)

    tool_use_id = hook_input.get("tool_use_id", "") or f"notif-{session_id}-{notification_type}"

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
