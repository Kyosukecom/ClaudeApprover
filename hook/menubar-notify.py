#!/usr/bin/env python3
"""
Claude Code Notification hook: shows task completion in ClaudeApprover.
"""
import json
import sys
import urllib.request

APPROVER_URL = "http://localhost:19482/api/notify"
LOG_FILE = "/tmp/claude-notify-debug.log"

# Only these types trigger a "done" notification
SHOW_TYPES = {
    "task_complete",
    "stop",
    "",  # Some completion events may have empty type
}

# Definitely skip these
SKIP_TYPES = {
    "permission_prompt",
    "auth_success",
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

    # Log ALL notifications for debugging
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps({
            "type": notification_type,
            "title": title,
            "message": message[:100],
        }, ensure_ascii=False) + "\n")

    # Skip known non-completion types
    if notification_type in SKIP_TYPES:
        sys.exit(0)

    # Skip empty messages
    if not message.strip():
        sys.exit(0)

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
