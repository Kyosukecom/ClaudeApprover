#!/usr/bin/env python3
"""
Claude Code PreToolUse hook: sends tool invocations to ClaudeApprover menubar app.
- Reads JSON from stdin (tool_name, tool_input, permission_mode, etc.)
- Classifies risk level (high/medium/low) based on patterns
- Only notifies for genuinely risky operations
- Uses Claude's own description field for context
- Auto-starts ClaudeApprover if needed
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error

APPROVER_URL = "http://localhost:19482/api/notify"
APPROVER_HEALTH_URL = "http://localhost:19482/api/health"
APPROVER_BINARY = os.path.expanduser("~/Projects/ClaudeApprover/.build/debug/ClaudeApprover")
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:1.5b"
OLLAMA_TIMEOUT = 3

# ---------------------------------------------------------------------------
# Risk classification patterns (pre-compiled at module level)
# ---------------------------------------------------------------------------

# High risk: destructive / irreversible / external-facing
# These ALWAYS show a notification, even if allow-listed
HIGH_RISK_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Recursive/force deletion
    (re.compile(r"\brm\s+-[^\s]*r"), "フォルダごと削除", "指定したフォルダとその中身が全て消えます。復元できません。"),
    (re.compile(r"\brm\s+"), "ファイル削除", "指定したファイルが消えます。ゴミ箱には入りません。"),
    (re.compile(r"\bfind\b.*-delete\b"), "一括削除", "条件に合うファイルをまとめて削除します。"),
    (re.compile(r"\btruncate\b"), "ファイル内容消去", "ファイルの中身が空になります。"),
    # Git: pushing/destroying history
    (re.compile(r"\bgit\s+push\s+--force"), "Git 強制プッシュ", "リモートの履歴を上書きします。他の人の作業が消える可能性があります。"),
    (re.compile(r"\bgit\s+push\b"), "Git プッシュ", "コードをサーバー（GitHub等）に送信します。チーム全員に影響します。"),
    (re.compile(r"\bgit\s+reset\s+--hard"), "Git 変更破棄", "まだ保存していない編集内容が全て消えます。"),
    (re.compile(r"\bgit\s+clean\b"), "Git 未追跡ファイル削除", "Gitで管理していないファイルを削除します。"),
    (re.compile(r"\bgit\s+checkout\s+\.\s*$"), "Git 編集取り消し", "現在の編集内容を全て元に戻します。"),
    (re.compile(r"\bgit\s+restore\s+\.\s*$"), "Git 編集取り消し", "現在の編集内容を全て元に戻します。"),
    (re.compile(r"\bgit\s+branch\s+-D\b"), "ブランチ強制削除", "ブランチを完全に削除します。マージされていない変更も消えます。"),
    (re.compile(r"\bgit\s+stash\s+clear\b"), "一時保存を全削除", "一時保存していた作業内容が全て消えます。"),
    # GitHub CLI merge
    (re.compile(r"\bgh\s+pr\s+merge\b"), "PR マージ", "プルリクエストを本番ブランチに統合します。"),
    # System admin
    (re.compile(r"\bsudo\b"), "管理者権限で実行", "パソコン全体に影響を与える操作です。慎重に確認してください。"),
    (re.compile(r"\breboot\b"), "パソコン再起動", "パソコンが再起動されます。作業中のものは失われます。"),
    (re.compile(r"\bshutdown\b"), "パソコン停止", "パソコンがシャットダウンされます。"),
    # Remote script execution
    (re.compile(r"\bcurl\b.*\|\s*(ba)?sh\b"), "外部スクリプト実行", "インターネットからダウンロードしたプログラムをそのまま実行します。安全性が不明です。"),
    (re.compile(r"\bwget\b.*\|\s*(ba)?sh\b"), "外部スクリプト実行", "インターネットからダウンロードしたプログラムをそのまま実行します。"),
    # Remote access
    (re.compile(r"\bssh\b"), "リモートサーバー接続", "別のサーバーに接続して操作を行います。"),
    (re.compile(r"\bscp\b"), "リモートファイル転送", "別のサーバーとファイルをやり取りします。"),
    (re.compile(r"\brsync\b"), "リモート同期", "別のサーバーとファイルを同期します。"),
    # Dangerous utilities
    (re.compile(r"\bdd\b"), "ディスク直接書き込み", "ハードディスクに直接データを書き込みます。誤操作でデータが消えます。"),
    (re.compile(r"\bcrontab\b"), "定期実行設定", "パソコンで定期的にプログラムを実行する設定を変更します。"),
    # Package publishing
    (re.compile(r"\bnpm\s+publish\b"), "パッケージ公開", "作成したプログラムをインターネット上に公開します。"),
]

# Medium risk: state-modifying but recoverable / expected dev operations
# Only notified if NOT in the allow-list
MEDIUM_RISK_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Deployments
    (re.compile(r"\bfirebase\s+deploy\b"), "Firebase デプロイ", "ウェブサイトやAPIを本番環境に公開します。"),
    (re.compile(r"\bvercel\b.*deploy"), "Vercel デプロイ", "ウェブサイトを本番環境に公開します。"),
    (re.compile(r"\bgcloud\b.*deploy"), "Google Cloud デプロイ", "サービスをクラウドに公開します。"),
    (re.compile(r"\bterraform\s+apply\b"), "インフラ変更適用", "クラウドのサーバー構成を変更します。"),
    # Database direct access
    (re.compile(r"\bpsql\b"), "データベース操作", "PostgreSQLデータベースに直接コマンドを実行します。"),
    (re.compile(r"\bmysql\b"), "データベース操作", "MySQLデータベースに直接コマンドを実行します。"),
    # Docker (can affect running services)
    (re.compile(r"\bdocker\b"), "Docker操作", "コンテナ（仮想環境）を操作します。動作中のサービスに影響する場合があります。"),
    (re.compile(r"\bkubectl\b"), "Kubernetes操作", "本番サーバーのコンテナを操作します。"),
    # Network requests sending data
    (re.compile(r"\bcurl\s+.*-X\s*(POST|PUT|DELETE|PATCH)"), "API送信", "外部サービスにデータを送信します。"),
    (re.compile(r"\bcurl\s+.*--data"), "API送信", "外部サービスにデータを送信します。"),
    (re.compile(r"\bcurl\s+.*-d\s"), "API送信", "外部サービスにデータを送信します。"),
]

# Everything else is LOW risk (normal development flow) — no notification needed.
# This includes: git add/commit/pull/checkout, npm install, swift build, python3,
# file read/write/edit, ls, cat, grep, etc.
# These are standard Claude Code operations that don't need user attention.


def classify_risk(tool_name: str, tool_input: dict) -> tuple[str, str, str]:
    """Classify risk level of a tool invocation.
    Returns (level, action, description) where level is 'high', 'medium', or 'low'.
    """
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        for pattern, action, risk in HIGH_RISK_PATTERNS:
            if pattern.search(cmd):
                return ("high", action, risk)
        for pattern, action, risk in MEDIUM_RISK_PATTERNS:
            if pattern.search(cmd):
                return ("medium", action, risk)
        # Everything else is low risk — normal dev operations
        return ("low", "", "")

    # Edit/Write are normal Claude Code operations — always low risk
    return ("low", "", "")


# ---------------------------------------------------------------------------
# Allow-list checking
# ---------------------------------------------------------------------------

def _has_compound_operators(cmd: str) -> bool:
    """Check if command contains compound operators (; && || standalone &)."""
    for ch in (";", "&&", "||"):
        if ch in cmd:
            return True
    i = 0
    while i < len(cmd):
        if cmd[i] == "&":
            if i + 1 < len(cmd) and cmd[i + 1] in ("&", ">"):
                i += 2
                continue
            return True
        i += 1
    return False


def _load_settings_files() -> list[dict]:
    """Load all relevant settings.json files."""
    results = []
    for name in ("settings.json", "settings.local.json"):
        path = os.path.expanduser(f"~/.claude/{name}")
        if os.path.isfile(path):
            try:
                with open(path) as f:
                    results.append(json.load(f))
            except (json.JSONDecodeError, OSError):
                pass
    cwd = os.getcwd()
    seen = set()
    d = cwd
    while True:
        if d in seen:
            break
        seen.add(d)
        for name in ("settings.json", "settings.local.json"):
            path = os.path.join(d, ".claude", name)
            if os.path.isfile(path):
                try:
                    with open(path) as f:
                        results.append(json.load(f))
                except (json.JSONDecodeError, OSError):
                    pass
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return results


def _match_allow_pattern(pattern: str, tool_name: str, cmd: str) -> bool:
    m = re.match(r"^(\w+)(?:\((.+)\))?$", pattern)
    if not m:
        return False
    if m.group(1) != tool_name:
        return False
    pat_arg = m.group(2)
    if pat_arg is None:
        return True
    if pat_arg.endswith(":*"):
        return cmd.startswith(pat_arg[:-2])
    return cmd == pat_arg


def is_allowed_by_settings(tool_name: str, tool_input: dict) -> bool:
    """Check if the tool invocation is allow-listed."""
    if tool_name != "Bash":
        return False
    cmd = tool_input.get("command", "")
    if _has_compound_operators(cmd):
        return False
    for settings in _load_settings_files():
        for pattern in settings.get("permissions", {}).get("allow", []):
            if _match_allow_pattern(pattern, tool_name, cmd):
                return True
    return False


# ---------------------------------------------------------------------------
# Summarization
# ---------------------------------------------------------------------------

def read_input():
    raw = sys.stdin.read()
    if not raw.strip():
        return None
    return json.loads(raw)


def summarize_with_ollama(tool_name: str, tool_input: dict) -> str | None:
    """Get a Japanese summary from Ollama."""
    detail = tool_input.get("command", "")[:200] if tool_name == "Bash" else ""
    prompt = (
        f"以下のコマンドを日本語で15文字以内で簡潔に要約してください。説明不要、要約のみ出力:\n"
        f"ツール: {tool_name}\n内容: {detail}"
    )
    payload = json.dumps({
        "model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
        "options": {"num_predict": 30, "temperature": 0.1},
    }).encode()
    req = urllib.request.Request(OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            summary = json.loads(resp.read()).get("response", "").strip().strip('"\'').strip()
            return summary if summary else None
    except Exception:
        return None


def summarize_fallback(tool_name: str, tool_input: dict) -> str:
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if cmd.startswith("rm "):
            return "ファイル/フォルダの削除"
        if "git push" in cmd:
            return "コードをサーバーに送信"
        if "git " in cmd:
            return "Git操作"
        if cmd.startswith("curl"):
            return "HTTPリクエスト"
        return "コマンド実行"
    return f"{tool_name} 実行"


# ---------------------------------------------------------------------------
# Approver communication (with auto-start)
# ---------------------------------------------------------------------------

def _is_approver_running() -> bool:
    req = urllib.request.Request(APPROVER_HEALTH_URL)
    try:
        with urllib.request.urlopen(req, timeout=1) as resp:
            return resp.status == 200
    except Exception:
        return False


def _ensure_approver_running() -> bool:
    if _is_approver_running():
        return True
    if not os.path.isfile(APPROVER_BINARY):
        return False
    try:
        subprocess.Popen([APPROVER_BINARY], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        return False
    for _ in range(20):
        time.sleep(0.2)
        if _is_approver_running():
            return True
    return False


def notify_approver(
    tool_name: str, tool_input: dict, summary: str,
    risk_level: str, risk_action: str, risk_description: str,
    claude_description: str,
) -> bool:
    """Send notification to ClaudeApprover (fire-and-forget)."""
    payload = json.dumps({
        "tool_name": tool_name,
        "tool_input": tool_input,
        "summary": summary,
        "risk_level": risk_level,
        "risk_action": risk_action,
        "risk_description": risk_description,
        "claude_description": claude_description,
    }).encode()
    req = urllib.request.Request(APPROVER_URL, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def main():
    hook_input = read_input()
    if not hook_input:
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    # Claude's own description of what it's doing (available for Bash)
    claude_description = tool_input.get("description", "")

    # Step 1: Classify risk
    risk_level, risk_action, risk_description = classify_risk(tool_name, tool_input)

    # Step 2: Low risk → no notification (normal dev operations)
    if risk_level == "low":
        sys.exit(0)

    # Step 3: Medium risk + allow-listed → no notification
    if risk_level == "medium" and is_allowed_by_settings(tool_name, tool_input):
        sys.exit(0)

    # Step 4: Notify (medium not-allowed / high always)
    _ensure_approver_running()

    summary = summarize_with_ollama(tool_name, tool_input)
    if not summary:
        summary = summarize_fallback(tool_name, tool_input)

    notify_approver(
        tool_name, tool_input, summary,
        risk_level, risk_action, risk_description,
        claude_description,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
