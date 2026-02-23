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
OLLAMA_TIMEOUT = 8

# ---------------------------------------------------------------------------
# Risk classification patterns (pre-compiled at module level)
# ---------------------------------------------------------------------------

# High risk: destructive / irreversible / external-facing
# These ALWAYS show a notification, even if allow-listed
HIGH_RISK_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Recursive/force deletion
    (re.compile(r"\brm\s+-[^\s]*r"), "フォルダごと削除",
     "ディレクトリとその中のファイルを全て削除します。ゴミ箱に入らないので復元できません。"),
    (re.compile(r"\brm\s+"), "ファイル削除",
     "ファイルを直接削除します。ゴミ箱に入らないので復元できません。"),
    (re.compile(r"\bfind\b.*-delete\b"), "ファイル一括削除",
     "条件に一致するファイルをまとめて削除します。"),
    (re.compile(r"\btruncate\b"), "ファイル内容の消去",
     "ファイルの中身を空にします。ファイル自体は残りますが内容は消えます。"),
    # Git: pushing/destroying history
    (re.compile(r"\bgit\s+push\s+--force"), "リモートに強制プッシュ",
     "リモートリポジトリの履歴を上書きします。他のメンバーの変更が消える可能性があります。"),
    (re.compile(r"\bgit\s+push\b"), "リモートにプッシュ",
     "ローカルの変更をGitHubなどのリモートリポジトリにアップロードします。チーム全員のコードに反映されます。"),
    (re.compile(r"\bgit\s+reset\s+--hard"), "変更を全て破棄",
     "コミットしていない作業中の変更が全て消えます。最後のコミット状態に戻ります。"),
    (re.compile(r"\bgit\s+clean\b"), "未追跡ファイル削除",
     "gitで管理していないファイル（新規作成したがgit addしていないもの等）を削除します。"),
    (re.compile(r"\bgit\s+checkout\s+\.\s*$"), "作業ツリーの変更を破棄",
     "編集中のファイルを全て最後のコミット状態に戻します。未コミットの変更が消えます。"),
    (re.compile(r"\bgit\s+restore\s+\.\s*$"), "作業ツリーの変更を破棄",
     "編集中のファイルを全て最後のコミット状態に戻します。未コミットの変更が消えます。"),
    (re.compile(r"\bgit\s+branch\s+-D\b"), "ブランチ強制削除",
     "ブランチを削除します。マージされていない変更も消えます。"),
    (re.compile(r"\bgit\s+stash\s+clear\b"), "stash全削除",
     "一時退避していた作業内容が全て消えます。"),
    # GitHub CLI merge
    (re.compile(r"\bgh\s+pr\s+merge\b"), "PRをマージ",
     "プルリクエストをメインブランチに統合します。本番環境に反映される可能性があります。"),
    # System admin
    (re.compile(r"\bsudo\b"), "管理者権限で実行",
     "root権限でコマンドを実行します。システム全体に影響する操作です。"),
    (re.compile(r"\breboot\b"), "パソコンの再起動",
     "システムが再起動されます。保存していない作業は失われます。"),
    (re.compile(r"\bshutdown\b"), "シャットダウン",
     "システムが停止します。"),
    # Remote script execution
    (re.compile(r"\bcurl\b.*\|\s*(ba)?sh\b"), "ネットからスクリプトを直接実行",
     "インターネットからダウンロードしたスクリプトをそのまま実行します。安全性が保証されません。"),
    (re.compile(r"\bwget\b.*\|\s*(ba)?sh\b"), "ネットからスクリプトを直接実行",
     "インターネットからダウンロードしたスクリプトをそのまま実行します。"),
    # Remote access
    (re.compile(r"\bssh\b"), "リモートサーバーに接続",
     "SSH経由で別のサーバーに接続します。接続先で操作を行えます。"),
    (re.compile(r"\bscp\b"), "リモートとファイル転送",
     "SSH経由で別のサーバーとファイルをやり取りします。"),
    (re.compile(r"\brsync\b"), "リモートとファイル同期",
     "ファイルをリモートと同期します。同期先のファイルが上書きされることがあります。"),
    # Dangerous utilities
    (re.compile(r"\bdd\b"), "ディスク直接書き込み",
     "記憶装置に直接データを書き込みます。誤操作でデータが消えて復旧不可になります。"),
    (re.compile(r"\bcrontab\b"), "定期実行スケジュール変更",
     "cronジョブ（自動実行スケジュール）を変更します。"),
    # Package publishing
    (re.compile(r"\bnpm\s+publish\b"), "npmに公開",
     "パッケージをnpmレジストリに公開します。誰でもインストール可能になります。"),
]

# Medium risk: state-modifying but recoverable
# Only notified if NOT in the allow-list
MEDIUM_RISK_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Deployments
    (re.compile(r"\bfirebase\s+deploy\b"), "Firebaseにデプロイ",
     "本番環境にデプロイします。ユーザーに公開される変更です。"),
    (re.compile(r"\bvercel\b.*deploy"), "Vercelにデプロイ",
     "本番環境にデプロイします。ユーザーに公開されます。"),
    (re.compile(r"\bgcloud\b.*deploy"), "GCPにデプロイ",
     "Google Cloudの本番環境にデプロイします。"),
    (re.compile(r"\bterraform\s+apply\b"), "Terraform適用",
     "クラウドインフラの構成を変更します。稼働中のサービスに影響する可能性があります。"),
    # Database direct access
    (re.compile(r"\bpsql\b"), "PostgreSQL操作",
     "データベースに直接コマンドを実行します。データの変更・削除が可能です。"),
    (re.compile(r"\bmysql\b"), "MySQL操作",
     "データベースに直接コマンドを実行します。データの変更・削除が可能です。"),
    # Docker
    (re.compile(r"\bdocker\b"), "Docker操作",
     "コンテナを操作します。動作中のサービスに影響する場合があります。"),
    (re.compile(r"\bkubectl\b"), "Kubernetes操作",
     "K8sクラスタを操作します。本番環境に影響する可能性があります。"),
    # Network requests sending data
    (re.compile(r"\bcurl\s+.*-X\s*(POST|PUT|DELETE|PATCH)"), "APIリクエスト送信",
     "外部APIにデータを送信（POST/PUT/DELETE等）します。"),
    (re.compile(r"\bcurl\s+.*--data"), "APIリクエスト送信",
     "外部APIにデータを送信します。"),
    (re.compile(r"\bcurl\s+.*-d\s"), "APIリクエスト送信",
     "外部APIにデータを送信します。"),
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


def _ollama_generate(prompt: str, max_tokens: int = 80) -> str | None:
    """Call Ollama and return the response text, or None on failure."""
    payload = json.dumps({
        "model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
        "options": {"num_predict": max_tokens, "temperature": 0.2},
    }).encode()
    req = urllib.request.Request(OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            text = json.loads(resp.read()).get("response", "").strip().strip('"\'').strip()
            return text if text else None
    except Exception:
        return None


def explain_for_non_engineer(cmd: str, claude_desc: str, risk_action: str) -> str | None:
    """Use Ollama to generate a non-engineer friendly Japanese explanation."""
    context = f"AIの意図: {claude_desc}\n" if claude_desc else ""
    prompt = (
        f"あなたはITに詳しくない人にコマンドの意味を説明するアシスタントです。\n"
        f"以下のコマンドが何をするのか、パソコンやデータにどんな影響があるのかを、"
        f"専門用語を使わずに日本語2文以内で簡潔に説明してください。\n\n"
        f"{context}"
        f"コマンド: {cmd[:150]}\n"
        f"操作名: {risk_action}\n\n"
        f"説明:"
    )
    return _ollama_generate(prompt, max_tokens=100)


def translate_claude_description(claude_desc: str) -> str | None:
    """Translate Claude's English description to non-engineer Japanese."""
    if not claude_desc:
        return None
    prompt = (
        f"以下の英語を、ITに詳しくない人でもわかる自然な日本語に翻訳してください。"
        f"専門用語は避け、1文で簡潔に。翻訳のみ出力:\n\n"
        f"{claude_desc}\n\n日本語:"
    )
    return _ollama_generate(prompt, max_tokens=60)


def summarize_fallback(tool_name: str, tool_input: dict) -> str:
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if cmd.startswith("rm "):
            return "ファイルやフォルダを削除しようとしています"
        if "git push" in cmd:
            return "コードをサーバーに送ろうとしています"
        if "git " in cmd:
            return "コードの管理操作をしています"
        if cmd.startswith("curl"):
            return "インターネットに接続しています"
        if cmd.startswith("ssh"):
            return "別のパソコンに接続しようとしています"
        if cmd.startswith("sudo"):
            return "管理者権限で操作しようとしています"
        return "コマンドを実行しようとしています"
    return f"{tool_name} を実行しようとしています"


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

    # Summary = risk_description (pre-written non-engineer Japanese)
    summary = risk_description or summarize_fallback(tool_name, tool_input)

    # Translate Claude's English description to Japanese (if available)
    claude_desc_ja = ""
    if claude_description:
        claude_desc_ja = translate_claude_description(claude_description) or claude_description

    notify_approver(
        tool_name, tool_input, summary,
        risk_level, risk_action, risk_description,
        claude_desc_ja,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
