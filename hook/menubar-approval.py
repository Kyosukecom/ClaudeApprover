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
APPROVER_BINARY = os.path.expanduser("~/bin/ClaudeApprover")
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
    # Supabase destructive
    (re.compile(r"\bsupabase\s+db\s+reset\b"), "Supabase DBリセット",
     "データベースを全て削除して再作成します。全データが消えます。"),
    (re.compile(r"\bsupabase\s+migration\s+repair\b"), "マイグレーション修復",
     "マイグレーション履歴を強制修正します。DBの整合性に影響します。"),
    (re.compile(r"\bsupabase\s+db\s+push\s+.*--include-all\b"), "Supabase 本番DBに全マイグレーション適用",
     "全マイグレーションを本番DBに適用します。CIと同等の操作です。"),
    (re.compile(r"\bsupabase\s+db\s+push\s+.*--linked\b"), "Supabase リモートDBにマイグレーション適用",
     "リンク先の本番/ステージングDBにマイグレーションを適用します。"),
    # GitHub PR/Issue destructive
    (re.compile(r"\bgh\s+pr\s+close\b"), "PRをクローズ",
     "プルリクエストを閉じます。マージされずに閉じられます。"),
    (re.compile(r"\bgh\s+issue\s+close\b"), "Issueをクローズ",
     "Issueを閉じます。"),
    (re.compile(r"\bgh\s+repo\s+delete\b"), "リポジトリ削除",
     "GitHubリポジトリを完全に削除します。復元できません。"),
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
    # Supabase state-changing
    (re.compile(r"\bsupabase\s+db\s+push\b"), "Supabase DBマイグレーション適用",
     "マイグレーションをDBに適用します。テーブル構造が変わります。"),
    (re.compile(r"\bsupabase\s+migration\s+(up|new)\b"), "Supabase マイグレーション操作",
     "マイグレーションを実行/作成します。DBスキーマに影響します。"),
    (re.compile(r"\bsupabase\s+functions\s+deploy\b"), "Supabase Edge Functions デプロイ",
     "Edge Functionsを本番にデプロイします。"),
    (re.compile(r"\bsupabase\s+secrets\s+(set|unset)\b"), "Supabase シークレット変更",
     "本番環境の環境変数（APIキー等）を変更します。"),
    (re.compile(r"\bsupabase\s+link\b"), "Supabase プロジェクトリンク",
     "CLIの接続先プロジェクトを変更します。以降のコマンドが別のDBを対象にします。"),
    # GitHub state-changing
    (re.compile(r"\bgh\s+pr\s+create\b"), "PR作成",
     "プルリクエストを作成します。レビュー対象になります。"),
    (re.compile(r"\bgh\s+pr\s+edit\b"), "PR編集",
     "プルリクエストのタイトル・本文・ラベル等を変更します。"),
    (re.compile(r"\bgh\s+issue\s+create\b"), "Issue作成",
     "GitHubにIssueを作成します。"),
    (re.compile(r"\bgh\s+release\s+create\b"), "リリース作成",
     "GitHubリリースを作成します。タグが作られます。"),
    # Vercel
    (re.compile(r"\bvercel\s+env\b"), "Vercel環境変数操作",
     "Vercelの環境変数を変更します。本番のAPIキー等に影響します。"),
    (re.compile(r"\bvercel\s+rm\b"), "Vercelデプロイメント削除",
     "Vercelのデプロイメントを削除します。"),
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
        # Check full command for high risk (e.g. rm -rf in any position)
        for pattern, action, risk in HIGH_RISK_PATTERNS:
            if pattern.search(cmd):
                return ("high", action, risk)
        # For medium risk, check the main command (skip cd prefix)
        main_cmd = _extract_main_command(cmd)
        for pattern, action, risk in MEDIUM_RISK_PATTERNS:
            if pattern.search(main_cmd):
                return ("medium", action, risk)
        # Everything else is low risk
        return ("low", "", "")

    if tool_name in ("Edit", "Write"):
        return ("low", "", "")

    if tool_name == "WebFetch":
        url = tool_input.get("url", "")
        return ("low", f"Webページ取得: {url[:50]}", "")

    if tool_name == "WebSearch":
        query = tool_input.get("query", "")
        return ("low", f"Web検索: {query[:50]}", "")

    # Other tools (Read, Glob, Grep, Task, etc.) — low risk
    return ("low", f"{tool_name}", "")


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


def _extract_main_command(cmd: str) -> str:
    """Extract the main command from compound expressions.
    'cd /some/path && gh issue create --title x' → 'gh issue create --title x'
    'cd /path && cd sub && npm install' → 'npm install'
    """
    if "&&" not in cmd and ";" not in cmd:
        return cmd
    # Split on && and ; and take the last non-cd part
    parts = re.split(r"\s*&&\s*|\s*;\s*", cmd)
    for part in reversed(parts):
        stripped = part.strip()
        if stripped and not stripped.startswith("cd "):
            return stripped
    return cmd


def is_allowed_by_settings(tool_name: str, tool_input: dict) -> bool:
    """Check if the tool invocation is allow-listed."""
    if tool_name != "Bash":
        return False
    cmd = tool_input.get("command", "")
    # For compound commands, check the main (non-cd) command
    main_cmd = _extract_main_command(cmd)
    for settings in _load_settings_files():
        for pattern in settings.get("permissions", {}).get("allow", []):
            if _match_allow_pattern(pattern, tool_name, main_cmd):
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


def gather_context(tool_name: str, tool_input: dict) -> str:
    """Gather contextual info about WHAT the command will affect."""
    if tool_name != "Bash":
        return ""
    cmd = tool_input.get("command", "")
    try:
        if re.search(r"\bgit\s+push\b", cmd):
            return _git_push_context(cmd)
        if re.search(r"\brm\s+", cmd):
            return _rm_context(cmd)
        if re.search(r"\bssh\b", cmd):
            return _ssh_context(cmd)
        if re.search(r"\bgit\s+reset\s+--hard", cmd):
            return _git_reset_context()
        if re.search(r"\bgit\s+branch\s+-D", cmd):
            return _git_branch_delete_context(cmd)
    except Exception:
        pass
    return ""


def _run_git(args: list[str], timeout: float = 3) -> str:
    """Run a git command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(
            ["git"] + args, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def _git_push_context(cmd: str) -> str:
    """What commits would be pushed?"""
    # Figure out branch
    branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"]) or "main"
    # Find remote tracking branch
    remote_branch = _run_git(["rev-parse", "--abbrev-ref", f"@{{upstream}}"]) or f"origin/{branch}"
    # Commits ahead of remote
    log = _run_git(["log", "--oneline", f"{remote_branch}..HEAD", "--max-count=10"])
    if not log:
        return f"ブランチ: {branch}（プッシュする新しいコミットはありません）"
    commit_count = len(log.strip().splitlines())
    # Files changed
    stat = _run_git(["diff", "--stat", f"{remote_branch}..HEAD"])
    stat_summary = stat.strip().splitlines()[-1] if stat.strip() else ""
    lines = [f"ブランチ: {branch} → {remote_branch}"]
    lines.append(f"プッシュするコミット ({commit_count}件):")
    for line in log.strip().splitlines()[:5]:
        lines.append(f"  {line}")
    if commit_count > 5:
        lines.append(f"  ... 他 {commit_count - 5}件")
    if stat_summary:
        lines.append(f"変更: {stat_summary}")
    return "\n".join(lines)


def _rm_context(cmd: str) -> str:
    """What files/dirs will be deleted?"""
    # Extract paths from rm command (skip flags)
    parts = cmd.split()
    targets = [p for p in parts[1:] if not p.startswith("-")]
    if not targets:
        return ""
    lines = ["削除対象:"]
    for t in targets[:5]:
        expanded = os.path.expanduser(t)
        if os.path.isdir(expanded):
            # Count files inside
            try:
                count = sum(len(files) for _, _, files in os.walk(expanded))
                lines.append(f"  📁 {t} ({count}ファイル)")
            except Exception:
                lines.append(f"  📁 {t}")
        elif os.path.exists(expanded):
            lines.append(f"  📄 {t}")
        else:
            lines.append(f"  ❓ {t} (存在しない)")
    if len(targets) > 5:
        lines.append(f"  ... 他 {len(targets) - 5}件")
    return "\n".join(lines)


def _ssh_context(cmd: str) -> str:
    """Extract connection target."""
    # Look for user@host pattern
    m = re.search(r"(\S+@\S+)", cmd)
    if m:
        return f"接続先: {m.group(1)}"
    return ""


def _git_reset_context() -> str:
    """Show what uncommitted changes would be lost."""
    status = _run_git(["status", "--short"])
    if not status:
        return "変更なし（影響は少ない）"
    lines = status.strip().splitlines()
    result = [f"失われる変更 ({len(lines)}ファイル):"]
    for line in lines[:8]:
        result.append(f"  {line}")
    if len(lines) > 8:
        result.append(f"  ... 他 {len(lines) - 8}件")
    return "\n".join(result)


def _git_branch_delete_context(cmd: str) -> str:
    """Show info about branch being deleted."""
    parts = cmd.split()
    # Find branch name (after -D flag)
    branch_name = ""
    for i, p in enumerate(parts):
        if p == "-D" and i + 1 < len(parts):
            branch_name = parts[i + 1]
            break
    if not branch_name:
        return ""
    # Check if merged
    merged = _run_git(["branch", "--merged", "main"])
    is_merged = branch_name in merged if merged else False
    log = _run_git(["log", "--oneline", f"main..{branch_name}", "--max-count=5"])
    lines = [f"ブランチ: {branch_name}"]
    lines.append(f"mainにマージ済み: {'はい' if is_merged else 'いいえ ⚠️'}")
    if log:
        lines.append("未マージのコミット:")
        for line in log.strip().splitlines():
            lines.append(f"  {line}")
    return "\n".join(lines)


def _low_risk_action(tool_name: str, tool_input: dict) -> str:
    """Generate a short action name for low-risk operations."""
    if tool_name == "Edit":
        path = tool_input.get("file_path", "")
        name = path.rsplit("/", 1)[-1] if "/" in path else path
        return f"ファイル編集: {name}"
    if tool_name == "Write":
        path = tool_input.get("file_path", "")
        name = path.rsplit("/", 1)[-1] if "/" in path else path
        return f"ファイル作成: {name}"
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        first_word = cmd.split()[0] if cmd.split() else cmd
        return f"コマンド実行: {first_word}"
    if tool_name == "WebFetch":
        url = tool_input.get("url", "")
        return f"Webページ取得: {url[:50]}"
    if tool_name == "WebSearch":
        query = tool_input.get("query", "")
        return f"Web検索: {query[:50]}"
    return f"{tool_name}"


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
    claude_description: str, context: str,
    tool_use_id: str, session_id: str,
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
        "context": context,
        "tool_use_id": tool_use_id,
        "session_id": session_id,
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
    tool_use_id = hook_input.get("tool_use_id", "")
    session_id = hook_input.get("session_id", "")

    # Claude's own description of what it's doing (available for Bash)
    claude_description = tool_input.get("description", "")

    # Step 1: Classify risk
    risk_level, risk_action, risk_description = classify_risk(tool_name, tool_input)

    # Step 2: Low risk → skip entirely (no notification)
    if risk_level == "low":
        sys.exit(0)

    # Step 3: Medium + allow-listed → skip
    if risk_level == "medium" and is_allowed_by_settings(tool_name, tool_input):
        sys.exit(0)

    # Step 4: Medium (not allowed) / High → notify
    _ensure_approver_running()

    summary = risk_description or summarize_fallback(tool_name, tool_input)
    context = gather_context(tool_name, tool_input)

    claude_desc_ja = ""
    if claude_description:
        claude_desc_ja = translate_claude_description(claude_description) or claude_description

    notify_approver(
        tool_name, tool_input, summary,
        risk_level, risk_action, risk_description,
        claude_desc_ja, context,
        tool_use_id, session_id,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
