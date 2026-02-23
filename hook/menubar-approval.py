#!/usr/bin/env python3
"""
Claude Code PreToolUse hook: sends tool invocations to ClaudeApprover menubar app for review.
- Reads JSON from stdin (tool_name, tool_input)
- Classifies risk level (high/medium/low) based on 150+ patterns
- Auto-approves allow-listed commands via settings.json
- Auto-passes low-risk commands (no review needed)
- Sends medium/high risk to ClaudeApprover with risk info
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
APPROVER_TIMEOUT = 600

# ---------------------------------------------------------------------------
# Risk classification patterns (pre-compiled at module level)
# Based on wataame/claude-code-explain-risk 150+ patterns
# ---------------------------------------------------------------------------

# High risk: destructive / irreversible / external access
HIGH_RISK_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # File deletion
    (re.compile(r"\brm\s+-[^\s]*r"), "再帰的ファイル削除", "ファイルが永久に失われる可能性"),
    (re.compile(r"\brm\s+"), "ファイル削除", "ファイルが失われる可能性"),
    (re.compile(r"\bfind\b.*-delete\b"), "find -delete", "条件に一致するファイルを一括削除"),
    (re.compile(r"\bfind\b.*-exec\b"), "find -exec", "検索結果に対して任意のコマンドを実行"),
    (re.compile(r"\btruncate\b"), "ファイル切り詰め", "ファイル内容が消去される"),
    # Git irreversible
    (re.compile(r"\bgit\s+push\s+--force\b"), "git force push", "リモート履歴が上書きされる"),
    (re.compile(r"\bgit\s+push\b"), "git push", "リモートリポジトリにコード送信"),
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "git reset --hard", "未コミットの変更が全て失われる"),
    (re.compile(r"\bgit\s+clean\b"), "git clean", "未追跡ファイルを削除"),
    (re.compile(r"\bgit\s+checkout\s+\.\s*$"), "git checkout .", "作業ツリーの変更を全て破棄"),
    (re.compile(r"\bgit\s+restore\s+\.\s*$"), "git restore .", "作業ツリーの変更を全て破棄"),
    (re.compile(r"\bgit\s+branch\s+-D\b"), "ブランチ強制削除", "ブランチが復元不可能に削除"),
    (re.compile(r"\bgit\s+stash\s+clear\b"), "stash全削除", "全stashが失われる"),
    (re.compile(r"\bgit\s+stash\s+drop\b"), "stash削除", "stashエントリが失われる"),
    # GitHub CLI
    (re.compile(r"\bgh\s+pr\s+merge\b"), "PR マージ", "プルリクエストをマージ"),
    # System admin
    (re.compile(r"\bsudo\b"), "管理者権限", "システム全体に影響を与える可能性"),
    (re.compile(r"\bsystemctl\b"), "サービス管理", "システムサービスの状態変更"),
    (re.compile(r"\blaunchctl\b"), "macOSサービス", "macOSシステムサービス操作"),
    (re.compile(r"\breboot\b"), "再起動", "システムが再起動される"),
    (re.compile(r"\bshutdown\b"), "シャットダウン", "システムが停止する"),
    # External script execution
    (re.compile(r"\bcurl\b.*\|\s*(ba)?sh\b"), "リモートスクリプト実行", "外部スクリプトを直接実行"),
    (re.compile(r"\bwget\b.*\|\s*(ba)?sh\b"), "リモートスクリプト実行", "外部スクリプトを直接実行"),
    # Permissions
    (re.compile(r"\bchmod\b"), "権限変更", "ファイルのアクセス権限を変更"),
    (re.compile(r"\bchown\b"), "所有者変更", "ファイルの所有者を変更"),
    # Process management
    (re.compile(r"\bkillall\b"), "全プロセス終了", "同名プロセスを全て終了"),
    (re.compile(r"\bkill\b"), "プロセス終了", "プロセスにシグナル送信"),
    # Remote access
    (re.compile(r"\bsshpass\b"), "SSH(パスワード)", "パスワード付きSSH接続"),
    (re.compile(r"\bssh\b"), "SSH接続", "リモートサーバーに接続"),
    (re.compile(r"\bscp\b"), "リモートコピー", "SSH経由でファイル転送"),
    (re.compile(r"\brsync\b"), "リモート同期", "ファイルをリモートと同期"),
    # In-place edit
    (re.compile(r"\bsed\s+-i\b"), "ファイル直接編集", "ファイルを直接書き換え"),
    # Dangerous utilities
    (re.compile(r"\bdd\b"), "低レベルI/O", "ディスクに直接書き込み"),
    (re.compile(r"\beval\b"), "任意コード実行", "動的にコードを評価・実行"),
    (re.compile(r"\bcrontab\b"), "定期実行設定", "スケジュールタスクを変更"),
    # Package publishing
    (re.compile(r"\bnpm\s+publish\b"), "パッケージ公開", "npmレジストリに公開"),
    # Shell redirects (write)
    (re.compile(r">>[^>]"), "ファイル追記", "ファイルにデータを追記"),
    (re.compile(r"(?<![>12])>[^>]"), "ファイル上書き", "ファイルを上書き"),
]

# Medium risk: state-modifying but typically recoverable
MEDIUM_RISK_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Package management
    (re.compile(r"\bnpm\s+(ci|install)\b"), "npm install", "パッケージをインストール"),
    (re.compile(r"\byarn\s+(add|install)\b"), "yarn install", "パッケージをインストール"),
    (re.compile(r"\bpip\s+install\b"), "pip install", "Pythonパッケージをインストール"),
    (re.compile(r"\bbrew\s+install\b"), "brew install", "Homebrewパッケージをインストール"),
    (re.compile(r"\bgem\s+install\b"), "gem install", "Rubyパッケージをインストール"),
    (re.compile(r"\bcargo\s+install\b"), "cargo install", "Rustパッケージをインストール"),
    (re.compile(r"\bconda\s+install\b"), "conda install", "Condaパッケージをインストール"),
    (re.compile(r"\bbun\s+(add|install)\b"), "bun install", "パッケージをインストール"),
    # Git modifications
    (re.compile(r"\bgit\s+add\b"), "git add", "ファイルをステージング"),
    (re.compile(r"\bgit\s+commit\b"), "git commit", "変更をコミット"),
    (re.compile(r"\bgit\s+checkout\b"), "git checkout", "ブランチ切り替え"),
    (re.compile(r"\bgit\s+merge\b"), "git merge", "ブランチをマージ"),
    (re.compile(r"\bgit\s+pull\b"), "git pull", "リモートから取得・マージ"),
    (re.compile(r"\bgit\s+clone\b"), "git clone", "リポジトリをクローン"),
    (re.compile(r"\bgit\s+rebase\b"), "git rebase", "コミット履歴を再構築"),
    (re.compile(r"\bgit\s+cherry-pick\b"), "git cherry-pick", "特定コミットを適用"),
    # File operations
    (re.compile(r"\bmkdir\b"), "ディレクトリ作成", "新しいフォルダを作成"),
    (re.compile(r"\btouch\b"), "ファイル作成/更新", "ファイルを作成または更新"),
    (re.compile(r"\bcp\b"), "ファイルコピー", "ファイルを複製"),
    (re.compile(r"\bmv\b"), "ファイル移動", "ファイルを移動/名前変更"),
    (re.compile(r"\bln\b"), "リンク作成", "シンボリック/ハードリンク作成"),
    (re.compile(r"\btee\b"), "tee出力", "標準出力とファイルに同時書き込み"),
    # Archive
    (re.compile(r"\btar\b"), "アーカイブ操作", "tar形式の圧縮/展開"),
    (re.compile(r"\bunzip\b"), "ZIP展開", "ZIPファイルを展開"),
    (re.compile(r"\bzip\b"), "ZIP圧縮", "ZIPファイルを作成"),
    # Script/program execution
    (re.compile(r"\bnpx\b"), "npx実行", "npmパッケージを直接実行"),
    (re.compile(r"\bnpm\s+(run|start|test)\b"), "npmスクリプト", "npmスクリプトを実行"),
    (re.compile(r"\bnode\b"), "Node.js実行", "JavaScriptを実行"),
    (re.compile(r"\bpython3?\b"), "Python実行", "Pythonスクリプトを実行"),
    (re.compile(r"\bruby\b"), "Ruby実行", "Rubyスクリプトを実行"),
    (re.compile(r"\bjest\b"), "Jestテスト", "JavaScriptテストを実行"),
    (re.compile(r"\bpytest\b"), "pytestテスト", "Pythonテストを実行"),
    (re.compile(r"\bplaywright\b"), "Playwright", "ブラウザ自動テスト"),
    (re.compile(r"\bbun\s+run\b"), "bunスクリプト", "bunスクリプトを実行"),
    (re.compile(r"\bbun\s+test\b"), "bunテスト", "bunテストを実行"),
    # Build tools
    (re.compile(r"\bmake\b"), "make", "ビルド自動化を実行"),
    (re.compile(r"\bcmake\b"), "cmake", "ビルドシステム生成"),
    (re.compile(r"\btsc\b"), "TypeScriptコンパイル", "TypeScriptをコンパイル"),
    (re.compile(r"\bwebpack\b"), "webpack", "モジュールバンドル実行"),
    (re.compile(r"\bswift\s+build\b"), "Swiftビルド", "Swiftプロジェクトをビルド"),
    (re.compile(r"\bswift\s+run\b"), "Swift実行", "Swiftプロジェクトを実行"),
    (re.compile(r"\bswift\s+test\b"), "Swiftテスト", "Swiftテストを実行"),
    # Code quality
    (re.compile(r"\beslint\b"), "ESLint", "JavaScript/TSリント実行"),
    (re.compile(r"\bprettier\b"), "Prettier", "コードフォーマット実行"),
    (re.compile(r"\bblack\b"), "Black", "Pythonフォーマット実行"),
    # Database/server
    (re.compile(r"\bflask\b"), "Flask", "Pythonサーバー操作"),
    (re.compile(r"\bpsql\b"), "PostgreSQL", "PostgreSQLクライアント"),
    (re.compile(r"\bmysql\b"), "MySQL", "MySQLクライアント"),
    (re.compile(r"\bsqlite3\b"), "SQLite", "SQLiteクライアント"),
    (re.compile(r"\bdocker\b"), "Docker", "コンテナ管理"),
    (re.compile(r"\bkubectl\b"), "Kubernetes", "K8sクラスタ管理"),
    (re.compile(r"\bsupabase\b"), "Supabase CLI", "Supabase操作"),
    # Network
    (re.compile(r"\bcurl\b"), "HTTPリクエスト", "HTTP通信を実行"),
    (re.compile(r"\bwget\b"), "ダウンロード", "ファイルをダウンロード"),
    # Cloud/deployment
    (re.compile(r"\bfirebase\s+deploy\b"), "Firebaseデプロイ", "Firebaseにデプロイ"),
    (re.compile(r"\bterraform\b"), "Terraform", "インフラ管理"),
    (re.compile(r"\bgcloud\b"), "Google Cloud", "GCPリソース操作"),
    (re.compile(r"\bvercel\b"), "Vercel", "Vercelデプロイ/操作"),
]

# Low risk: read-only / information-only commands
LOW_RISK_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # File listing/viewing
    (re.compile(r"^\s*ls\b"), "ファイル一覧", "ファイル一覧を表示"),
    (re.compile(r"^\s*cat\b"), "ファイル表示", "ファイル内容を表示"),
    (re.compile(r"^\s*head\b"), "先頭表示", "ファイル先頭を表示"),
    (re.compile(r"^\s*tail\b"), "末尾表示", "ファイル末尾を表示"),
    (re.compile(r"^\s*tree\b"), "ディレクトリ構造", "ツリー表示"),
    (re.compile(r"^\s*wc\b"), "行数/文字数", "ファイルの統計情報"),
    (re.compile(r"^\s*file\b"), "ファイル種別", "ファイルタイプを判定"),
    (re.compile(r"^\s*less\b"), "ページャ表示", "ファイルをページ送り表示"),
    (re.compile(r"^\s*more\b"), "ページャ表示", "ファイルをページ送り表示"),
    # Navigation
    (re.compile(r"^\s*pwd\b"), "現在のディレクトリ", "作業ディレクトリを表示"),
    (re.compile(r"^\s*cd\b"), "ディレクトリ移動", "ディレクトリを変更"),
    # System info
    (re.compile(r"^\s*uname\b"), "システム情報", "OS情報を表示"),
    (re.compile(r"^\s*hostname\b"), "ホスト名", "ホスト名を表示"),
    (re.compile(r"^\s*whoami\b"), "ユーザー名", "現在のユーザーを表示"),
    (re.compile(r"^\s*date\b"), "日時表示", "現在の日時を表示"),
    (re.compile(r"^\s*uptime\b"), "稼働時間", "システム稼働時間を表示"),
    (re.compile(r"^\s*which\b"), "コマンド場所", "コマンドのパスを表示"),
    (re.compile(r"^\s*type\b"), "コマンド種別", "コマンドの種類を表示"),
    (re.compile(r"^\s*echo\b"), "echo出力", "テキストを出力"),
    (re.compile(r"^\s*printf\b"), "printf出力", "テキストを出力"),
    (re.compile(r"^\s*env\b"), "環境変数", "環境変数を表示"),
    (re.compile(r"^\s*printenv\b"), "環境変数", "環境変数を表示"),
    # Text processing (read-only)
    (re.compile(r"^\s*grep\b"), "テキスト検索", "テキストパターンを検索"),
    (re.compile(r"^\s*rg\b"), "テキスト検索", "ripgrepで高速検索"),
    (re.compile(r"^\s*find\b(?!.*(-delete|-exec))"), "ファイル検索", "ファイルを検索"),
    (re.compile(r"^\s*diff\b"), "差分比較", "ファイルの差分を表示"),
    (re.compile(r"^\s*sort\b"), "ソート", "行をソートして表示"),
    (re.compile(r"^\s*uniq\b"), "重複除去", "重複行を除去して表示"),
    (re.compile(r"^\s*awk\b"), "テキスト処理", "テキストを加工して表示"),
    (re.compile(r"^\s*sed\b(?!.*-i)"), "テキスト変換", "テキストを変換して表示"),
    (re.compile(r"^\s*cut\b"), "フィールド抽出", "テキストの一部を抽出"),
    (re.compile(r"^\s*tr\b"), "文字変換", "文字を変換して表示"),
    (re.compile(r"^\s*jq\b"), "JSON処理", "JSONを解析・表示"),
    (re.compile(r"^\s*xargs\b"), "引数変換", "標準入力を引数に変換"),
    # Git read-only
    (re.compile(r"^\s*git\s+status\b"), "git status", "作業ツリーの状態を表示"),
    (re.compile(r"^\s*git\s+log\b"), "git log", "コミット履歴を表示"),
    (re.compile(r"^\s*git\s+branch\b(?!.*-[dD])"), "git branch", "ブランチ一覧を表示"),
    (re.compile(r"^\s*git\s+diff\b"), "git diff", "差分を表示"),
    (re.compile(r"^\s*git\s+show\b"), "git show", "コミット内容を表示"),
    (re.compile(r"^\s*git\s+remote\b"), "git remote", "リモート情報を表示"),
    (re.compile(r"^\s*git\s+tag\b"), "git tag", "タグ一覧を表示"),
    (re.compile(r"^\s*git\s+stash\s+list\b"), "git stash list", "stash一覧を表示"),
    (re.compile(r"^\s*git\s+rev-parse\b"), "git rev-parse", "Gitリファレンスを解決"),
    # Package info (read-only)
    (re.compile(r"^\s*npm\s+list\b"), "npm list", "パッケージ一覧を表示"),
    (re.compile(r"^\s*npm\s+ls\b"), "npm ls", "パッケージ一覧を表示"),
    (re.compile(r"^\s*npm\s+view\b"), "npm view", "パッケージ情報を表示"),
    (re.compile(r"^\s*pip\s+show\b"), "pip show", "パッケージ情報を表示"),
    (re.compile(r"^\s*pip\s+list\b"), "pip list", "パッケージ一覧を表示"),
    (re.compile(r"^\s*brew\s+info\b"), "brew info", "パッケージ情報を表示"),
    (re.compile(r"^\s*brew\s+list\b"), "brew list", "パッケージ一覧を表示"),
    # Network info (read-only)
    (re.compile(r"^\s*ping\b"), "ping", "接続テスト"),
    (re.compile(r"^\s*dig\b"), "DNS検索", "DNSレコードを照会"),
    (re.compile(r"^\s*nslookup\b"), "DNS照会", "DNSを照会"),
    # Misc read-only
    (re.compile(r"^\s*gh\s+pr\s+(list|view|status)\b"), "PR情報表示", "PRの状態を確認"),
    (re.compile(r"^\s*gh\s+issue\s+(list|view)\b"), "Issue情報表示", "Issueを確認"),
    (re.compile(r"^\s*gh\s+api\b"), "GitHub API", "GitHub APIを呼び出し"),
]


def classify_risk(tool_name: str, tool_input: dict) -> tuple[str, str, str]:
    """Classify risk level of a tool invocation.
    Returns (level, action, description) where level is 'high', 'medium', or 'low'.
    """
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        # Check high risk first (order matters: more specific patterns first)
        for pattern, action, risk in HIGH_RISK_PATTERNS:
            if pattern.search(cmd):
                return ("high", action, risk)
        # Then low risk (check before medium so read-only git commands are low)
        for pattern, action, risk in LOW_RISK_PATTERNS:
            if pattern.search(cmd):
                return ("low", action, risk)
        # Then medium risk
        for pattern, action, risk in MEDIUM_RISK_PATTERNS:
            if pattern.search(cmd):
                return ("medium", action, risk)
        # Unknown bash command defaults to medium
        return ("medium", "コマンド実行", "未分類のコマンド")

    elif tool_name in ("Edit", "Write"):
        path = tool_input.get("file_path", "")
        name = path.rsplit("/", 1)[-1] if "/" in path else path
        if tool_name == "Write":
            return ("medium", f"ファイル作成: {name}", "新しいファイルを作成")
        else:
            return ("medium", f"ファイル編集: {name}", "既存ファイルを編集")

    # Other tools default to medium
    return ("medium", f"{tool_name} 実行", "ツール実行")


# ---------------------------------------------------------------------------
# Allow-list checking (reads Claude Code settings.json permissions.allow)
# ---------------------------------------------------------------------------

_COMPOUND_RE = re.compile(r"(?:^|[^&|])[;]|&&|\|\||(?<![&])&(?!&)")


def _has_compound_operators(cmd: str) -> bool:
    """Check if command contains compound operators (; && || standalone &)."""
    # Simple check: look for ; && || or standalone &
    for ch in (";", "&&", "||"):
        if ch in cmd:
            return True
    # Standalone & (not && and not &> etc.)
    i = 0
    while i < len(cmd):
        if cmd[i] == "&":
            if i + 1 < len(cmd) and cmd[i + 1] == "&":
                i += 2
                continue
            if i + 1 < len(cmd) and cmd[i + 1] == ">":
                i += 2
                continue
            return True
        i += 1
    return False


def _load_settings_files() -> list[dict]:
    """Load all relevant settings.json files (global + project hierarchy)."""
    results = []
    # Global settings
    global_settings = os.path.expanduser("~/.claude/settings.json")
    if os.path.isfile(global_settings):
        try:
            with open(global_settings) as f:
                results.append(json.load(f))
        except (json.JSONDecodeError, OSError):
            pass
    # Also check settings.local.json
    global_local = os.path.expanduser("~/.claude/settings.local.json")
    if os.path.isfile(global_local):
        try:
            with open(global_local) as f:
                results.append(json.load(f))
        except (json.JSONDecodeError, OSError):
            pass
    # Walk from CWD up to root looking for .claude/settings*.json
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
    """Check if a single allow pattern matches the tool invocation.
    Patterns look like: "Bash(cat:*)", "Bash(git status:*)", "Edit", etc.
    """
    # Parse "ToolName(prefix:*)" or just "ToolName"
    m = re.match(r"^(\w+)(?:\((.+)\))?$", pattern)
    if not m:
        return False
    pat_tool = m.group(1)
    pat_arg = m.group(2)  # e.g. "cat:*" or "git status:*"

    if pat_tool != tool_name:
        return False
    if pat_arg is None:
        # Matches any invocation of this tool
        return True
    # Parse prefix:* pattern
    if pat_arg.endswith(":*"):
        prefix = pat_arg[:-2]
        return cmd.startswith(prefix)
    # Exact match
    return cmd == pat_arg


def is_allowed_by_settings(tool_name: str, tool_input: dict) -> bool:
    """Check if the tool invocation is allow-listed in settings.json."""
    if tool_name != "Bash":
        return False
    cmd = tool_input.get("command", "")
    # Compound commands bypass allow-list for safety
    if _has_compound_operators(cmd):
        return False

    settings_list = _load_settings_files()
    for settings in settings_list:
        permissions = settings.get("permissions", {})
        allow_list = permissions.get("allow", [])
        for pattern in allow_list:
            if _match_allow_pattern(pattern, tool_name, cmd):
                return True
    return False


# ---------------------------------------------------------------------------
# Ollama summarization (kept from original)
# ---------------------------------------------------------------------------

def read_input():
    """Read hook input from stdin."""
    raw = sys.stdin.read()
    if not raw.strip():
        return None
    return json.loads(raw)


def summarize_with_ollama(tool_name: str, tool_input: dict) -> str | None:
    """Try to get a Japanese summary from Ollama. Returns None on failure."""
    detail = _tool_detail(tool_name, tool_input)
    prompt = (
        f"以下のコマンドを日本語で15文字以内で簡潔に要約してください。説明不要、要約のみ出力:\n"
        f"ツール: {tool_name}\n"
        f"内容: {detail}"
    )
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": 30, "temperature": 0.1},
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            data = json.loads(resp.read())
            summary = data.get("response", "").strip()
            summary = summary.strip('"\'').strip()
            return summary if summary else None
    except Exception:
        return None


def summarize_fallback(tool_name: str, tool_input: dict) -> str:
    """Rule-based Japanese summary when Ollama is unavailable."""
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if cmd.startswith("rm "):
            return "ファイル/フォルダの削除"
        if cmd.startswith("mkdir"):
            return "ディレクトリ作成"
        if "git " in cmd:
            return "Git操作"
        if "npm " in cmd or "bun " in cmd:
            return "パッケージ操作"
        if cmd.startswith("curl"):
            return "HTTP リクエスト"
        if cmd.startswith("swift"):
            return "Swiftビルド/実行"
        return "コマンド実行"
    elif tool_name == "Write":
        path = tool_input.get("file_path", "")
        name = path.rsplit("/", 1)[-1] if "/" in path else path
        return f"ファイル作成: {name}"
    elif tool_name == "Edit":
        path = tool_input.get("file_path", "")
        name = path.rsplit("/", 1)[-1] if "/" in path else path
        return f"ファイル編集: {name}"
    else:
        return f"{tool_name} 実行"


def _tool_detail(tool_name: str, tool_input: dict) -> str:
    if tool_name == "Bash":
        return tool_input.get("command", "")[:200]
    elif tool_name == "Write":
        return tool_input.get("file_path", "")
    elif tool_name == "Edit":
        path = tool_input.get("file_path", "")
        old = tool_input.get("old_string", "")[:80]
        return f"{path} ({old}...)"
    return json.dumps(tool_input, ensure_ascii=False)[:200]


# ---------------------------------------------------------------------------
# Approver communication (with auto-start)
# ---------------------------------------------------------------------------

def _is_approver_running() -> bool:
    """Check if ClaudeApprover is responding on its health endpoint."""
    req = urllib.request.Request(APPROVER_HEALTH_URL)
    try:
        with urllib.request.urlopen(req, timeout=1) as resp:
            return resp.status == 200
    except Exception:
        return False


def _ensure_approver_running() -> bool:
    """Start ClaudeApprover if not running. Returns True if running after attempt."""
    if _is_approver_running():
        return True
    if not os.path.isfile(APPROVER_BINARY):
        print(f"[menubar-approval] Binary not found: {APPROVER_BINARY}", file=sys.stderr)
        return False
    try:
        subprocess.Popen(
            [APPROVER_BINARY],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as e:
        print(f"[menubar-approval] Failed to start ClaudeApprover: {e}", file=sys.stderr)
        return False
    # Wait for it to become ready
    for _ in range(20):  # up to 4 seconds
        time.sleep(0.2)
        if _is_approver_running():
            return True
    print("[menubar-approval] ClaudeApprover started but not responding", file=sys.stderr)
    return False


def notify_approver(
    tool_name: str,
    tool_input: dict,
    summary: str,
    risk_level: str,
    risk_action: str,
    risk_description: str,
) -> bool:
    """Send notification to ClaudeApprover (fire-and-forget). Returns True if sent."""
    payload = json.dumps({
        "tool_name": tool_name,
        "tool_input": tool_input,
        "summary": summary,
        "risk_level": risk_level,
        "risk_action": risk_action,
        "risk_description": risk_description,
    }).encode()

    req = urllib.request.Request(
        APPROVER_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
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

    # Step 1: Classify risk
    risk_level, risk_action, risk_description = classify_risk(tool_name, tool_input)

    # Step 2: Low risk → skip notification
    if risk_level == "low":
        sys.exit(0)

    # Step 3: Medium risk + allow-listed → skip notification
    if risk_level == "medium" and is_allowed_by_settings(tool_name, tool_input):
        sys.exit(0)

    # Step 4: Medium (not allow-listed) / High → notify ClaudeApprover (non-blocking)
    # Ensure ClaudeApprover is running (auto-start if needed)
    _ensure_approver_running()

    summary = summarize_with_ollama(tool_name, tool_input)
    if not summary:
        summary = summarize_fallback(tool_name, tool_input)

    notify_approver(
        tool_name, tool_input, summary,
        risk_level, risk_action, risk_description,
    )

    # Always exit 0 — approval is handled by Claude Code, not by this hook
    # This hook is notification-only
    sys.exit(0)


if __name__ == "__main__":
    main()
