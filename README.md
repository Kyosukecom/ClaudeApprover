# ClaudeApprover

Claude Code のコマンド実行をリアルタイムで通知する macOS メニューバーアプリ。

## 機能

- **リスク分類**: 150+ パターンで高/中/低リスクを自動判定
- **自動ポップアップ**: 中/高リスクコマンド実行時にフローティングパネルが自動表示
- **非エンジニア向け説明**: コマンドの内容とリスクを日本語で分かりやすく表示
- **Ollama 要約**: ローカル LLM でコマンドを 15 文字以内に要約
- **自動起動**: フックが ClaudeApprover を自動で起動
- **自動消去**: 通知は一定時間後に自動で消える（高リスク: 30秒、中リスク: 15秒）

## アーキテクチャ

```
Claude Code → PreToolUse Hook (Python)
                ↓ リスク分類
            低リスク → スルー
            中リスク + allow-list → スルー
            中/高リスク → POST /api/notify → ClaudeApprover (Swift)
                                                ↓
                                          フローティングパネル自動表示
```

## セットアップ

### 1. ビルド

```bash
cd ~/Projects/ClaudeApprover
swift build
```

### 2. フック設定

`~/.claude/settings.json` に追加:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/menubar-approval.py",
            "timeout": 600
          }
        ]
      }
    ]
  }
}
```

### 3. フックスクリプト

`~/.claude/hooks/menubar-approval.py` を配置（リポジトリの `hook/menubar-approval.py` を参照）。

### 4. Ollama（オプション）

```bash
ollama pull qwen2.5:1.5b
```

## 必要環境

- macOS 14+
- Swift 5.10+
- Python 3.10+
- Ollama（オプション、要約用）
