# ClaudeApprover

Claude Code が危険なコマンドを実行しようとした時に、macOS のフローティングパネルでリアルタイム通知するアプリ。

**通常の開発操作（ファイル編集、git commit、npm install 等）では何も表示されません。**
`git push`、`rm -rf`、`sudo`、SSH接続など、本当に注意が必要な操作だけを通知します。

## スクリーンショット

通知パネルには以下が表示されます:
- **何をしようとしているか**（リモートにプッシュ、ファイル削除 等）
- **リスクの説明**（チーム全員のコードに反映される 等）
- **対象の詳細**（プッシュするコミット一覧、削除対象のファイル 等）
- **AI の意図**（Claude が英語で書いた説明を日本語に翻訳）

## 機能

| 機能 | 説明 |
|------|------|
| リスク分類 | コマンドを高/中/低の3段階に自動判定 |
| 自動ポップアップ | 危険なコマンド実行時にパネルが自動で出現 |
| コンテキスト表示 | git push → プッシュするコミット一覧、rm → 削除対象ファイル等 |
| 全デスクトップ対応 | Space を切り替えてもパネルが付いてくる |
| 自動消去 | 高リスク: 30秒、中リスク: 15秒で自動的に消える |
| 自動起動 | フックが ClaudeApprover を自動で起動（手動起動不要） |
| Ollama 翻訳 | Claude の英語説明をローカル LLM で日本語に翻訳 |

### リスク分類

| レベル | 動作 | 例 |
|--------|------|-----|
| 高リスク | **常に通知** | `git push`, `rm -rf`, `sudo`, `ssh`, `npm publish`, `git reset --hard` |
| 中リスク | allow-list にない場合のみ通知 | `docker`, `psql`, `firebase deploy`, `curl -X POST` |
| 低リスク | 通知なし（サイレント） | `git add/commit/pull`, `npm install`, `swift build`, `Edit`, `Write`, `ls`, `cat` |

## セットアップ

### 必要環境

- macOS 14 以上
- Swift 5.10+
- Python 3.10+
- [Ollama](https://ollama.ai)（オプション、Claude の説明を日本語翻訳する場合）

### 1. クローン & ビルド

```bash
git clone https://github.com/Kyosukecom/ClaudeApprover.git ~/Projects/ClaudeApprover
cd ~/Projects/ClaudeApprover
swift build
```

### 2. フックスクリプトを配置

```bash
mkdir -p ~/.claude/hooks
cp hook/menubar-approval.py ~/.claude/hooks/menubar-approval.py
chmod +x ~/.claude/hooks/menubar-approval.py
```

### 3. Claude Code にフックを登録

`~/.claude/settings.json` の `hooks` セクションに追加:

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

> **既に `hooks` セクションがある場合**: `PreToolUse` 配列にエントリを追加してください。

### 4. Ollama（オプション）

Claude の英語説明を日本語に翻訳したい場合:

```bash
# Ollama をインストール（https://ollama.ai）
ollama pull qwen2.5:1.5b
```

Ollama がなくても動作します（翻訳がスキップされ、英語のまま表示されます）。

### 5. 動作確認

新しい Claude Code セッションを開始して、`git push` 等のコマンドが実行されるとパネルが表示されます。
ClaudeApprover はフックが自動的に起動するので、手動で起動する必要はありません。

## アーキテクチャ

```
Claude Code がコマンドを実行しようとする
        ↓
PreToolUse Hook (Python) が起動
        ↓
リスク分類（パターンマッチ）
        ↓
┌─ 低リスク ──────→ 何もしない（サイレント）
│
├─ 中リスク + allow-list → 何もしない
│
└─ 中/高リスク ──→ コンテキスト収集（git log, rm対象等）
                        ↓
                   POST /api/notify（即座に返る、ブロックしない）
                        ↓
                   ClaudeApprover (Swift macOS アプリ)
                        ↓
                   フローティングパネル自動表示
                        ↓
                   承認は Claude Code のターミナルで行う
```

## ファイル構成

```
ClaudeApprover/
├── Package.swift              # Swift Package Manager 設定
├── Sources/
│   ├── ClaudeApproverApp.swift  # アプリエントリポイント + フローティングパネル管理
│   ├── Models.swift             # データモデル（ReviewRequest, NotificationItem等）
│   ├── ReviewManager.swift      # 通知の状態管理
│   ├── ReviewPopoverView.swift  # SwiftUI ポップアップUI
│   └── ReviewServer.swift       # HTTP サーバー（ポート 19482）
└── hook/
    └── menubar-approval.py      # Claude Code PreToolUse フック
```

## カスタマイズ

### 通知の表示時間を変更

`Sources/ReviewManager.swift` の `dismissDelay` を変更:

```swift
private let dismissDelay: TimeInterval = 15  // 秒（高リスクはこの2倍）
```

### リスクパターンを追加

`hook/menubar-approval.py` の `HIGH_RISK_PATTERNS` / `MEDIUM_RISK_PATTERNS` に正規表現を追加:

```python
(re.compile(r"\byour-command\b"), "操作名", "リスクの説明"),
```

## License

MIT
