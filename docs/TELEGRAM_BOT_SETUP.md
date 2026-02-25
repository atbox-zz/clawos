# Telegram Bot Remote Control Setup Guide

本指南說明如何設置 Telegram Bot，讓你可以從手機遠程控制 Opencode/ClawOS 開發環境。

## 📋 功能特色

- ✅ 執行 shell 命令
- ✅ 查看 git 狀態和提交歷史
- ✅ 執行 cargo 命令（build, test, check）
- ✅ 監控 GitHub Actions 構建狀態
- ✅ 接收構建通知
- ✅ 內聯鍵盤快捷鍵

## 🚀 快速開始

### 步驟 1：創建 Telegram Bot

1. 在 Telegram 中打開 **[@BotFather](https://t.me/BotFather)**
2. 發送 `/newbot` 命令
3. 輸入您的 bot 名稱（例如：`ClawOS_Bot`）
4. 輸入用戶名稱（例如：`clawos_bot`，必須以 `_bot` 結尾）
5. BotFather 會給您一個 **Bot Token**，格式如：`123456789:ABCdefGHIjklMNOpqrsTUVwxyz`

⚠️ **保存好這個 Token！** 不要分享給任何人。

### 步驟 2：獲取您的 Telegram User ID

1. 在 Telegram 中打開 **[@userinfobot](https://t.me/userinfobot)**
2. 發送任何消息
3. Bot 會回複您的 **User ID**，格式如：`123456789`

⚠️ **只有這個 User ID 才能控制您的 bot！** 這是安全機制。

### 步驟 3：配置環境變量

編輯文件 `scripts/telegram_bot.env`（創建腳本已自動生成）：

```bash
# Telegram Bot Token (從 @BotFather 獲取)
TELEGRAM_BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz

# 您的 Telegram User ID (從 @userinfobot 獲取)
AUTHORIZED_USER_ID=123456789

# ClawOS/Opencode 工作目錄
WORKING_DIR=/mnt/d/home/ClawOS
```

### 步驟 4：安裝依賴

在 Windows（Git Bash）中：
```bash
python3 -m pip install -r scripts/telegram_requirements.txt
```

在 Linux/Mac/WSL2 中：
```bash
pip3 install -r scripts/telegram_requirements.txt
```

### 步驟 5：啟動 Bot

**臨時運行（測試）：**
```bash
python3 scripts/telegram_bot.py
```

**作為後台服務運行（推薦）：**

在 Linux/Mac/WSL2：
```bash
# 使用 nohup
nohup python3 scripts/telegram_bot.py > /tmp/telegram_bot.log 2>&1 &

# 或使用 systemd（見下方）
```

### 步驟 6：在手機上使用

1. 在手機 Telegram 應用中搜索您的 Bot
2. 發送 `/start` 命令
3. 使用內聯鍵盤按鈕或輸入命令

## 📱 可用命令

### 系統命令
- `/status` - 顯示系統狀態（OS, 磁盤, 內存, 時間）
- `/pwd` - 顯示當前工作目錄
- `/ls` - 列出當前目錄文件

### Git 命令
- `/git` - 顯示 git 狀態
- `/log [N]` - 顯示最近 N 次提交（默認：5）
- `/diff` - 顯示 git 差異
- `/branch` - 列出所有分支

### Cargo 命令
- `/build` - 運行 `cargo build --release`
- `/build_debug` - 運行 `cargo build` (debug)
- `/test` - 運行 `cargo test`
- `/check` - 運行 `cargo check`
- `/clippy` - 運行 `cargo clippy`

### 自定義命令
- `/run <command>` - 執行任何 shell 命令
  ```
  示例：
  /run ls -la
  /run git log --oneline -10
  /run cargo build --release --verbose
  ```

### GitHub Actions
- `/ci` - 檢查 GitHub Actions 構建狀態
- `/runs <N>` - 顯示最近 N 個工作流運行

## 🔒 安全說明

### User ID 驗證
- **必須設置** `AUTHORIZED_USER_ID`，否則任何人都可以控制！
- 只有這個 User ID 的用戶才可以發送命令
- 建議創建專用的測試 bot

### 命令白名單
 Bot 只允許執行以下命令：
```
ls, pwd, cd, cat, grep, find
git status, git log, git diff, git branch
cargo build, cargo test, cargo check, cargo clippy
python, python3, bash, echo, date, whoami
```

### 時間限制
- 默認超時：300 秒（5 分鐘）
- 長時間運行的命令可能會超時

## 🔧 高級配置

### Systemd 服務（Linux）

1. 創建服務文件：
```bash
sudo nano /etc/systemd/system/opencode-telegram-bot.service
```

2. 粘貼以下內容：
```ini
[Unit]
Description=Opencode Telegram Remote Control Bot
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/mnt/d/home/ClawOS
ExecStart=/usr/bin/python3 /mnt/d/home/ClawOS/scripts/telegram_bot.py
Restart=always
RestartSec=5
EnvironmentFile=/mnt/d/home/ClawOS/scripts/telegram_bot.env

[Install]
WantedBy=multi-user.target
```

3. 啟動服務：
```bash
sudo systemctl daemon-reload
sudo systemctl enable opencode-telegram-bot
sudo systemctl start opencode-telegram-bot
sudo systemctl status opencode-telegram-bot
```

4. 查看日誌：
```bash
sudo journalctl -u opencode-telegram-bot -f
```

### Windows 服務（可選）

使用 **NSSM** (Non-Sucking Service Manager)：

1. 下載 NSSM: https://nssm.cc/download
2. 安裝服務：
```cmd
nssm install OpencodeTelegramBot
nssm set OpencodeTelegramBot Application "C:\Path\To\python3.exe"
nssm set OpencodeTelegramBot AppParameters "D:\home\ClawOS\scripts\telegram_bot.py"
nssm set OpencodeTelegramBot AppDirectory "D:\home\ClawOS"
nssm install OpencodeTelegramBot
nssm start OpencodeTelegramBot
```

## 📸 截圖示例

### 內聯鍵盤
```
┌──────────────────────────┐
│  🤖 Opencode Bot         │
├──────────────────────────┤
│  [📊 Status] [🌿 Git]    │
│  [🔨 Build]   [🧪 Test]  │
│  [✅ Check]   [🔍 CI]    │
└──────────────────────────┘
```

### 命令示例
```
您: /run cargo build --release

Bot: 🔄 Executing: `cargo build --release`...

Bot: ✅ Build Successful!

    Compiling clawos-security v0.1.0
    Compiling clawos-core-dev v0.1.0
    ...
    Finished release [optimized] target(s) in 2m 30s
```

## 🚨 故障排除

### Bot 無回應
1. 檢查 Bot Token 是否正確
2. 檢查 User ID 是否正確
3. 查看運行日誌：`cat /tmp/telegram_bot.log`

### 命令被拒絕
- 檢查命令是否在白名單中
- 命令格式：`/run <command>`（不要忘記空格）

### 超時錯誤
- 命令運行時間超過 300 秒
- 可以修改腳本中的 `DEFAULT_TIMEOUT` 常量

### Windows 路徑問題
- 使用 Git Bash 或 WSL2
- 路徑格式：`/mnt/d/home/ClawOS`（而不是 `D:\home\ClawOS`）

## 📚 相關資源

- [Telegram Bot API](https://core.telegram.org/bots/api)
- [python-telegram-bot 文檔](https://docs.python-telegram-bot.org/)
- [BotFather](https://t.me/BotFather)

## 📞 支持

如有問題，請檢查：
1. Bot 是否正在運行
2. 日誌文件：`/tmp/telegram_bot.log`
3. Telegram Bot API 狀態：https://status.telegram.org/

---

**最後更新：** 2026-02-25
**作者：** ClawOS Project
**許可證：** Apache-2.0 / MIT
