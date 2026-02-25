# Telegram Bot 遠程控制 - 快速開始

## 📱 3分鐘快速設置

### 1️⃣ 創建 Telegram Bot (30秒)
```
1. 打開 @BotFather: https://t.me/BotFather
2. 發送 /newbot
3. 輸入名稱: ClawOS_Bot
4. 輸入用戶名: clawos_bot (必須以 _bot 結尾)
5. 複製 Bot Token: 格式如 123456789:ABCdefGHI...
```

### 2️⃣ 獲取您的 User ID (15秒)
```
1. 打開 @userinfobot: https://t.me/userinfobot
2. 發送任何消息
3. 複製 User ID: 如 123456789
```

### 3️⃣ 配置並啟動 Bot (2分鐘)

在 Git Bash / WSL2 / Linux 中執行：

```bash
# 1. 編輯 .env 文件
cd /mnt/d/home/ClawOS
nano .env  # 或使用 vim /code .env

# 2. 填入以下值：
# TELEGRAM_BOT_TOKEN=你的Bot Token
# AUTHORIZED_USER_ID=你的User ID

# 3. 安裝依賴
python3 -m pip install -r scripts/telegram_requirements.txt

# 4. 啟動 Bot（測試模式）
python3 scripts/telegram_bot.py

# 5. 在手機打開 Telegram，找到您的 Bot，發送 /start
```

## 🎯 常用命令速查

| 命令 | 功能 | 示例 |
|------|------|------|
| `/status` | 系統狀態 | `/status` |
| `/git` | Git 狀態 | `/git` |
| `/build` | 構建專案 | `/build` |
| `/test` | 運行測試 | `/test` |
| `/check` | 檢查代碼 | `/check` |
| `/run <cmd>` | 自定義命令 | `/run ls -la` |
| `/ci` | CI 狀態 | `/ci` |

## 🚀 推薦使用內聯鍵聯鍵盤

啟動 Bot 後，直接點擊按鈕即可！

```
┌─────────────────────┐
│ [📊 Status] [🌿 Git]│
│ [🔨 Build]  [🧪 Test]│
│ [✅ Check]  [🔍 CI]  │
└─────────────────────┘
```

## ⚠️ 安全提醒

- ✅ **必須設置** `AUTHORIZED_USER_ID`
- ⚠️ 不要將您的 Bot Token 分享給任何人
- ⚠️ 不要將 User ID 設置為空（任何人都能控制！）

## 🆘 遇到問題？

查看完整文檔：`docs/TELEGRAM_BOT_SETUP.md`

常見問題：
1. **Bot 無回應** → 檢查 Token 是否正確
2. **命令被拒絕** → 檢查 User ID 是否匹配
3. **超時** → 構建命令可能需要 3-5 分鐘

---

**需要更多幫助？** 查看 `docs/TELEGRAM_BOT_SETUP.md` 完整文檔。
