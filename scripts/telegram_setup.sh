#!/bin/bash
# Setup script for Telegram Bot

set -e

echo "🤖 Setting up Opencode Telegram Bot..."
echo ""

# 1. Check Python installation
echo "📦 Checking Python installation..."
python3 --version || { echo "❌ Python 3 not found!"; exit 1; }

# 2. Install dependencies
echo "📦 Installing Python dependencies..."
pip3 install -r scripts/telegram_requirements.txt

# 3. Create .env.example if not exists
if [ ! -f scripts/telegram_bot.env ]; then
    echo "📝 Creating telegram_bot.env configuration file..."
    cat > scripts/telegram_bot.env << 'EOF'
# Telegram Bot Configuration
# Copy this file to telegram_bot.env and fill in your values

# Telegram Bot Token (from @BotFather)
TELEGRAM_BOT_TOKEN=your-bot-token-here

# Your Telegram User ID (get from @userinfobot)
# IMPORTANT: Only this user can control the bot!
AUTHORIZED_USER_ID=

# Maximum command execution time (seconds)
COMMAND_TIMEOUT=300

# ClawOS/Opencode working directory
WORKING_DIR=/mnt/d/home/ClawOS
EOF
    echo "✅ Created scripts/telegram_bot.env"
else
    echo "ℹ️  scripts/telegram_bot.env already exists"
fi

# 4. Create systemd service file (Linux)
if [ -d /etc/systemd/system ]; then
    echo "📝 Creating systemd service file..."
    cat > /tmp/opencode-telegram-bot.service << 'EOF'
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
EOF

    echo "📄 Systemd service file created at /tmp/opencode-telegram-bot.service"
    echo ""
    echo "To install systemd service:"
    echo "  1. Edit /tmp/opencode-telegram-bot.service and replace 'your-username'"
    echo "  2. Copy: sudo cp /tmp/opencode-telegram-bot.service /etc/systemd/system/"
    echo "  3. Enable: sudo systemctl enable opencode-telegram-bot"
    echo "  4. Start: sudo systemctl start opencode-telegram-bot"
    echo "  5. Status: sudo systemctl status opencode-telegram-bot"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 Next Steps:"
echo "  1. Create a Telegram Bot:"
echo "     - Open @BotFather in Telegram"
echo "     - Send /newbot and follow instructions"
echo "     - Copy your bot token"
echo ""
echo "  2. Get your User ID:"
echo "     - Open @userinfobot in Telegram"
echo "     - Send any message to get your User ID"
echo ""
echo "  3. Edit scripts/telegram_bot.env:"
echo "     - Set TELEGRAM_BOT_TOKEN"
echo "     - Set AUTHORIZED_USER_ID"
echo ""
echo "  4. Start the bot:"
echo "     python3 scripts/telegram_bot.py"
echo ""
echo "📱 On your phone:"
echo "  - Find your bot by name in Telegram"
echo "  - Send /start to begin"
echo "  - Use the inline buttons or commands"
