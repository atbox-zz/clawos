#!/usr/bin/env python3
"""
Telegram Bot for Remote Control of Opencode/ClawOS

This script creates a Telegram bot that allows remote control of the
development environment from mobile devices.

Features:
- Execute shell commands
- View git status and commit history
- Run cargo commands (build, test, check)
- Monitor GitHub Actions status
- Receive build notifications

Author: ClawOS Project
License: Apache-2.0 / MIT
"""

import asyncio
import logging
import os
import subprocess
import json
from datetime import datetime
from typing import Optional

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    CallbackContext,
    CallbackQueryHandler,
)

# ============================================================================
# Configuration
# ============================================================================

# Load environment variables
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
AUTHORIZED_USER_ID = os.getenv("AUTHORIZED_USER_ID", "")  # Your Telegram user ID

# Security settings
ALLOWED_COMMANDS = [
    "ls",
    "pwd",
    "cd",
    "cat",
    "grep",
    "find",
    "git status",
    "git log",
    "git diff",
    "git branch",
    "cargo build",
    "cargo test",
    "cargo check",
    "cargo clippy",
    "python",
    "python3",
    "bash",
    "echo",
    "date",
    "whoami",
]

MAX_OUTPUT_LENGTH = 4000  # Telegram message size limit

# ============================================================================
# Logging
# ============================================================================

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ============================================================================
# Command Execution
# ============================================================================


def execute_command(command: str, timeout: int = 300) -> tuple[str, str, int]:
    """
    Execute a shell command and return stdout, stderr, and exit code.

    Args:
        command: The command to execute
        timeout: Maximum execution time in seconds

    Returns:
        Tuple of (stdout, stderr, exit_code)
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/mnt/d/home/ClawOS",  # ClawOS working directory
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except Exception as e:
        return "", f"Error: {str(e)}", -1


def validate_command(command: str) -> bool:
    """
    Validate that a command is allowed to execute.

    Args:
        command: The command to validate

    Returns:
        True if allowed, False otherwise
    """
    cmd_parts = command.strip().split(maxsplit=1)
    if not cmd_parts:
        return False

    base_cmd = cmd_parts[0]

    # Check if base command is in allowed list
    for allowed in ALLOWED_COMMANDS:
        if base_cmd == allowed or base_cmd == allowed.split()[0]:
            return True

    return False


def truncate_output(output: str, max_length: int = MAX_OUTPUT_LENGTH) -> str:
    """Truncate output to fit Telegram message size limit."""
    if len(output) <= max_length:
        return output

    truncation_msg = f"\n\n... Output truncated ({len(output)} total chars) ..."
    return output[: max_length - len(truncation_msg)] + truncation_msg


# ============================================================================
# Telegram Bot Handlers
# ============================================================================


async def start(update: Update, context: CallbackContext) -> None:
    """Handle /start command."""
    user_id = update.effective_user.id

    # Check authorization
    if AUTHORIZED_USER_ID and str(user_id) != AUTHORIZED_USER_ID:
        await update.message.reply_text(
            f"⛔ Unauthorized access\nUser ID: {user_id}\n\n"
            "You don't have permission to use this bot."
        )
        logger.warning(f"Unauthorized access attempt by user {user_id}")
        return

    welcome_message = (
        "🤖 *Opencode/ClawOS Remote Control Bot*\n\n"
        "Welcome! You can now control your development environment from your phone.\n\n"
        "*Available Commands:*\n"
        "/start - Show this welcome message\n"
        "/help - Display all available commands\n"
        "/status - Show system status\n"
        "/git - Show git status\n"
        "/build - Run cargo build --release\n"
        "/test - Run cargo test\n"
        "/check - Run cargo check\n"
        "/run <command> - Execute a custom shell command\n"
        "\n*KeyboardShortcuts:* Tap buttons below for quick actions"
    )

    keyboard = [
        [
            InlineKeyboardButton("📊 Status", callback_data="status"),
            InlineKeyboardButton("🌿 Git Status", callback_data="git_status"),
        ],
        [
            InlineKeyboardButton("🔨 Build", callback_data="build"),
            InlineKeyboardButton("🧪 Test", callback_data="test"),
        ],
        [
            InlineKeyboardButton("✅ Check", callback_data="check"),
            InlineKeyboardButton("🔍 CI Status", callback_data="ci_status"),
        ],
    ]

    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        welcome_message, reply_markup=reply_markup, parse_mode="Markdown"
    )


async def help_command(update: Update, context: CallbackContext) -> None:
    """Handle /help command."""
    help_text = (
        "📚 *Available Commands:*\n\n"
        "*System Commands:*\n"
        "/status - Show system status (OS, disk, memory)\n"
        "/pwd - Show current working directory\n"
        "/ls - List files in current directory\n\n"
        "*Git Commands:*\n"
        "/git - Show git status\n"
        "/log [N] - Show last N commits (default: 5)\n"
        "/diff - Show git diff\n"
        "/branch - List all branches\n\n"
        "*Cargo Commands:*\n"
        "/build - Run cargo build --release\n"
        "/build_debug - Run cargo build (debug)\n"
        "/test - Run cargo test\n"
        "/check - Run cargo check\n"
        "/clippy - Run cargo clippy\n\n"
        "*Custom Commands:*\n"
        "/run <command> - Execute any shell command\n"
        "  Example: /run git log --oneline -10\n\n"
        "*GitHub Actions:*\n"
        "/ci - Check GitHub Actions build status\n"
        "/runs <N> - Show last N workflow runs\n\n"
        "⚠️ *Note:* All commands have a 5-minute timeout."
    )

    await update.message.reply_text(help_text, parse_mode="Markdown")


async def status(update: Update, context: CallbackContext) -> None:
    """Show system status."""
    status_parts = []

    # System info
    stdout, _, _ = execute_command("uname -a")
    status_parts.append(f"🖥️ *System:*\n`{stdout.strip()}`\n")

    # Disk usage
    stdout, _, _ = execute_command("df -h /mnt/d | tail -1")
    status_parts.append(f"💾 *Disk Usage:*\n`{stdout.strip()}`\n")

    # Current time
    stdout, _, _ = execute_command("date")
    status_parts.append(f"🕰️ *Time:*\n`{stdout.strip()}`\n")

    # Git status
    stdout, _, _ = execute_command("cd /mnt/d/home/ClawOS && git branch --show-current")
    status_parts.append(f"🌿 *Git Branch:*\n`{stdout.strip()}`\n")

    await update.message.reply_text("\n".join(status_parts), parse_mode="Markdown")


async def git_status(update: Update, context: CallbackContext) -> None:
    """Show git status."""
    stdout, stderr, code = execute_command(
        "cd /mnt/d/home/ClawOS && git status --short"
    )

    if code == 0 and stdout:
        message = f"🌿 *Git Status:*\n\n```\n{stdout.strip()}\n```"
    else:
        message = "✅ Working tree is clean (no changes)"

    await update.message.reply_text(message, parse_mode="Markdown")


async def git_log(update: Update, context: Update, ctx: CallbackContext) -> None:
    """Show git commit log."""
    # Get argument (number of commits)
    limit = 5
    if context.args and context.args[0].isdigit():
        limit = min(int(context.args[0]), 20)  # Max 20 commits

    stdout, _, code = execute_command(
        f"cd /mnt/d/home/ClawOS && git log --oneline -{limit}"
    )

    if code == 0:
        message = f"📜 *Last {limit} Commits:*\n\n```\n{stdout.strip()}\n```"
        await update.message.reply_text(message, parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ Failed to get git log")


async def build(update: Update, context: CallbackContext) -> None:
    """Run cargo build --release."""
    await update.message.reply_text(
        "🔨 Starting cargo build --release...\nThis may take a few minutes..."
    )

    stdout, stderr, code = execute_command(
        "cd /mnt/d/home/ClawOS && cargo build --release", timeout=600
    )

    output = stdout + stderr
    output = truncate_output(output)

    if code == 0:
        message = f"✅ *Build Successful!*\n\n```\n{output}\n```"
    else:
        message = f"❌ *Build Failed (exit code: {code})*\n\n```\n{output}\n```"

    await update.message.reply_text(message, parse_mode="Markdown")


async def test(update: Update, context: CallbackContext) -> None:
    """Run cargo test."""
    await update.message.reply_text(
        "🧪 Running cargo test...\nThis may take a few minutes..."
    )

    stdout, stderr, code = execute_command(
        "cd /mnt/d/home/ClawOS && cargo test", timeout=600
    )

    # Show only test results (last 50 lines)
    lines = (stdout + stderr).split("\n")
    test_output = "\n".join(lines[-50:])

    if code == 0:
        message = f"✅ *Tests Passed!*\n\n```\n{test_output}\n```"
    else:
        message = f"❌ *Tests Failed (exit code: {code})*\n\n```\n{test_output}\n```"

    await update.message.reply_text(message, parse_mode="Markdown")


async def check(update: Update, context: CallbackContext) -> None:
    """Run cargo check."""
    await update.message.reply_text("✅ Running cargo check...")

    stdout, stderr, code = execute_command(
        "cd /mnt/d/home/ClawOS && cargo check", timeout=300
    )

    output = stdout + stderr
    output = truncate_output(output, 2000)

    if code == 0:
        message = f"✅ *Check Successful!*\n\n```\n{output}\n```"
    else:
        message = f"❌ *Check Failed (exit code: {code})*\n\n```\n{output}\n```"

    await update.message.reply_text(message, parse_mode="Markdown")


async def run_command(update: Update, context: CallbackContext) -> None:
    """Execute custom shell command."""
    if not context.args:
        await update.message.reply_text("Usage: /run <command>\nExample: /run ls -la")
        return

    command = " ".join(context.args)

    # Validate command
    if not validate_command(command):
        await update.message.reply_text(
            f"❌ Command not allowed: `{command}`\n\nAllowed commands:\n"
            + ", ".join(ALLOWED_COMMANDS[:10])
            + "..."
        )
        return

    await update.message.reply_text(
        f"🔄 Executing: `{command}`...", parse_mode="Markdown"
    )

    stdout, stderr, code = execute_command(command, timeout=300)

    output = stdout + stderr
    output = truncate_output(output)

    if code == 0:
        message = f"✅ *Success (exit code: 0)*\n\n```\n{output}\n```"
    else:
        message = f"⚠️ *Exit Code: {code}*\n\n```\n{output}\n```"

    await update.message.reply_text(message, parse_mode="Markdown")


async def get_ci_status() -> str:
    """Get GitHub Actions CI status using API."""
    import urllib.request
    import json

    try:
        url = "https://api.github.com/repos/atbox-zz/clawos/actions/runs?per_page=1"
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read())

        if data.get("total_count", 0) > 0:
            run = data["workflow_runs"][0]
            status = run.get("status", "unknown")
            conclusion = run.get("conclusion", "pending")
            name = run.get("name", "Unknown Workflow")
            url = run.get("html_url", "")

            emoji = (
                "🟡"
                if status == "in_progress"
                else "🟢"
                if conclusion == "success"
                else "🔴"
            )

            return f"{emoji} *{name}*\nStatus: `{status}`\nConclusion: `{conclusion}`\n\n[View in GitHub]({url})"
    except Exception as e:
        return f"❌ Failed to get CI status: {str(e)}"

    return "❌ No CI runs found"


async def ci_status(update: Update, context: CallbackContext) -> None:
    """Check GitHub Actions CI status."""
    await update.message.reply_text("🔄 Checking CI status...")

    status = await get_ci_status()
    await update.message.reply_text(status, parse_mode="Markdown")


# ============================================================================
# Inline Keyboard Handlers
# ============================================================================


async def button_callback(update: Update, context: CallbackContext) -> None:
    """Handle inline button callbacks."""
    query = update.callback_query
    await query.answer()

    data = query.data

    if data == "status":
        await status(update, context)
    elif data == "git_status":
        await git_status(update, context)
    elif data == "build":
        await build(update, context)
    elif data == "test":
        await test(update, context)
    elif data == "check":
        await check(update, context)
    elif data == "ci_status":
        await ci_status(update, context)


# ============================================================================
# Main Function
# ============================================================================


def main() -> None:
    """Start the Telegram bot."""
    if not TELEGRAM_BOT_TOKEN:
        print("❌ TELEGRAM_BOT_TOKEN not set in environment variables")
        print("Please set: export TELEGRAM_BOT_TOKEN='your-bot-token'")
        return

    print("🤖 Starting Opencode Telegram Bot...")
    print(f"📱 Bot Token: {TELEGRAM_BOT_TOKEN[:20]}...")
    print(
        f"🔐 Authorized User ID: {AUTHORIZED_USER_ID or 'Any user (not recommended!)'}"
    )

    # Create the Application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    # Register command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("status", status))
    application.add_handler(CommandHandler("git", git_status))
    application.add_handler(CommandHandler("log", git_log))
    application.add_handler(CommandHandler("build", build))
    application.add_handler(CommandHandler("test", test))
    application.add_handler(CommandHandler("check", check))
    application.add_handler(CommandHandler("run", run_command))
    application.add_handler(CommandHandler("ci", ci_status))

    # Register inline button handlers
    application.add_handler(CallbackQueryHandler(button_callback))

    # Start the bot
    print("✅ Bot started! Press Ctrl+C to stop")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
