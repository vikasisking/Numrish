#!/usr/bin/env python3
"""
Number Bot v0.2.0 - Admin-only /status + /mask on|off + error alerts + auto relogin
Single-file ready-to-run.

Requirements:
pip install requests beautifulsoup4 pycountry python-telegram-bot==20.0
(Adjust telegram lib version if needed)
"""

import os
import re
import time
import json
import hashlib
import logging
import html
import threading
import asyncio
from datetime import datetime, timezone
from typing import Optional

import requests
from bs4 import BeautifulSoup
import pycountry

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
)

# -------------------------
# Config / Constants
# -------------------------
BOT_VERSION = "v0.2.0"
BUILD_DATE = "2025-10-12"

LOGIN_URL = "http://51.89.99.105/NumberPanel/signin"
XHR_URL = "http://51.89.99.105/NumberPanel/client/res/data_smscdr.php?fdate1=2025-09-05%2000:00:00&fdate2=2026-09-04%2023:59:59&frange=&fclient=&fnum=&fcli=&fgdate=&fgmonth=&fgrange=&fgclient=&fgnumber=&fgcli=&fg=0&sEcho=1&iColumns=9&sColumns=%2C%2C%2C%2C%2C%2C%2C%2C&iDisplayStart=0&iDisplayLength=02&mDataProp_0=0&sSearch_0=&bRegex_0=false&bSearchable_0=true&bSortable_0=true&mDataProp_1=1&sSearch_1=&bRegex_1=false&bSearchable_1=true&bSortable_1=true&mDataProp_2=2&sSearch_2=&bRegex_2=false&bSearchable_2=true&bSortable_2=true&mDataProp_3=3&sSearch_3=&bRegex_3=false&bSearchable_3=true&bSortable_3=true&mDataProp_4=4&sSearch_4=&bRegex_4=false&bSearchable_4=true&bSortable_4=true&mDataProp_5=5&sSearch_5=&bRegex_5=false&bSearchable_5=true&bSortable_5=true&mDataProp_6=6&sSearch_6=&bRegex_6=false&bSearchable_6=true&bSortable_6=true&mDataProp_7=7&sSearch_7=&bRegex_7=false&bSearchable_7=true&bSortable_7=true&mDataProp_8=8&sSearch_8=&bRegex_8=false&bSearchable_8=true&bSortable_8=false&sSearch=&bRegex=false&iSortCol_0=0&sSortDir_0=desc&iSortingCols=1&_=1756968295291"

USERNAME = os.getenv("USERNAME", "rishi890")
PASSWORD = os.getenv("PASSWORD", "rishi890")
BOT_TOKEN = os.getenv("BOT_TOKEN", "8191752561:AAEJilSRVFYP0znZrPnvqifebyrk4dRaJe8")

# Chat & Admin
CHAT_IDS = os.getenv("CHAT_IDS", "-1002988078993").split(",")  # csv of group ids
ADMIN_ID = int(os.getenv("ADMIN_ID", "7761576669"))
DEVELOPER_ID = os.getenv("DEVELOPER_ID", "@RISHIHEARTMAKER")
CHANNEL_LINK = os.getenv("CHANNEL_LINK", "https://t.me/TEAM56RJ")

# Headers
HEADERS = {"User-Agent": "Mozilla/5.0", "Referer": "http://51.89.99.105/NumberPanel/login"}
AJAX_HEADERS = {"User-Agent": "Mozilla/5.0", "X-Requested-With": "XMLHttpRequest", "Referer": "http://51.89.99.105/NumberPanel/client/SMSCDRStats"}

# Runtime state
MASKING_ENABLED = True
LOGIN_STATE = {"logged_in": False}
TOTAL_OTPS_SENT = 0
LAST_FETCH_TIME: Optional[str] = None
START_TIME = datetime.now(timezone.utc)

# Persistence files
SEEN_CACHE_FILE = "seen_cache.json"
LOG_FILE = "bot.log"
OTP_LOG_FILE = "otp_logs.txt"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger("numberbot")

# Session / seen
session = requests.Session()
seen = set()
EXTRA_CODES = {"Kosovo": "XK"}

# -------------------------
# Utilities
# -------------------------
def load_seen_cache():
    global seen
    try:
        if os.path.exists(SEEN_CACHE_FILE):
            with open(SEEN_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    seen = set(data)
            logger.info("Loaded seen cache (%d items).", len(seen))
    except Exception as e:
        logger.exception("Failed to load seen cache: %s", e)

def save_seen_cache():
    try:
        with open(SEEN_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(list(seen), f)
    except Exception as e:
        logger.exception("Failed to save seen cache: %s", e)

def country_to_flag(country_name: str) -> str:
    code = EXTRA_CODES.get(country_name)
    if not code:
        try:
            country = pycountry.countries.lookup(country_name)
            code = country.alpha_2
        except LookupError:
            return ""
    return "".join(chr(127397 + ord(c)) for c in code.upper())

def mask_number(number: str) -> str:
    if not MASKING_ENABLED:
        return number
    number = str(number)
    if len(number) <= 6:
        return number
    mid = len(number) // 2
    return number[:mid-1] + "***" + number[mid+2:]

def extract_otp(message: str) -> Optional[str]:
    message = (message or "").strip()
    keyword_regex = re.search(r"(?:otp|code|pin|password)[^\d]{0,10}(\d[\d\-]{3,8})", message, re.I)
    if keyword_regex:
        return re.sub(r"\D", "", keyword_regex.group(1))
    reverse_regex = re.search(r"(\d[\d\-]{3,8})[^\w]{0,10}(?:otp|code|pin|password)", message, re.I)
    if reverse_regex:
        return re.sub(r"\D", "", reverse_regex.group(1))
    generic_regex = re.findall(r"\b\d[\d\-]{3,8}\b", message)
    for num in generic_regex:
        num_clean = re.sub(r"\D", "", num)
        if 4 <= len(num_clean) <= 8 and not (1900 <= int(num_clean) <= 2099):
            return num_clean
    return None

def format_message(current_time_str, country, number, sender, message_text, otp=None):
    flag = country_to_flag(country)
    otp_line = f"<blockquote>🔑 <b>OTP:</b> <code>{html.escape(str(otp))}</code></blockquote>\n" if otp else ""
    formatted = (
        f"✅ <b>NumberBot {BOT_VERSION}</b>\n\n"
        f"<blockquote>🕰 <b>Time:</b> <b>{html.escape(current_time_str)}</b></blockquote>\n"
        f"<blockquote>🌍 <b>Country:</b> <b>{html.escape(country or 'Unknown')} {flag}</b></blockquote>\n"
        f"<blockquote>📱 <b>Service:</b> <b>{html.escape(str(sender))}</b></blockquote>\n"
        f"<blockquote>📞 <b>Number:</b> <b>{html.escape(mask_number(str(number)))}</b></blockquote>\n"
        f"{otp_line}"
        f"<blockquote>✉️ <b>Full Message:</b></blockquote>\n"
        f"<blockquote><code>{html.escape(str(message_text))}</code></blockquote>\n"
        f"<blockquote>🧩 <b>Powered By:</b> <b>{html.escape(str(DEVELOPER_ID))}</b></blockquote>\n"
    )
    return formatted

# -------------------------
# Login with retries + admin alert
# -------------------------
def login(max_retries: int = 3, delay: float = 3.0) -> bool:
    """Attempt login. On persistent failure, alert admin."""
    for attempt in range(1, max_retries + 1):
        try:
            res = session.get(LOGIN_URL, headers=HEADERS, timeout=12)
            soup = BeautifulSoup(res.text, "html.parser")
            captcha_text = None
            for string in soup.stripped_strings:
                if "What is" in string and "+" in string:
                    captcha_text = string.strip()
                    break
            match = re.search(r"What is\s*(\d+)\s*\+\s*(\d+)", captcha_text or "")
            if not match:
                logger.warning("Captcha not found on login page (attempt %d).", attempt)
                LOGIN_STATE["logged_in"] = False
            else:
                a, b = int(match.group(1)), int(match.group(2))
                payload = {"username": USERNAME, "password": PASSWORD, "capt": str(a + b)}
                res2 = session.post(LOGIN_URL, data=payload, headers=HEADERS, timeout=12)
                if "SMSCDRStats" in res2.text:
                    LOGIN_STATE["logged_in"] = True
                    logger.info("Logged in successfully (attempt %d).", attempt)
                    return True
                else:
                    logger.warning("Login response didn't include SMSCDRStats (attempt %d).", attempt)
                    LOGIN_STATE["logged_in"] = False
        except Exception as e:
            logger.exception("Exception during login attempt %d: %s", attempt, e)
            LOGIN_STATE["logged_in"] = False

        # retry delay
        if attempt < max_retries:
            time.sleep(delay)

    # After retries, alert admin
    try:
        alert = (
            f"⚠️ <b>ALERT:</b> NumberBot failed to login after {max_retries} attempts.\n"
            f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        )
        # we cannot call bot here (app not passed); but we will set LOGIN_STATE and rely on fetch loop to notify via app.bot
        logger.error("Login failed after %d attempts. Admin should be notified when bot has access to Telegram context.", max_retries)
    except Exception:
        logger.exception("Failed to prepare admin alert message.")
    return False

# -------------------------
# Telegram send with error alerts
# -------------------------
async def send_to_chats(app, text, reply_markup=None):
    global TOTAL_OTPS_SENT
    for chat_id in CHAT_IDS:
        try:
            await app.bot.send_message(
                chat_id=chat_id,
                text=text,
                reply_markup=reply_markup,
                disable_web_page_preview=True,
                parse_mode="HTML"
            )
            TOTAL_OTPS_SENT += 1
        except Exception as e:
            logger.exception("Failed to send to %s: %s", chat_id, e)
            # notify admin
            try:
                err_text = (
                    f"⚠️ <b>Send Failure Alert</b>\n\n"
                    f"Failed to send message to <code>{chat_id}</code>\n"
                    f"Reason: {html.escape(str(e))}\n"
                    f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                )
                await app.bot.send_message(chat_id=ADMIN_ID, text=err_text, parse_mode="HTML")
            except Exception as ee:
                logger.exception("Also failed to notify admin: %s", ee)

async def send_telegram_message_async(app, current_time, country, number, sender, message_text):
    otp = extract_otp(message_text)
    formatted = format_message(current_time, country, number, sender, message_text, otp)
    keyboard = [
        [InlineKeyboardButton("📱 Channel", url=f"{CHANNEL_LINK}")],
        [InlineKeyboardButton("👨‍💻 Developer", url=f"https://t.me/{DEVELOPER_ID.lstrip('@')}")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await send_to_chats(app, formatted, reply_markup=reply_markup)

# -------------------------
# Fetch loop
# -------------------------
def fetch_otp_loop(app):
    global LAST_FETCH_TIME
    logger.info("Starting OTP fetch loop...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    consecutive_login_failures = 0

    while True:
        try:
            # ensure logged in
            if not LOGIN_STATE.get("logged_in", False):
                ok = login(max_retries=3, delay=2.0)
                if not ok:
                    consecutive_login_failures += 1
                else:
                    consecutive_login_failures = 0

                # if repeated failures, notify admin via bot when possible
                if consecutive_login_failures >= 3:
                    try:
                        alert_text = (
                            f"⚠️ <b>ALERT:</b> Repeated login failures ({consecutive_login_failures}).\n"
                            f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                        )
                        loop.run_until_complete(app.bot.send_message(chat_id=ADMIN_ID, text=alert_text, parse_mode="HTML"))
                    except Exception:
                        logger.exception("Failed to notify admin about repeated login failures.")
                    # wait a bit longer before next attempt
                    time.sleep(10)

            # attempt to fetch XHR
            try:
                res = session.get(XHR_URL, headers=AJAX_HEADERS, timeout=18)
                data = res.json()
            except ValueError as ve:
                logger.exception("JSON decode error while fetching XHR: %s", ve)
                # notify admin once
                try:
                    loop.run_until_complete(app.bot.send_message(
                        chat_id=ADMIN_ID,
                        text=f"⚠️ <b>ALERT:</b> JSON decode error while fetching XHR. {html.escape(str(ve))}",
                        parse_mode="HTML"
                    ))
                except Exception:
                    logger.exception("Failed to notify admin about JSON error.")
                time.sleep(5)
                continue

            otps = data.get("aaData", [])
            otps = [row for row in otps if isinstance(row[0], str) and ":" in row[0]]

            new_found = False
            with open(OTP_LOG_FILE, "a", encoding="utf-8") as f:
                for row in otps:
                    time_ = row[0]
                    operator = str(row[1]).split("-")[0] if row[1] else ""
                    number = str(row[2])
                    sender = str(row[3])
                    message = str(row[4])

                    hash_id = hashlib.md5((number + time_ + message).encode()).hexdigest()
                    if hash_id in seen:
                        continue
                    seen.add(hash_id)
                    new_found = True

                    log_formatted = (
                        f"📱 Number:      {number}\n"
                        f"🏷️ Sender ID:   {sender}\n"
                        f"💬 Message:     {message}\n"
                        f"{'-'*60}\n"
                    )
                    logger.info(log_formatted)
                    f.write(log_formatted + "\n")

                    current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    try:
                        loop.run_until_complete(send_telegram_message_async(app, current_time, operator, number, sender, message))
                    except Exception:
                        logger.exception("Failed to schedule send task to Telegram.")

                if new_found:
                    LAST_FETCH_TIME = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    save_seen_cache()

            if not new_found:
                # less noisy than printing every loop
                logger.debug("No new OTPs found on this cycle.")

        except Exception as e:
            logger.exception("Unexpected error in fetch loop: %s", e)
            # notify admin
            try:
                loop.run_until_complete(app.bot.send_message(
                    chat_id=ADMIN_ID,
                    text=f"⚠️ <b>ALERT:</b> Fetch loop encountered an error: {html.escape(str(e))}",
                    parse_mode="HTML"
                ))
            except Exception:
                logger.exception("Failed to notify admin about fetch loop error.")
        # small delay (adjustable)
        time.sleep(1.5)

# -------------------------
# Telegram handlers (Admin-only status/mask)
# -------------------------
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uptime_delta = datetime.now(timezone.utc) - START_TIME
    secs = int(uptime_delta.total_seconds())
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    await update.message.reply_text(f"✅ NumberBot {BOT_VERSION} running.\nUptime: {h}h {m}m {s}s\nUse /status (admin) to view details.")

def is_admin(user_id: int) -> bool:
    return user_id == ADMIN_ID

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await update.message.reply_text("❌ You are not allowed to use this command.")
        return

    uptime_delta = datetime.now(timezone.utc) - START_TIME
    secs = int(uptime_delta.total_seconds())
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    uptime_str = f"{h}h {m}m {s}s"
    logged_in = "✅" if LOGIN_STATE.get("logged_in", False) else "❌"
    mask_state = "ON" if MASKING_ENABLED else "OFF"
    last_fetch = LAST_FETCH_TIME or "Never"
    text = (
        f"🤖 <b>NumberBot {BOT_VERSION} Status</b>\n\n"
        f"🕒 <b>Uptime:</b> {uptime_str}\n"
        f"📬 <b>Total OTPs Sent:</b> {TOTAL_OTPS_SENT}\n"
        f"🔁 <b>Logged in:</b> {logged_in}\n"
        f"🛡️ <b>Masking:</b> {mask_state}\n"
        f"⏱️ <b>Last fetch:</b> {last_fetch}\n"
    )
    await update.message.reply_text(text, parse_mode="HTML")

async def mask_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global MASKING_ENABLED
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await update.message.reply_text("❌ You are not allowed to use this command.")
        return
    args = context.args or []
    if not args:
        await update.message.reply_text("Usage: /mask on  OR  /mask off")
        return
    cmd = args[0].lower()
    if cmd in ("on", "true", "1"):
        MASKING_ENABLED = True
        await update.message.reply_text("✅ Number masking turned ON.")
    elif cmd in ("off", "false", "0"):
        MASKING_ENABLED = False
        await update.message.reply_text("⚠️ Number masking turned OFF. (Numbers will be sent unmasked)")
    else:
        await update.message.reply_text("Usage: /mask on  OR  /mask off")

# small convenience aliases
async def mask_on_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    update.message.text = "/mask on"
    await mask_command(update, context)

async def mask_off_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    update.message.text = "/mask off"
    await mask_command(update, context)

# -------------------------
# Startup
# -------------------------
def start_bot():
    load_seen_cache()
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    # handlers
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("mask", mask_command))   # /mask on|off
    app.add_handler(CommandHandler("mask_on", mask_on_command))
    app.add_handler(CommandHandler("mask_off", mask_off_command))

    # start fetch loop thread (pass app)
    def run_fetcher():
        try:
            # initial login attempt
            login()
        except Exception:
            logger.exception("Initial login attempt failed.")
        fetch_otp_loop(app)

    fetcher_thread = threading.Thread(target=run_fetcher, daemon=True)
    fetcher_thread.start()

    logger.info("Starting Telegram polling...")
    app.run_polling()

if __name__ == "__main__":
    try:
        start_bot()
    except KeyboardInterrupt:
        logger.info("Shutting down (KeyboardInterrupt). Saving seen cache.")
        save_seen_cache()
    except Exception:
        logger.exception("Fatal exception in main. Saving seen cache.")
        save_seen_cache()
