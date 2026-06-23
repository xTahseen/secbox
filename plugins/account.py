import hashlib
from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton, ForceReply
from database.mongo import settings

# ── Conversation state: {user_id: "awaiting_username" | "awaiting_password"}
_state    = {}
_tmp_user = {}  # user_id → chosen username (held between steps)


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


async def _show_webui_panel(message, user_id, edit=False):
    """Show the main /webui panel with current account info."""
    doc = await settings.find_one({"user_id": user_id})
    has_account = doc and doc.get("webui_password_hash") and doc.get("webui_username")

    if has_account:
        uname = doc["webui_username"]
        text = (
            f"<b>🌐 WebUI Account</b>\n\n"
            f"✅ Account is set up\n"
            f"👤 Username: <code>{uname}</code>\n"
            f"🔒 Password: <i>hidden</i>\n\n"
            f"Use these credentials to log into the WebUI."
        )
        buttons = [
            [InlineKeyboardButton("✏️ Change Account", callback_data="webui_set")],
            [InlineKeyboardButton("🗑 Clear Account",   callback_data="webui_clear_confirm")],
        ]
    else:
        text = (
            "<b>🌐 WebUI Account</b>\n\n"
            "❌ No account set up yet.\n\n"
            "Tap <b>Set Account</b> to create your WebUI login credentials."
        )
        buttons = [
            [InlineKeyboardButton("➕ Set Account", callback_data="webui_set")],
        ]

    markup = InlineKeyboardMarkup(buttons)
    if edit:
        await message.edit_text(text, reply_markup=markup)
    else:
        await message.reply_text(text, reply_markup=markup)


# ── /webui command ─────────────────────────────────────────────────────────────

@Client.on_message(filters.command("webui") & filters.private)
async def webui_cmd(_, message):
    _state.pop(message.from_user.id, None)
    _tmp_user.pop(message.from_user.id, None)
    await _show_webui_panel(message, message.from_user.id)


# ── Callbacks ──────────────────────────────────────────────────────────────────

@Client.on_callback_query(filters.regex("^webui_set$"))
async def webui_set(_, query):
    uid = query.from_user.id
    _state[uid] = "awaiting_username"
    _tmp_user.pop(uid, None)
    await query.answer()
    await query.message.edit_text(
        "<b>🌐 Set WebUI Account</b>\n\n"
        "<b>Step 1 of 2 — Choose a username</b>\n\n"
        "Reply with the username you want to use on the WebUI login page.\n"
        "• At least 3 characters\n"
        "• Letters, numbers, underscores only\n"
        "• Not case-sensitive",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("❌ Cancel", callback_data="webui_cancel")]
        ])
    )
    await query.message.reply_text(
        "👤 Enter your desired WebUI username:",
        reply_markup=ForceReply(selective=True)
    )


@Client.on_callback_query(filters.regex("^webui_clear_confirm$"))
async def webui_clear_confirm(_, query):
    await query.answer()
    await query.message.edit_text(
        "<b>🗑 Clear WebUI Account</b>\n\n"
        "Are you sure? This will remove your WebUI login credentials.\n"
        "You won't be able to log into the WebUI until you set a new account.",
        reply_markup=InlineKeyboardMarkup([
            [
                InlineKeyboardButton("✅ Yes, Clear", callback_data="webui_clear_execute"),
                InlineKeyboardButton("❌ Cancel",     callback_data="webui_cancel"),
            ]
        ])
    )


@Client.on_callback_query(filters.regex("^webui_clear_execute$"))
async def webui_clear_execute(_, query):
    uid = query.from_user.id
    await query.answer("Account cleared.")
    await settings.update_one(
        {"user_id": uid},
        {"$unset": {"webui_password_hash": "", "webui_username": ""}},
    )
    await query.message.edit_text(
        "<b>✅ WebUI account cleared.</b>\n\n"
        "Your WebUI credentials have been removed.\n"
        "Use /webui to set up a new account.",
    )


@Client.on_callback_query(filters.regex("^webui_cancel$"))
async def webui_cancel(_, query):
    uid = query.from_user.id
    _state.pop(uid, None)
    _tmp_user.pop(uid, None)
    await query.answer("Cancelled.")
    await _show_webui_panel(query.message, uid, edit=True)


# ── Reply handler for username / password steps ────────────────────────────────

async def webui_reply_handler(_, message):
    uid = message.from_user.id
    step = _state.get(uid)
    if not step:
        return

    text = message.text.strip()

    if step == "awaiting_username":
        # Validate username
        import re
        if len(text) < 3:
            return await message.reply_text("⚠️ Username must be at least 3 characters. Try again:")
        if not re.match(r"^[a-zA-Z0-9_]+$", text):
            return await message.reply_text("⚠️ Only letters, numbers, and underscores allowed. Try again:")

        username = text.lower()

        # Check if username is taken by another user
        existing = await settings.find_one({"webui_username": username})
        if existing and existing.get("user_id") != uid:
            return await message.reply_text(
                f"⚠️ Username <code>{username}</code> is already taken. Choose a different one:",
            )

        _tmp_user[uid] = username
        _state[uid] = "awaiting_password"

        await message.reply_text(
            f"✅ Username: <code>{username}</code>\n\n"
            f"<b>Step 2 of 2 — Set a password</b>\n\n"
            f"Reply with your desired password.\n"
            f"• At least 4 characters\n"
            f"• Will be stored as a secure hash",
            reply_markup=ForceReply(selective=True)
        )

    elif step == "awaiting_password":
        if len(text) < 4:
            return await message.reply_text("⚠️ Password must be at least 4 characters. Try again:")

        username = _tmp_user.get(uid)
        if not username:
            _state.pop(uid, None)
            return await message.reply_text("⚠️ Something went wrong. Please run /webui again.")

        pw_hash = _hash(text)
        await settings.update_one(
            {"user_id": uid},
            {"$set": {
                "webui_username":      username,
                "webui_password_hash": pw_hash,
                "user_id":             uid,
            }},
            upsert=True
        )

        _state.pop(uid, None)
        _tmp_user.pop(uid, None)

        # Try to delete the password message for security
        try:
            await message.delete()
        except Exception:
            pass

        await message.reply_text(
            f"<b>✅ WebUI account set up!</b>\n\n"
            f"👤 Username: <code>{username}</code>\n"
            f"🔒 Password: stored securely\n\n"
            f"You can now log into the WebUI with these credentials.\n"
            f"<i>(Your password message was deleted for security.)</i>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🌐 View Account", callback_data="webui_cancel")]
            ])
        )
