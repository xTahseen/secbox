from datetime import datetime, timezone
from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from database.mongo import users


@Client.on_message(filters.command("start"))
async def start(client, message):
    user = message.from_user

    # Insert a users doc only the first time this user is seen. find_one +
    # insert_one (rather than upsert) lets us know cheaply whether this was
    # a brand-new user, so we only fire the join notification once.
    existing = await users.find_one({"user_id": user.id})
    if not existing:
        await users.insert_one({
            "user_id":    user.id,
            "username":   user.username,
            "first_name": user.first_name,
            "joined_at":  datetime.now(timezone.utc),
        })
        from utils.notify import notify_new_user
        await notify_new_user(client, user)

    await message.reply_text(
        "Send me any file (doc, video, image, etc.) and I'll store it.",
        reply_markup=InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔍 Explore", switch_inline_query_current_chat=""),
                InlineKeyboardButton("📂 Files", callback_data="open_files_ui"),
            ]
        ])
    )
