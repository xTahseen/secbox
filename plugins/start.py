from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton


@Client.on_message(filters.command("start"))
async def start(_, message):
    await message.reply_text(
        "Send me any file (doc, video, image, etc.) and I'll store it.",
        reply_markup=InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔍 Explore", switch_inline_query_current_chat=""),
                InlineKeyboardButton("📂 Files", callback_data="open_files_ui"),
            ]
        ])
    )
