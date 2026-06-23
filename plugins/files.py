from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from database.mongo import folders, files, settings
from utils.format import fmt_size


@Client.on_message(filters.command("files"))
async def files_cmd(_, message):
    from utils.keyboards import root_keyboard
    user_id = message.from_user.id
    await message.reply_text(
        "📂 <b>My Drive</b>:",
        reply_markup=await root_keyboard(user_id, 0)
    )


# NOTE: video_note (round "telescope" videos) and voice (voice messages) were
# previously missing from this filter, so the bot silently ignored them.
@Client.on_message(
    filters.document | filters.video | filters.audio | filters.photo
    | filters.video_note | filters.voice
)
async def save_file(_, message):
    user_id = message.from_user.id

    # Determine target folder from user's settings
    setting = await settings.find_one({"user_id": user_id})
    default_folder_id = setting.get("default_folder_id") if setting else None

    folder_id_str = ""
    folder_name   = ""

    if default_folder_id and default_folder_id != "root":
        import bson
        folder = await folders.find_one({"_id": bson.ObjectId(default_folder_id)})
        if folder:
            folder_id_str = str(folder["_id"])
            folder_name   = folder["name"]
        # Deleted folder → fall through to root

    if message.document:
        tg = message.document; ftype = "document"; name = tg.file_name or "document"
    elif message.video:
        tg = message.video;    ftype = "video";    name = tg.file_name or "video.mp4"
    elif message.video_note:
        tg = message.video_note; ftype = "video";  name = "video_note.mp4"
    elif message.voice:
        tg = message.voice;    ftype = "audio";    name = "voice_message.ogg"
    elif message.audio:
        tg = message.audio;    ftype = "audio";    name = tg.file_name or "audio.mp3"
    else:
        tg = message.photo;    ftype = "photo";    name = "photo.jpg"

    file_size = getattr(tg, "file_size", None)
    duration  = getattr(tg, "duration", None)
    width     = getattr(tg, "width", None)
    height    = getattr(tg, "height", None)
    mime_type = getattr(tg, "mime_type", None)

    doc = {
        "user_id":          user_id,
        "folder_id":        folder_id_str,
        "folder_name":      folder_name,
        "file_name":        name,
        "telegram_file_id": tg.file_id,
        "file_type":        ftype,
        "file_size":        file_size,
    }
    if duration is not None:
        doc["duration"] = duration
    if width is not None:
        doc["width"] = width
    if height is not None:
        doc["height"] = height
    if mime_type:
        doc["mime_type"] = mime_type

    result = await files.insert_one(doc)

    file_id_str = str(result.inserted_id)
    location = folder_name if folder_name else "Root"

    text = (
        "<b>File saved successfully!</b> 🎉\n"
        f"<b>File Name</b>: {name}\n"
        f"<b>File Type</b>: {ftype}\n"
        f"<b>File Size</b>: {fmt_size(file_size)}\n"
        f"<b>Directory</b>: {location}"
    )

    await message.reply_text(
        text,
        quote=True,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✏️ Rename", callback_data=f"frename:{file_id_str}")],
            [InlineKeyboardButton("✗ Delete", callback_data=f"fdelete:{file_id_str}")],
        ])
    )
