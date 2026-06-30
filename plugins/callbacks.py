import os
import re
from bson import ObjectId
from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton, ForceReply
from database.mongo import folders, files, settings
from utils.format import fmt_size as _fmt_size
from utils.keyboards import (
    root_keyboard,
    folder_keyboard,
    folder_options_keyboard,
    get_default_folder_id,
)

WEBUI_BASE = os.getenv("WEBUI_BASE_URL", "https://yourwebui.example.com/drive?folder=")


@Client.on_callback_query(filters.regex(r"^open_files_ui$"))
async def open_files_ui(_, cq):
    await cq.answer()
    await cq.message.edit_text(
        "📂 <b>My Drive</b>:",
        reply_markup=await root_keyboard(cq.from_user.id, 0)
    )



@Client.on_callback_query(filters.regex(r"^root_page:(\d+)$"))
async def root_page(_, cq):
    await cq.answer()
    page = int(cq.data.split(":")[1])
    await cq.message.edit_text(
        "📂 <b>My Drive</b>:",
        reply_markup=await root_keyboard(cq.from_user.id, page)
    )


@Client.on_callback_query(filters.regex(r"^back_root:(\d+)$"))
async def back_root(_, cq):
    """Back button footer action — goes up one level (to parent folder, or root)."""
    await cq.answer()
    page = int(cq.data.split(":")[1])
    await cq.message.edit_text(
        "📂 <b>My Drive</b>:",
        reply_markup=await root_keyboard(cq.from_user.id, page)
    )


@Client.on_callback_query(filters.regex(r"^up_folder:([a-f0-9]+):(\d+)$"))
async def up_folder(_, cq):
    """Navigate to a specific parent folder (used when Back is pressed inside a subfolder)."""
    _, folder_id, page_str = cq.data.split(":")
    page = int(page_str)
    folder = await folders.find_one({"_id": ObjectId(folder_id)})
    if not folder:
        return await cq.answer("Folder not found", show_alert=True)
    kb = await folder_keyboard(cq.from_user.id, folder_id, folder["name"], page)
    await cq.answer()
    await cq.message.edit_text(f"📁 {folder['name']}", reply_markup=kb)



@Client.on_callback_query(filters.regex(r"^folder:([a-f0-9]+):(\d+)$"))
async def open_folder(_, cq):
    _, folder_id, page_str = cq.data.split(":")
    page = int(page_str)
    folder = await folders.find_one({"_id": ObjectId(folder_id)})
    if not folder:
        return await cq.answer("Folder not found", show_alert=True)
    kb = await folder_keyboard(cq.from_user.id, folder_id, folder["name"], page)
    await cq.answer()
    await cq.message.edit_text(f"📁 {folder['name']}", reply_markup=kb)



@Client.on_callback_query(filters.regex(r"^file:([a-f0-9]+)$"))
async def file_send(_, cq):
    fid = cq.data.split(":")[1]
    data = await files.find_one({"_id": ObjectId(fid)})
    if not data:
        return await cq.answer("File not found", show_alert=True)
    ft = data["file_type"]
    tid = data["telegram_file_id"]
    await cq.answer()
    if ft == "video":
        await cq.message.reply_video(tid)
    elif ft == "audio":
        await cq.message.reply_audio(tid)
    elif ft == "photo":
        await cq.message.reply_photo(tid)
    else:
        await cq.message.reply_document(tid)



@Client.on_callback_query(filters.regex(r"^fopts:([a-f0-9]+)$"))
async def folder_options(_, cq):
    folder_id = cq.data.split(":")[1]
    folder = await folders.find_one({"_id": ObjectId(folder_id)})
    if not folder:
        return await cq.answer("Folder not found", show_alert=True)
    await cq.answer()
    await cq.message.edit_text(
        f"⚙️ Folder Options — {folder['name']}",
        reply_markup=await folder_options_keyboard(folder_id)
    )



@Client.on_callback_query(filters.regex(r"^new_folder:(root|[a-f0-9]+)$"))
async def new_folder_prompt(_, cq):
    await cq.answer()
    parent_id = cq.data.split(":")[1]
    if parent_id == "root":
        prompt = "📁 Send me the new folder name:"
    else:
        prompt = f"📁 Send me the new subfolder name:\n(parent_id:{parent_id})"
    await cq.message.reply_text(
        prompt,
        reply_markup=ForceReply(selective=True)
    )


@Client.on_message(filters.reply & filters.text)
async def handle_reply(_, message):
    if not message.reply_to_message:
        return
    from plugins.account import _state as _webui_state, webui_reply_handler
    if message.from_user.id in _webui_state:
        await webui_reply_handler(_, message)
        return
    replied = message.reply_to_message
    text = replied.text or ""
    user_id = message.from_user.id

    if "Send me the new" in text and "folder name" in text:
        m = re.search(r"parent_id:([a-f0-9]+)", text)
        parent_id = m.group(1) if m else None
        name = message.text.strip()
        if await folders.find_one({"user_id": user_id, "parent_id": parent_id, "name": name}):
            return await message.reply_text("⚠️ A folder with that name already exists here.")
        await folders.insert_one({"user_id": user_id, "name": name, "parent_id": parent_id})
        if parent_id:
            parent = await folders.find_one({"_id": ObjectId(parent_id)})
            kb = await folder_keyboard(user_id, parent_id, parent["name"] if parent else "", 0)
            await message.reply_text(f"✅ Subfolder '{name}' created!", reply_markup=kb)
        else:
            await message.reply_text(
                f"✅ Folder '{name}' created!",
                reply_markup=await root_keyboard(user_id, 0)
            )

    elif text.startswith("✏️ Enter new name for") and "folder_id:" in text:
        m = re.search(r"folder_id:([a-f0-9]+)", text)
        if not m:
            return
        folder_id = m.group(1)
        folder = await folders.find_one({"_id": ObjectId(folder_id)})
        if not folder:
            return
        new_name = message.text.strip()
        if await folders.find_one({
            "user_id": user_id,
            "parent_id": folder.get("parent_id"),
            "name": new_name,
            "_id": {"$ne": ObjectId(folder_id)},
        }):
            return await message.reply_text("⚠️ A folder with that name already exists here.")
        await folders.update_one({"_id": ObjectId(folder_id)}, {"$set": {"name": new_name}})
        await files.update_many({"folder_id": folder_id}, {"$set": {"folder_name": new_name}})
        kb = await folder_keyboard(user_id, folder_id, new_name, 0)
        await message.reply_text(f"✅ Renamed to '{new_name}'", reply_markup=kb)

    elif text.startswith("✏️ Enter new name for") and "file_id:" in text:
        m = re.search(r"file_id:([a-f0-9]+)", text)
        if not m:
            return
        file_id = m.group(1)
        doc = await files.find_one({"_id": ObjectId(file_id)})
        if not doc:
            return await message.reply_text("⚠️ File not found (it may have been deleted).")
        new_name = message.text.strip()
        if not new_name:
            return await message.reply_text("⚠️ Name cannot be empty.")
        await files.update_one({"_id": ObjectId(file_id)}, {"$set": {"file_name": new_name}})
        await message.reply_text(f"✅ Renamed to '{new_name}'")



@Client.on_callback_query(filters.regex(r"^rename:([a-f0-9]+)$"))
async def rename_prompt(_, cq):
    folder_id = cq.data.split(":")[1]
    folder = await folders.find_one({"_id": ObjectId(folder_id)})
    if not folder:
        return await cq.answer("Folder not found", show_alert=True)
    await cq.answer()
    await cq.message.reply_text(
        f"✏️ Enter new name for '{folder['name']}':\n(folder_id:{folder_id})",
        reply_markup=ForceReply(selective=True)
    )



@Client.on_callback_query(filters.regex(r"^frename:([a-f0-9]+)$"))
async def file_rename_prompt(_, cq):
    file_id = cq.data.split(":")[1]
    doc = await files.find_one({"_id": ObjectId(file_id)})
    if not doc:
        return await cq.answer("File not found", show_alert=True)
    await cq.answer()
    await cq.message.reply_text(
        f"✏️ Enter new name for '{doc.get('file_name', 'file')}':\n(file_id:{file_id})",
        reply_markup=ForceReply(selective=True)
    )



@Client.on_callback_query(filters.regex(r"^fdelete:([a-f0-9]+)$"))
async def file_delete_confirm(_, cq):
    file_id = cq.data.split(":")[1]
    doc = await files.find_one({"_id": ObjectId(file_id)})
    if not doc:
        return await cq.answer("File not found", show_alert=True)
    await cq.answer()
    await cq.message.edit_text(
        f"🗑️ Delete file '{doc.get('file_name', 'file')}'?\nThis cannot be undone.",
        reply_markup=InlineKeyboardMarkup([
            [
                InlineKeyboardButton("✅ Yes, Delete", callback_data=f"fconfirm_delete:{file_id}"),
                InlineKeyboardButton("❌ Cancel", callback_data=f"fcancel_delete:{file_id}"),
            ]
        ])
    )


@Client.on_callback_query(filters.regex(r"^fconfirm_delete:([a-f0-9]+)$"))
async def file_delete_execute(_, cq):
    file_id = cq.data.split(":")[1]
    await cq.answer("Deleted!", show_alert=False)
    await files.delete_one({"_id": ObjectId(file_id)})
    await cq.message.edit_text("🗑️ File deleted.")


@Client.on_callback_query(filters.regex(r"^fcancel_delete:([a-f0-9]+)$"))
async def file_delete_cancel(_, cq):
    file_id = cq.data.split(":")[1]
    await cq.answer()
    doc = await files.find_one({"_id": ObjectId(file_id)})
    if not doc:
        return await cq.message.edit_text("⚠️ File not found (it may have been deleted).")
    location = doc.get("folder_name") or "Root"
    text = (
        "<b>File saved successfully!</b> 🎉\n"
        f"<b>File Name</b>: {doc.get('file_name', 'file')}\n"
        f"<b>File Type</b>: {doc.get('file_type', 'document')}\n"
        f"<b>File Size</b>: {_fmt_size(doc.get('file_size'))}\n"
        f"<b>Directory</b>: {location}"
    )
    await cq.message.edit_text(
        text,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✏️ Rename", callback_data=f"frename:{file_id}")],
            [InlineKeyboardButton("✗ Delete", callback_data=f"fdelete:{file_id}")],
        ])
    )



@Client.on_callback_query(filters.regex(r"^link:([a-f0-9]+)$"))
async def folder_link(_, cq):
    folder_id = cq.data.split(":")[1]
    folder = await folders.find_one({"_id": ObjectId(folder_id)})
    if not folder:
        return await cq.answer("Folder not found", show_alert=True)
    await cq.answer()
    link = f"{WEBUI_BASE}/drive?folder={folder_id}"
    await cq.message.reply_text(
        f"🔗 Link for folder **{folder['name']}**:\n`{link}`",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("« Back", callback_data=f"folder:{folder_id}:0")]
        ])
    )



@Client.on_callback_query(filters.regex(r"^delete_folder:([a-f0-9]+)$"))
async def delete_folder_confirm(_, cq):
    folder_id = cq.data.split(":")[1]
    folder = await folders.find_one({"_id": ObjectId(folder_id)})
    if not folder:
        return await cq.answer("Folder not found", show_alert=True)
    await cq.answer()
    await cq.message.edit_text(
        f"🗑️ Delete folder '{folder['name']}' and all its files?\nThis cannot be undone.",
        reply_markup=InlineKeyboardMarkup([
            [
                InlineKeyboardButton("✅ Yes, Delete", callback_data=f"confirm_delete:{folder_id}"),
                InlineKeyboardButton("❌ Cancel", callback_data=f"cancel_delete_folder:{folder_id}"),
            ]
        ])
    )


@Client.on_callback_query(filters.regex(r"^cancel_delete_folder:([a-f0-9]+)$"))
async def delete_folder_cancel(_, cq):
    folder_id = cq.data.split(":")[1]
    folder = await folders.find_one({"_id": ObjectId(folder_id)})
    if not folder:
        return await cq.answer("Folder not found", show_alert=True)
    kb = await folder_keyboard(cq.from_user.id, folder_id, folder["name"], 0)
    await cq.answer()
    await cq.message.edit_text(f"📁 {folder['name']}", reply_markup=kb)


@Client.on_callback_query(filters.regex(r"^confirm_delete:([a-f0-9]+)$"))
async def delete_folder_execute(_, cq):
    folder_id = cq.data.split(":")[1]
    await cq.answer("Deleted!", show_alert=False)
    await _delete_folder_recursive(folder_id)
    user_id = cq.from_user.id
    await cq.message.edit_text(
        "🗑️ Folder deleted.",
        reply_markup=await root_keyboard(user_id, 0)
    )


async def _delete_folder_recursive(folder_id: str):
    """Delete a folder, its files, and all nested subfolders (and their files)."""
    children = await folders.find({"parent_id": folder_id}).to_list(length=1000)
    for child in children:
        await _delete_folder_recursive(str(child["_id"]))
    await files.delete_many({"folder_id": folder_id})
    await folders.delete_one({"_id": ObjectId(folder_id)})
    await settings.update_many(
        {"default_folder_id": folder_id},
        {"$unset": {"default_folder_id": ""}}
    )



@Client.on_callback_query(filters.regex(r"^set_default:(root|[a-f0-9]+)$"))
async def set_default(_, cq):
    target = cq.data.split(":")[1]
    user_id = cq.from_user.id

    if target == "root":
        await cq.answer("Root set as default!", show_alert=False)
        await settings.update_one(
            {"user_id": user_id},
            {"$unset": {"default_folder_id": ""}},
            upsert=True
        )
        await cq.message.edit_text(
            "⭐ Root is now your Default Folder.",
            reply_markup=await root_keyboard(user_id, 0)
        )
    else:
        folder_id = target
        folder = await folders.find_one({"_id": ObjectId(folder_id)})
        if not folder:
            return await cq.answer("Folder not found", show_alert=True)
        await cq.answer("Default folder set!", show_alert=False)
        await settings.update_one(
            {"user_id": user_id},
            {"$set": {"default_folder_id": folder_id}},
            upsert=True
        )
        kb = await folder_keyboard(user_id, folder_id, folder["name"], 0)
        await cq.message.edit_text(
            f"⭐ '{folder['name']}' is now your Default Folder.",
            reply_markup=kb
        )
