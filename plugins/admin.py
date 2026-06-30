import os
from pyrogram import Client, filters
from database.mongo import users, files
from utils.format import fmt_size

_ADMIN_IDS = {
    int(uid) for uid in os.getenv("ADMIN_IDS", "").split(",") if uid.strip().isdigit()
}


def is_admin(_, __, message):
    return bool(message.from_user) and message.from_user.id in _ADMIN_IDS


admin_filter = filters.create(is_admin)



@Client.on_message(filters.command("stats") & admin_filter)
async def stats_cmd(_, message):
    total_users = await users.count_documents({})
    total_files = await files.count_documents({})

    size_agg = files.aggregate([
        {"$group": {"_id": None, "total_size": {"$sum": "$file_size"}}}
    ])
    size_doc = await size_agg.to_list(length=1)
    total_size = size_doc[0]["total_size"] if size_doc else 0

    top_agg = files.aggregate([
        {"$group": {"_id": "$user_id", "file_count": {"$sum": 1}}},
        {"$sort": {"file_count": -1}},
        {"$limit": 10},
    ])
    top_users = await top_agg.to_list(length=10)

    lines = [
        "📊 <b>Bot Stats</b>",
        f"<b>Total Users:</b> {total_users}",
        f"<b>Total Files:</b> {total_files}",
        f"<b>Total Storage:</b> {fmt_size(total_size)}",
        "",
        "<b>🏆 Top Users (by file count):</b>",
    ]

    if not top_users:
        lines.append("No files stored yet.")
    else:
        for i, entry in enumerate(top_users, start=1):
            uid = entry["_id"]
            count = entry["file_count"]
            user_doc = await users.find_one({"user_id": uid})
            if user_doc and user_doc.get("username"):
                label = f"@{user_doc['username']}"
            elif user_doc and user_doc.get("first_name"):
                label = user_doc["first_name"]
            else:
                label = f"ID {uid}"
            lines.append(f"{i}. {label} — {count} files")

    await message.reply_text("\n".join(lines))
