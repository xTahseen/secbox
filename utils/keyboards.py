from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from bson import ObjectId
import asyncio
from database.mongo import folders, settings

FOLDERS_PER_PAGE = 8
FILES_PER_PAGE = 8


async def get_default_folder_id(user_id: int):
    doc = await settings.find_one({"user_id": user_id})
    return doc.get("default_folder_id") if doc else None


async def root_keyboard(user_id: int, page: int = 0):
    """Root view: action row on top, then folders, then root-level files, paginated."""
    from database.mongo import files as files_col

    folder_query = {"user_id": user_id, "$or": [{"parent_id": None}, {"parent_id": {"$exists": False}}]}
    # Root-level files (folder_id == "" or missing or None)
    file_query = {"user_id": user_id, "$or": [
        {"folder_id": ""},
        {"folder_id": {"$exists": False}},
        {"folder_id": None},
    ]}

    # These three reads don't depend on each other's results, so run them
    # concurrently instead of waiting on each one in turn — this alone roughly
    # cuts the DB round-trip time for opening "My Drive" by ~3x.
    total_folders, total_files, default_id = await asyncio.gather(
        folders.count_documents(folder_query),
        files_col.count_documents(file_query),
        get_default_folder_id(user_id),
    )

    # Total items across folders + files, paginated together
    total_items = total_folders + total_files
    skip = page * FILES_PER_PAGE

    # Determine how many folders to skip/show on this page
    folder_skip = min(skip, total_folders)
    folders_on_page = min(FILES_PER_PAGE, total_folders - folder_skip)

    # Fetching the folder page is needed before we know file_slots/file_skip,
    # so this one stays sequential — but it's a single indexed query either way.
    folder_list = (
        await folders.find(folder_query)
        .sort("_id", -1)
        .skip(folder_skip)
        .to_list(length=folders_on_page if folders_on_page > 0 else 0)
    )

    # Remaining slots on this page go to files
    file_slots = FILES_PER_PAGE - len(folder_list)
    file_skip = max(0, skip - total_folders)
    file_list = (
        await files_col.find(file_query)
        .sort("_id", -1)
        .skip(file_skip)
        .to_list(length=file_slots if file_slots > 0 else 0)
    )

    is_root_default = (default_id is None or default_id == "root" or default_id == "")
    default_label = "⭐ Default" if is_root_default else "📌 Set as Default"

    # Top action row
    rows = [[
        InlineKeyboardButton("➕ New Folder", callback_data="new_folder:root"),
        InlineKeyboardButton(default_label, callback_data="set_default:root"),
    ]]

    # Folders
    for folder in folder_list:
        fid = str(folder["_id"])
        label = folder["name"]
        if fid == default_id:
            label = "⭐ " + label
        rows.append([InlineKeyboardButton(f"📁 {label}", callback_data=f"folder:{fid}:0")])

    # Root-level files
    for f in file_list:
        icon = {"video": "🎬", "audio": "🎵", "photo": "🖼️"}.get(f.get("file_type", ""), "📄")
        rows.append([
            InlineKeyboardButton(
                f"{icon} {f.get('file_name', 'file')[:45]}",
                callback_data=f"file:{f['_id']}"
            )
        ])

    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("« Prev", callback_data=f"root_page:{page - 1}"))
    if skip + FILES_PER_PAGE < total_items:
        nav.append(InlineKeyboardButton("Next »", callback_data=f"root_page:{page + 1}"))
    if nav:
        rows.append(nav)

    return InlineKeyboardMarkup(rows)


async def folder_keyboard(user_id: int, folder_id: str, folder_name: str, page: int = 0):
    """Inside a folder: Folder Options + Default on top, subfolders + files, Back footer."""
    from database.mongo import files as files_col

    skip = page * FILES_PER_PAGE

    # subfolders, file count, default-folder id, and this folder's own doc
    # (needed for the Back button's target) are all independent reads —
    # fire them together instead of one after another.
    subfolders, total, default_id, this_folder = await asyncio.gather(
        folders.find({"user_id": user_id, "parent_id": folder_id}).sort("_id", -1).to_list(length=200),
        files_col.count_documents({"user_id": user_id, "folder_id": folder_id}),
        get_default_folder_id(user_id),
        folders.find_one({"_id": ObjectId(folder_id)}),
    )

    # The actual file page depends only on skip/limit, not on the count above,
    # so it can run while we're already building the keyboard rows below —
    # but it still needs awaiting before we use file_list, so fetch it now.
    file_list = (
        await files_col.find({"user_id": user_id, "folder_id": folder_id})
        .sort("_id", -1)
        .skip(skip)
        .to_list(length=FILES_PER_PAGE)
    )

    is_default = (str(default_id) == str(folder_id)) if default_id else False
    default_label = "⭐ Default" if is_default else "📌 Set as Default"

    rows = [[
        InlineKeyboardButton("⚙️ Folder Options", callback_data=f"fopts:{folder_id}"),
        InlineKeyboardButton(default_label, callback_data=f"set_default:{folder_id}"),
    ]]

    for sf in subfolders:
        sfid = str(sf["_id"])
        rows.append([InlineKeyboardButton(f"📁 {sf['name']}", callback_data=f"folder:{sfid}:0")])

    for f in file_list:
        icon = {"video": "🎬", "audio": "🎵", "photo": "🖼️"}.get(f["file_type"], "📄")
        rows.append([
            InlineKeyboardButton(
                f"{icon} {f['file_name'][:45]}",
                callback_data=f"file:{f['_id']}"
            )
        ])

    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("« Prev", callback_data=f"folder:{folder_id}:{page - 1}"))
    if skip + FILES_PER_PAGE < total:
        nav.append(InlineKeyboardButton("Next »", callback_data=f"folder:{folder_id}:{page + 1}"))
    if nav:
        rows.append(nav)

    parent_id = this_folder.get("parent_id") if this_folder else None
    back_cb = f"up_folder:{parent_id}:0" if parent_id else "back_root:0"
    rows.append([InlineKeyboardButton("« Back", callback_data=back_cb)])

    return InlineKeyboardMarkup(rows)


async def folder_options_keyboard(folder_id: str):
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("➕ New Subfolder", callback_data=f"new_folder:{folder_id}"),
            InlineKeyboardButton("✏️ Rename", callback_data=f"rename:{folder_id}"),
        ],
        [
            InlineKeyboardButton("🔗 Link", callback_data=f"link:{folder_id}"),
            InlineKeyboardButton("✗ Delete", callback_data=f"delete_folder:{folder_id}"),
        ],
        [InlineKeyboardButton("« Back", callback_data=f"folder:{folder_id}:0")],
    ])
