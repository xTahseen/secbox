"""
Inline mode: lets a user type @<bot_username> <search> in ANY chat to find
and send one of their own saved files, without having to open a chat with
the bot first.

Results only ever include files belonging to the user who typed the query —
inline queries can be sent from any chat, including ones with strangers, so
this must never expose another user's saved files.
"""

import logging

from pyrogram import Client
from pyrogram.types import (
    InlineQueryResultCachedDocument,
    InlineQueryResultCachedPhoto,
)

from database.mongo import files as files_col
from utils.format import fmt_size

logger = logging.getLogger(__name__)

RESULTS_PER_PAGE = 20


def _result_for(doc) -> "InlineQueryResultCachedDocument | InlineQueryResultCachedPhoto":
    name = doc.get("file_name", "file")
    ftype = doc.get("file_type", "document")
    tg_id = doc["telegram_file_id"]
    size_str = fmt_size(doc.get("file_size"))
    date_str = doc["_id"].generation_time.strftime("%d %b %Y")
    result_id = str(doc["_id"])

    if ftype == "photo":
        return InlineQueryResultCachedPhoto(
            photo_file_id=tg_id,
            id=result_id,
            title=name,
            description=f"{size_str} · {date_str}",
        )

    return InlineQueryResultCachedDocument(
        document_file_id=tg_id,
        title=name,
        id=result_id,
        description=f"{size_str} · {date_str}",
    )


@Client.on_inline_query()
async def inline_file_search(_, inline_query):
    user_id = inline_query.from_user.id
    query = (inline_query.query or "").strip()
    try:
        offset = int(inline_query.offset) if inline_query.offset else 0
    except ValueError:
        offset = 0

    mongo_query = {"user_id": user_id}
    if query:
        mongo_query["file_name"] = {"$regex": query, "$options": "i"}

    cursor = (
        files_col.find(mongo_query)
        .sort("_id", -1)
        .skip(offset)
        .limit(RESULTS_PER_PAGE)
    )
    docs = await cursor.to_list(length=RESULTS_PER_PAGE)

    results = []
    for doc in docs:
        try:
            results.append(_result_for(doc))
        except Exception as e:
            logger.warning(f"inline_file_search: skipping file {doc.get('_id')}: {e}")

    next_offset = str(offset + RESULTS_PER_PAGE) if len(docs) == RESULTS_PER_PAGE else ""

    answer_kwargs = dict(
        results=results,
        cache_time=5,
        is_personal=True,
        next_offset=next_offset,
    )
    if not results:
        answer_kwargs["switch_pm_text"] = "No files found — open bot"
        answer_kwargs["switch_pm_parameter"] = "inline"

    await inline_query.answer(**answer_kwargs)
