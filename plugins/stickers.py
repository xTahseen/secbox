"""
Sticker pack auto-builder.

When a user sends the bot a sticker, we figure out its kind (static / animated /
video) and make sure that user has a *real* Telegram sticker pack of that kind,
creating one on the user's first sticker of that kind and adding to it on every
sticker after that. Three kinds == up to three packs per user: one static, one
animated, one video — Telegram doesn't allow mixing formats in a single pack,
which conveniently matches what was asked for.

Pyrogram has no high-level helper for sticker set creation, so this goes
through the raw MTProto API (pyrogram.raw) directly, the same way userbot
"kang sticker" scripts do it.
"""

import logging
import random
import re
import string

from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from pyrogram.errors import RPCError
from pyrogram.file_id import FileId
from pyrogram.raw import functions, types as raw_types

from database.mongo import sticker_packs

logger = logging.getLogger(__name__)

_KIND_LABEL = {"static": "🖼️ Static", "animated": "✨ Animated", "video": "🎞️ Video"}

_bot_username = None

_NAME_TAKEN_IDS = {"SHORT_NAME_OCCUPIED", "SHORTNAME_OCCUPY_FAILED"}

_PACK_FULL_IDS = {"STICKERS_TOO_MUCH"}


def _classify(sticker):
    """Return 'static' | 'animated' | 'video' for a pyrogram Sticker."""
    if getattr(sticker, "is_video", False):
        return "video"
    if getattr(sticker, "is_animated", False):
        return "animated"
    return "static"


def _rpc_id(exc: Exception) -> str:
    """Best-effort extraction of Telegram's RPC error ID across Pyrogram versions."""
    return str(getattr(exc, "ID", None) or getattr(exc, "MESSAGE", None) or exc).upper()


async def _get_bot_username(client: Client) -> str:
    global _bot_username
    if _bot_username:
        return _bot_username
    me = await client.get_me()
    _bot_username = me.username
    return _bot_username


def _slug(user_id: int, kind: str, suffix: int) -> str:
    """Build a short_name candidate: must start with a letter, alnum + underscores only."""
    tag = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    base = f"u{user_id}{kind}{'' if suffix == 1 else suffix}{tag}"
    return re.sub(r"[^a-zA-Z0-9]", "", base)


def _pack_title(kind: str, suffix: int) -> str:
    label = {"static": "Static", "animated": "Animated", "video": "Video"}[kind]
    base = f"{label} Stickers"
    return base if suffix == 1 else f"{base} {suffix}"


async def _input_sticker_item(client: Client, sticker):
    """Decode a Sticker's file_id into a raw InputStickerSetItem Telegram can use
    to add it to a pack (no re-download/re-upload needed — Telegram lets a bot
    reference any document it has already seen)."""
    decoded = FileId.decode(sticker.file_id)
    document = raw_types.InputDocument(
        id=decoded.media_id,
        access_hash=decoded.access_hash,
        file_reference=decoded.file_reference,
    )
    return raw_types.InputStickerSetItem(
        document=document,
        emoji=sticker.emoji or "🙂",
    )


async def _create_pack(client: Client, owner_peer, kind: str, item, title: str, short_name: str):
    await client.invoke(
        functions.stickers.CreateStickerSet(
            user_id=owner_peer,
            title=title,
            short_name=short_name,
            stickers=[item],
            animated=(kind == "animated"),
            videos=(kind == "video"),
        )
    )


async def _add_to_pack(client: Client, short_name: str, item):
    await client.invoke(
        functions.stickers.AddStickerToSet(
            stickerset=raw_types.InputStickerSetShortName(short_name=short_name),
            sticker=item,
        )
    )


async def _get_or_create_pack(client: Client, message, kind: str, sticker):
    """
    Returns (short_name, just_created: bool) for the pack this sticker should
    live in, creating a new pack (or a new overflow pack like '..._2') as needed.

    The pack must be owned by the human user who sent the sticker — Telegram
    rejects CreateStickerSet with USER_IS_BOT if you try to make the bot itself
    the owner, since bot accounts can't own sticker sets.
    """
    user_id = message.from_user.id
    bot_username = await _get_bot_username(client)
    item = await _input_sticker_item(client, sticker)
    owner_peer = await client.resolve_peer(message.from_user.username or user_id)

    existing = await sticker_packs.find_one({"user_id": user_id, "kind": kind})

    if existing:
        short_name = existing["short_name"]
        try:
            await _add_to_pack(client, short_name, item)
            await sticker_packs.update_one(
                {"_id": existing["_id"]},
                {"$inc": {"sticker_count": 1}}
            )
            return short_name, False
        except RPCError as e:
            if _rpc_id(e) not in _PACK_FULL_IDS:
                raise
            logger.info(f"Pack {short_name} full for user {user_id} ({kind}); creating overflow pack.")

    suffix = (existing.get("suffix", 1) + 1) if existing else 1

    last_err = None
    for _attempt in range(5):
        short_base = _slug(user_id, kind, suffix)
        short_name = f"{short_base}_by_{bot_username}"
        title = _pack_title(kind, suffix)
        try:
            await _create_pack(client, owner_peer, kind, item, title, short_name)
            await sticker_packs.update_one(
                {"user_id": user_id, "kind": kind},
                {"$set": {
                    "user_id": user_id,
                    "kind": kind,
                    "short_name": short_name,
                    "title": title,
                    "suffix": suffix,
                    "sticker_count": 1,
                }},
                upsert=True,
            )
            return short_name, True
        except RPCError as e:
            last_err = e
            if _rpc_id(e) in _NAME_TAKEN_IDS:
                continue
            raise

    raise last_err or RuntimeError("Could not create sticker pack")


@Client.on_message(filters.sticker)
async def save_sticker(client: Client, message):
    user_id = message.from_user.id
    sticker = message.sticker
    kind = _classify(sticker)

    try:
        short_name, just_created = await _get_or_create_pack(client, message, kind, sticker)
    except Exception as e:
        logger.error(f"sticker pack error for user {user_id}: {e}", exc_info=True)
        return await message.reply_text(
            "⚠️ Couldn't add that sticker to your pack right now. Please try again in a moment.",
            quote=True,
        )

    pack_link = f"https://t.me/addstickers/{short_name}"
    if just_created:
        text = (
            f"{_KIND_LABEL[kind]} pack created and this sticker was added! 🎉\n"
            f"View it here: {pack_link}"
        )
    else:
        text = f"{_KIND_LABEL[kind]} sticker added to your pack! ✅"

    await message.reply_text(
        text,
        quote=True,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("📦 Open Pack", url=pack_link)]
        ])
    )


@Client.on_message(filters.command("stickers"))
async def stickers_cmd(_, message):
    user_id = message.from_user.id
    packs = await sticker_packs.find({"user_id": user_id}).to_list(length=10)

    if not packs:
        return await message.reply_text(
            "You haven't saved any stickers yet. Send the bot a sticker and "
            "I'll create a matching pack (static, animated, or video) for you."
        )

    rows = []
    for p in packs:
        label = _KIND_LABEL.get(p["kind"], p["kind"])
        count = p.get("sticker_count", 0)
        link = f"https://t.me/addstickers/{p['short_name']}"
        rows.append([InlineKeyboardButton(f"{label} ({count})", url=link)])

    await message.reply_text("🗂️ Your Sticker Packs:", reply_markup=InlineKeyboardMarkup(rows))
