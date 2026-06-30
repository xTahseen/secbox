import logging
import os
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

logger = logging.getLogger(__name__)

load_dotenv()

client = AsyncIOMotorClient(
    os.getenv("MONGO_URI"),
    maxPoolSize=200,
    minPoolSize=10,
    waitQueueTimeoutMS=10_000,
)
db = client[os.getenv("DATABASE_NAME")]
folders = db.folders
files = db.files
settings = db.settings
sticker_packs = db.sticker_packs
shares = db.shares
users = db.users


async def ensure_indexes():
    """
    Create every index the bot + WebUI rely on for fast lookups.

    Before this, only `shares` had indexes (created separately inside
    plugins/webui.py's create_app). Every other collection was being scanned
    in full on every query — folders/files lookups, login, settings reads,
    sticker pack lookups — which is the main reason things slow down as the
    number of users and files grows. create_index() is a no-op if an
    equivalent index already exists, so this is safe to run on every startup.

    Each index is created in its own try/except so one failure (e.g. a
    leftover conflicting index from manual DB work) doesn't prevent the rest
    from being created.
    """
    index_jobs = [
        (folders, [("user_id", 1), ("parent_id", 1)], {}),

        (files, [("user_id", 1), ("folder_id", 1), ("_id", -1)], {}),
        (files, "user_id", {}),
        (files, [("file_name", "text")], {}),

        (settings, "user_id", {}),
        (settings, "webui_username", {"partialFilterExpression": {"webui_username": {"$exists": True}}}),

        (sticker_packs, [("user_id", 1), ("kind", 1)], {}),

        (shares, "token", {"unique": True}),
        (shares, [("user_id", 1), ("resource_type", 1), ("resource_id", 1)], {}),

        (users, "user_id", {"unique": True}),
    ]

    for col, keys, kwargs in index_jobs:
        try:
            await col.create_index(keys, **kwargs)
        except Exception:
            logger.warning(
                "Could not ensure index %r on %s", keys, col.name, exc_info=True
            )

    logger.info("MongoDB index setup complete.")
