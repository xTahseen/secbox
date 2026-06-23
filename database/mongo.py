import logging
import os
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

logger = logging.getLogger(__name__)

load_dotenv()

# maxPoolSize/minPoolSize: with thousands of users hitting the bot + WebUI
# concurrently, the default pool (100) can queue up under load. These are
# generous but bounded so a single deployment can't exhaust MongoDB's own
# connection limit. waitQueueTimeoutMS makes pool exhaustion fail fast with a
# clear error instead of hanging requests indefinitely.
client = AsyncIOMotorClient(
    os.getenv("MONGO_URI"),
    maxPoolSize=200,
    minPoolSize=10,
    waitQueueTimeoutMS=10_000,
)
db = client[os.getenv("DATABASE_NAME")]
folders = db.folders
files = db.files
settings = db.settings   # stores default_folder per user
sticker_packs = db.sticker_packs   # one doc per (user_id, kind) — tracks the real Telegram pack created for that user
shares = db.shares   # public share links: { user_id, resource_type, resource_id, token, password_hash, created_at }


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
        # folders: looked up by user_id+parent_id (listing a folder's children).
        # _id point lookups are already covered by Mongo's default _id index.
        (folders, [("user_id", 1), ("parent_id", 1)], {}),

        # files: looked up by user_id+folder_id (listing a folder's files),
        # sorted by _id descending (newest first) — folding _id into the index
        # lets Mongo satisfy that sort without an extra in-memory sort step.
        (files, [("user_id", 1), ("folder_id", 1), ("_id", -1)], {}),
        # Plain user_id index for count_documents({"user_id": uid}) (api_stats)
        # and inline-search queries, which filter by user_id alone.
        (files, "user_id", {}),
        # Case-insensitive filename search (api_search, inline mode) — a text
        # index lets Mongo use a real index instead of scanning every
        # document's file_name with a regex.
        (files, [("file_name", "text")], {}),

        # settings: looked up by user_id (every keyboard render, /webui, login
        # display-name lookup) and by webui_username (WebUI login). Partial
        # index restricted to docs that actually have the field avoids
        # breaking on existing data with no webui_username set.
        (settings, "user_id", {}),
        (settings, "webui_username", {"partialFilterExpression": {"webui_username": {"$exists": True}}}),

        # sticker_packs: looked up by (user_id, kind) on every sticker sent.
        (sticker_packs, [("user_id", 1), ("kind", 1)], {}),

        # shares: kept here too so all index setup lives in one place.
        (shares, "token", {"unique": True}),
        (shares, [("user_id", 1), ("resource_type", 1), ("resource_id", 1)], {}),
    ]

    for col, keys, kwargs in index_jobs:
        try:
            await col.create_index(keys, **kwargs)
        except Exception:
            logger.warning(
                "Could not ensure index %r on %s", keys, col.name, exc_info=True
            )

    logger.info("MongoDB index setup complete.")
