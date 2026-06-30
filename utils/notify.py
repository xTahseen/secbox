import logging
import os

logger = logging.getLogger(__name__)

LOG_GROUP_ID = os.getenv("LOG_GROUP_ID")


async def notify_new_user(client, user):
    """Send a new-user-joined notification to the configured log group.

    Silently does nothing if LOG_GROUP_ID isn't set, and never lets a
    notification failure (bot not in group, group deleted, etc.) break the
    /start flow for the user.
    """
    if not LOG_GROUP_ID:
        return

    name = user.first_name or "Unknown"
    if user.last_name:
        name += f" {user.last_name}"
    username = f"@{user.username}" if user.username else "—"

    text = (
        "🆕 <b>New User Joined</b>\n"
        f"<b>Name:</b> {name}\n"
        f"<b>Username:</b> {username}\n"
        f"<b>User ID:</b> <code>{user.id}</code>"
    )

    try:
        await client.send_message(int(LOG_GROUP_ID), text)
    except Exception:
        logger.warning("Failed to send new-user notification to log group", exc_info=True)
