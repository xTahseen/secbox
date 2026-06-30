import asyncio
import logging
import os
from dotenv import load_dotenv
from pyrogram import Client
from pyrogram.types import BotCommand
from aiohttp import web

logging.basicConfig(level=logging.INFO)
load_dotenv()


def _build_webui(app_client):
    from database.mongo import files, folders, settings, shares
    from plugins.webui import create_app
    return create_app(
        files_col=files,
        folders_col=folders,
        settings_col=settings,
        bot_instance=app_client,
        shares_col=shares,
    )


async def _set_commands(client: Client):
    """Register bot commands so they appear in the Telegram menu."""
    await client.set_bot_commands([
        BotCommand("start",       "Welcome & quick help"),
        BotCommand("files",       "Browse your folders & files"),
        BotCommand("stickers",    "Browse your saved sticker packs"),
        BotCommand("webui",       "Manage your WebUI account"),
    ])
    logging.info("Bot commands registered.")


async def main():
    app_client = Client(
        "FileStorageBot",
        api_id=int(os.getenv("API_ID")),
        api_hash=os.getenv("API_HASH"),
        bot_token=os.getenv("BOT_TOKEN"),
        plugins={"root": "plugins"},
    )

    webui_app  = _build_webui(app_client)
    webui_host = os.getenv("WEBUI_HOST", "0.0.0.0")
    webui_port = int(os.getenv("WEBUI_PORT", "8080"))

    runner = web.AppRunner(webui_app)
    await runner.setup()
    site   = web.TCPSite(runner, webui_host, webui_port)

    async with app_client:
        from database.mongo import ensure_indexes
        await ensure_indexes()

        await _set_commands(app_client)
        await site.start()
        print("Bot started.")
        print(f"WebUI running at http://{webui_host}:{webui_port}")
        await asyncio.Event().wait()

    await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
