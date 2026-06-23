# SecureBox File Storage Bot

A Telegram bot that stores files and provides a WebUI to browse and manage them.

## 🚀 Deploy with Docker

### 1. Clone / unzip the project
```bash
unzip securebot_fixed.zip
cd securebot_fixed
```

### 2. Configure environment
Edit `.env` and fill in your values:
```env
API_ID=your_api_id
API_HASH=your_api_hash
BOT_TOKEN=your_bot_token
MONGO_URI=your_mongodb_uri
DATABASE_NAME=securebox1
WEBUI_PORT=8080
WEBUI_SECRET_KEY=change-me-to-a-random-secret
```

### 3. Build and run
```bash
docker compose up -d
```

### 4. Set your WebUI password via Telegram
Send this to your bot:
```
/setpassword YourSecurePassword
```

### 5. Open the WebUI
```
http://YOUR_SERVER_IP:8080
```

---

## 🔗 Public sharing

Long-press (or right-click) any file or folder in the WebUI to open its **Share** menu. From there you can:
- Turn on a public link — anyone with the URL can view/download it without logging in
- Optionally require a password
- Copy the link, or clear it to revoke access instantly

Shared folders get a simple read-only public browser (subfolders + downloads); shared files get a direct download page. Items with an active link show a small link icon next to their name.

Set `WEBUI_BASE_URL` in `.env` to your public domain (e.g. `https://files.example.com/drive?folder=`) so generated links use the right host instead of a relative path.

---

## 🛠 Useful Docker commands

| Command | Description |
|---|---|
| `docker compose up -d` | Start in background |
| `docker compose down` | Stop the bot |
| `docker compose logs -f` | Live logs |
| `docker compose restart` | Restart after config change |
| `docker compose build --no-cache` | Rebuild image |

---

## 📁 Project structure
```
securebot/
├── bot.py               # Entry point — runs bot + WebUI together
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env                 # Your credentials (never commit this)
├── database/
│   └── mongo.py         # MongoDB collections
├── plugins/
│   ├── start.py         # /start command
│   ├── files.py         # File saving & /files command
│   ├── callbacks.py     # Inline button handlers
│   ├── setpassword.py   # /setpassword command
│   └── webui.py         # aiohttp WebUI server
└── utils/
    └── keyboards.py     # Inline keyboard builders
```
