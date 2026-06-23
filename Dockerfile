# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed by tgcrypto / pyrogram
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project
COPY . .

# Expose the WebUI port
EXPOSE 8080

# Run the bot (starts both Pyrogram bot + aiohttp WebUI)
CMD ["python", "bot.py"]
