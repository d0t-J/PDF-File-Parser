# Dockerfile (use this)
FROM node:20-slim

# Install build deps for native modules + pdftoppm & tesseract
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3 \
    pkg-config \
    libsqlite3-dev \
    poppler-utils \
    tesseract-ocr \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Copy package files and install first (leverage Docker cache)
COPY package.json package-lock.json* ./
RUN npm ci --production

# Copy source
COPY . .

EXPOSE 4001
CMD ["node", "server.js"]
