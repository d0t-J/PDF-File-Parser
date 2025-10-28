FROM node:20-slim

# install poppler-utils (pdftoppm) and tesseract-ocr for OCR fallback
RUN apt-get update && apt-get install -y --no-install-recommends \
    poppler-utils \
    tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# copy package.json first to leverage caching
COPY package.json package-lock.json* ./
RUN npm install --production

COPY . .

EXPOSE 4001
CMD ["node", "server.js"]
