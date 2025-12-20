# Лёгкий образ с инструментами сборки для better-sqlite3
FROM node:18-bullseye

# Устанавливаем системные зависимости для сборки native-модулей (better-sqlite3)
RUN apt-get update && \
    apt-get install -y build-essential python3 libsqlite3-dev --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем package.json + package-lock (если есть), ставим зависимости
COPY package*.json ./
RUN npm install --production

# Копируем весь код
COPY . .

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server.js"]
