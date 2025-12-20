```markdown
# Минимальная соцсеть (прототип)

Функции:
- регистрация / вход (JWT)
- отправка личных сообщений пользователю (toUserId) или всем (broadcast — toUserId = null)
- без Pro — максимум 10 сообщений/постов в сутки
- админ может выдать Pro (Pro — бесплатная) — с Pro нет лимита
- первый зарегистрированный пользователь становится админом автоматически

Запуск:
1. Установите зависимости:
   ```
   npm install
   ```
2. Запустите сервер:
   ```
   npm start
   ```
   По умолчанию: http://localhost:3000

Переменные окружения:
- `JWT_SECRET` (необязательно) — секрет для подписи токенов
- `PORT` (необязательно) — порт сервера
- `DB_FILE` (опционально) — путь к файлу SQLite (по умолчанию data.db)

Docker:
- Есть Dockerfile и docker-compose.yml. Для локального запуска через Docker:
  ```
  docker-compose up --build
  ```

API (основное):

- POST /register
  - body: { "username": "...", "password": "..." }
  - Первый зарегистрированный пользователь становится админом.

- POST /login
  - body: { "username": "...", "password": "..." }
  - Ответ: { user, token }

- POST /post
  - headers: Authorization: Bearer <token>
  - body: { "content": "текст", "toUserId": null | <id> }
  - toUserId опционально: если отсутствует или null — пост считается broadcast (всем).
  - Проверка лимита: если пользователь не Pro — максимум 10 постов в сутки.

- GET /posts
  - headers: Authorization: Bearer <token>
  - query:
    - `inbox=true` — получить feed: broadcast + сообщения, адресованные текущему пользователю
    - `authorId=...` — посты от автора
    - `toUserId=...` — посты адресованные конкретному пользователю и broadcast
    - без параметров — последние публичные/все посты

- POST /admin/grant-pro
  - headers: Authorization: Bearer <token> (админ)
  - body: { "userId": <id> }

- POST /admin/revoke-pro
  - headers: Authorization: Bearer <token> (админ)
  - body: { "userId": <id> }

- GET /admin/users
  - headers: Authorization: Bearer <token> (админ)
  - список пользователей

Примеры (curl):

1) Регистрация:
```
curl -X POST http://localhost:3000/register -H "Content-Type: application/json" -d '{"username":"alice","password":"pass"}'
```

2) Вход:
```
curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"username":"alice","password":"pass"}'
```
Ответ даст токен: используйте его в Authorization.

3) Отправить личное сообщение пользователю с id=2:
```
curl -X POST http://localhost:3000/post -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d '{"content":"Привет!","toUserId":2}'
```

4) Отправить broadcast (всем):
```
curl -X POST http://localhost:3000/post -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d '{"content":"Всем привет!"}'
```

5) Админ выдает Pro пользователю id=3:
```
curl -X POST http://localhost:3000/admin/grant-pro -H "Content-Type: application/json" -H "Authorization: Bearer <ADMIN_TOKEN>" -d '{"userId":3}'
```

Дальнейшие улучшения (идеи):
- WebSocket / Socket.IO для real-time сообщений
- фронтенд (React/Vue) с UI
- валидация, лимиты на длину поста, модерация
- пагинация и поиск
- email-подтверждение, восстановление пароля
- юнит-тесты и CI
```
