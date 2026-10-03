# Онлайн-сервер «Маршрутний Нова Пошта»

Схема: Android → Render Node.js API → Supabase PostgreSQL.

## 1. Supabase
1. Створіть безкоштовний проєкт у Supabase.
2. Відкрийте Connect / Database і скопіюйте PostgreSQL connection string.
3. Не публікуйте цей рядок і пароль.

Free-план Supabase має 500 MB PostgreSQL на проєкт. Проєкти Free можуть призупинятися після періоду неактивності.

## 2. GitHub
Створіть репозиторій і завантажте в нього папку `server` та `render.yaml`.

## 3. Render
New → Web Service → підключіть GitHub repository.
Якщо `render.yaml` використовується як Blueprint, Render створить Web Service.

Environment Variables:
- DATABASE_URL = PostgreSQL connection string із Supabase
- JWT_SECRET = довгий випадковий секрет (можна залишити Generate Value)
- ADMIN_EMAIL = ваш e-mail адміністратора
- ADMIN_PASSWORD = новий складний пароль адміністратора
- ADMIN_NAME = Адміністратор

Після Deploy отримаєте адресу виду:
https://marshrutnyi-nova-poshta-api.onrender.com

Перевірка:
https://ВАША-АДРЕСА.onrender.com/api/health

Має повернути:
{"ok":true,"db":true}

## 4. Android
У застосунку відкрийте:
Меню → Акаунт і синхронізація → Адреса сервера
і вставте адресу Render БЕЗ `/api`.

Наприклад:
https://marshrutnyi-nova-poshta-api.onrender.com

## Важливо
Безкоштовний Render Web Service засинає після 15 хвилин без запитів, тому перший запит після простою може чекати близько хвилини.
Для постійного зберігання маршрутів не використовуйте `data.json` на Render — цей пакет використовує PostgreSQL.
