# Node + MySQL local registration (save in DB)

This is a small demo API: register a user (POST) to save data in MySQL, then fetch the saved details (GET).

## 1) Setup MySQL DB/table

Run the SQL in `sql/init.sql` (example using mysql CLI):

```bash
mysql -u root -p < sql/init.sql
```

Or start a local MySQL + phpMyAdmin using Docker (recommended):

```bash
cp .env.example .env
docker compose up -d
```

Then open phpMyAdmin in browser:
- `http://localhost:8081` (or your `PMA_PORT`)
- Server: `mysql`
- Username: `appuser`
- Password: `AppPass123!`
- Database: `demo_app`

## 2) Configure env

Copy `.env.example` to `.env` and set your DB credentials:

```bash
cp .env.example .env
```

If you call this API from Next.js, set `CORS_ORIGINS` in `.env` to your Next dev URL (example `http://localhost:3000`).

Port notes:
- If `PORT` is not set, the server picks a free port from `3000` to `3100`.
- If `PORT` is set, it must be free (unique) on your machine.

## phpMyAdmin login (Docker network fix)

If phpMyAdmin shows error like:
`Access denied for user 'appuser'@'172.19.0.2'`

It means you created `appuser@localhost` but phpMyAdmin is coming from a Docker IP.
Create a user allowed from any host (`%`) using this project (uses `DB_*` from `.env`):

```bash
npm run create:pmauser -- --pma-user appuser --pma-pass 'AppPass123!' --pma-host '%'
```

## 3) Install + run

```bash
npm install
npm run dev
```

Test with curl:

```bash
curl -sS -X POST 'http://localhost:<port>/api/register' \
  -H 'Content-Type: application/json' \
  -d '{"name":"Alice","email":"alice@example.com","phone":"9999999999","address":"Pune","password":"secret12"}'
```

Then fetch details:

```bash
curl -sS 'http://localhost:<port>/users/1'
```

Optional JSON list:
- `http://localhost:<port>/api/users`
