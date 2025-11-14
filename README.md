# SoilCalcify Backend (Express + MySQL)

This backend provides a simple Express server with a MySQL connection pool for SoilCalcify.

## Setup

1. Navigate to the backend folder:
   - `cd backend`
2. Install dependencies:
   - `npm install`
3. Create an `.env` from the example and update credentials:
   - `copy .env.example .env` (Windows) or `cp .env.example .env` (macOS/Linux)
   - Confirm `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` with phpMyAdmin/hosting panel.
4. Run the server:
   - `npm run dev` (auto-restart with nodemon) or `npm start`

## Default Ports & Hosts

- Server: `http://localhost:8080` (configurable via `PORT`)
- DB host defaults to `soilcalcify.com` from `.env.example`.

## Diagnostic Endpoints

- `GET /health` — Server uptime and status.
- `GET /db/ping` — Tests DB connectivity with `SELECT 1`.
- `GET /db/version` — Returns MySQL server version.

## Profile & Upload Endpoints

- `GET /api/me` — Returns the authenticated user's profile. Requires `session` cookie.
- `PATCH /api/me` — Updates profile fields (`name`, `bio`, `location`, social links). Requires auth and CSRF.
- `POST /api/me/upload` — General upload for JPG/PNG/PDF up to 5MB. Requires auth and CSRF.
  - Virus scan optional via NodeClam when configured.

CSRF uses a double-submit cookie pattern:
- GET ` /api/csrf-token` to receive `{ token }` and a `csrfToken` cookie.
- Include the `x-csrf-token` header with the token on state-changing requests.

## Storage & Security

- Uploaded files are stored under `backend/uploads/` with randomized names, or in S3 when cloud storage is enabled.
- On Unix-like systems, files are chmod to `0640` to restrict access.
- Optional thumbnail generation for avatars uses `sharp` if installed (not required).
  - GIF thumbnails are skipped.
- Optional antivirus scanning uses `clamscan` (NodeClam) if installed and configured; infected uploads are rejected.
- Use a production-grade session store (Redis/DB) instead of the in-memory map.

### Optional Cloud Storage (S3)

- Enable with `USE_S3=true` in `.env`, and set:
  - `S3_BUCKET` — bucket name
  - `S3_REGION` — AWS region, e.g., `us-east-1`
  - `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`
  - Optional `S3_BASE_URL` to override URL construction (e.g., for CloudFront)

### Caching

- Static files under `/uploads` are served with `Cache-Control: public, max-age=31536000, immutable`.
- `/api/me` responses include `ETag` and short `Cache-Control` to reduce DB hits.

## Database Schema Changes

- New columns on `users`: `bio`, `location`, `website_url`, `twitter_url`, `linkedin_url`, `github_url`, `updated_at`.
- Index: `idx_users_updated_at` for cache invalidation and sorting.
- See `sql/alter_users_profile_fields.sql` for the manual script.

### Removing Legacy Avatar Columns

If your database has legacy avatar columns, run `sql/drop_avatar_columns.sql` to remove them safely.

## Notes

- If the MySQL server blocks remote connections, run this backend where the DB is reachable (e.g., same hosting), or allow your machine’s IP in the DB access list.
- Keep `.env` out of version control. Update `DB_NAME` and `DB_USER` as per your actual configuration (shared hosts often prefix both with the account ID).
- When integrating with the React app, enable CORS on endpoints you call from the browser.