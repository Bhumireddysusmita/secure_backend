# secure_backend

FastAPI + PostgreSQL auth API.

## Local development

```bash
pip install -r requirements-dev.txt
cp .env.example .env   # fill in values
alembic upgrade head
uvicorn app.main:app --reload
```

## Deploy to Vercel

The app runs as one Python serverless function: [api/index.py](api/index.py) exposes the FastAPI app and
[vercel.json](vercel.json) routes every path to it.

1. **Database.** Use a hosted Postgres (Neon, Supabase, Vercel Postgres…). Use its *pooled* connection
   string for `DATABASE_URL` (on Vercel the app opens one connection per request, with no pool of its own).
2. **Run migrations** from your machine against that database (Vercel doesn't run them):
   ```bash
   DATABASE_URL="<direct, non-pooled url>" alembic upgrade head
   ```
3. **Import the repo** in Vercel (Framework preset: *Other*, no build command).
4. **Set environment variables** (Project → Settings → Environment Variables):

   | Variable | Value |
   | --- | --- |
   | `APP_ENV` | `production` |
   | `DATABASE_URL` | pooled Postgres URL |
   | `SESSION_SECRET` | 32+ random chars (`python -c "import secrets; print(secrets.token_urlsafe(48))"`) |
   | `TURNSTILE_SECRET_KEY` | your Cloudflare Turnstile secret |
   | `APP_URL` | your frontend origin(s), comma-separated, e.g. `https://myapp.vercel.app` |
   | `TRUST_PROXY` | `true` (Vercel sets `X-Forwarded-For`; needed for per-IP rate limits) |

5. Deploy, then check `https://<your-project>.vercel.app/api/health`.

Note: the session cookie is `SameSite=Lax`, so the browser only sends it when the frontend and the API share
a site. Serve both from one domain (e.g. app on `example.com`, API on `api.example.com`), or add a rewrite
in the frontend project that proxies `/api/*` to this backend.
