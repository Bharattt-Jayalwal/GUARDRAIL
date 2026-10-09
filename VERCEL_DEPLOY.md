# Deploy Guardrail to Vercel

This package adds a root-level `index.py` FastAPI entrypoint and root-level `requirements.txt`, so Vercel can detect the app and install its dependencies.

## 1. Import the project

1. Extract this ZIP into a new folder.
2. Upload the **contents of this folder** to a GitHub repository (the repository root must contain `index.py`, `requirements.txt`, `backend/`, and `static/`).
3. In Vercel, import that repository.
4. In Project Settings → Build and Development Settings, leave the Root Directory as `./` (repository root). Do not select `backend/` or `static/`.
5. Deploy.

## 2. Add environment variables

In Vercel → Project → Settings → Environment Variables, add these for Production (and Preview if needed):

- `APP_ENV` = `production`
- `JWT_SECRET` = a unique random secret of at least 32 characters. Generate one locally with `python -c "import secrets; print(secrets.token_urlsafe(48))"` and paste the result into Vercel. Never commit it.
- `DATABASE_URL` = a managed PostgreSQL connection string (for example, from Neon or another hosted PostgreSQL provider). Use the provider's pooled/runtime-compatible connection string where offered.

Redeploy after saving environment variables. Without a managed `DATABASE_URL`, the package uses a temporary `/tmp` SQLite database on Vercel only so the preview can boot; that database is ephemeral and is **not suitable for real accounts or production use**. Do not rely on it for user data.

## 3. Smoke-test

After deployment, open:

- `/` — marketing homepage
- `/health` — should return `{"status":"ok","service":"guardrail","environment":"production"}`
- `/app` — dashboard

If the page still errors, open Vercel → Deployments → latest deployment → Functions/Runtime Logs and share the first Python traceback. Do not share secrets or the full database URL.

## Notes

- Keep the Vercel Root Directory at the repository root, where `index.py` is located.
- This is an early-stage MVP. Use a sandbox and review security before connecting real payment or customer-data actions.
