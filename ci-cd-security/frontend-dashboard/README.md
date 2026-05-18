# DevSecOps Dashboard — Vite + React

This is the React/Vite version of the VulnPriority AI dashboard.

## Run

```bash
npm install
npm run dev
```

The dev server is pinned to:

```text
http://127.0.0.1:5500
```

That matches the current FastAPI backend CORS default in `main.py`.

## Environment

Create `.env` in the project root:

```env
VITE_API_URL=http://127.0.0.1:8000
```

Restart Vite after editing `.env`.

## Backend `.env` reminders

Your backend must have these set for login and protected endpoints:

```env
API_AUTH_TOKEN=your-local-token
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=your-password
DASHBOARD_ORIGINS=http://127.0.0.1:5500,http://localhost:5500
```

For DefectDojo sync/products:

```env
DEFECTDOJO_URL=http://127.0.0.1:8080
DEFECTDOJO_API_KEY=your-defectdojo-token
DEFECTDOJO_PRODUCT_ID=3
```

If you choose to run Vite on `5173` instead, update backend `.env`:

```env
DASHBOARD_ORIGINS=http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:5173,http://localhost:5173
```
