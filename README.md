# InventoryNEW

Inventory web app with:
- Login and session handling
- Device Master Page
- User Setup Page
- User Management Page (rights-based access)
- Action Log Page

## Architecture

- Frontend: static HTML/CSS/JS served by Express
- Backend: Node.js + Express (`server.js`)
- Database: PostgreSQL (Render Postgres)
- Auth: JWT token in browser `localStorage`

## Local Run

1. Install dependencies:
   - `npm install`
2. Set environment variables:
   - `DATABASE_URL=<postgres connection string>`
   - `JWT_SECRET=<any long random secret>`
   - Optional: `ADMIN_INITIAL_PASSWORD=ADMIN123`
3. Start app:
   - `npm start`
4. Open:
   - `http://localhost:3000`

## Deploy To Render (Blueprint)

1. Push this repo to GitHub.
2. In Render, click `New` -> `Blueprint`.
3. Connect the GitHub repo `CLDeve/InventoryNEW`.
4. Render will read `render.yaml` and create:
   - Web Service (`inventorynew`)
   - Postgres database (`inventorynew-db`)
5. Open the generated URL.

## Entry URL

The app entry point is `index.html`, which redirects to `login-page.html`.

## Default Login

- Username: `ADMIN`
- Password: `ADMIN123`
