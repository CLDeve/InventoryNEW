# InventoryNEW

Inventory web app with:
- Login and session handling
- Device Master Page
- User Setup Page
- User Management Page (rights-based access)
- Action Log Page

## Deploy To Render

This project is a static site (HTML/CSS/JS), so deploy it as a Render Static Site.

### Option 1: Blueprint (Recommended)

1. Push this repo to GitHub.
2. In Render, click `New` -> `Blueprint`.
3. Connect the GitHub repo `CLDeve/InventoryNEW`.
4. Render will detect `render.yaml` and create the service automatically.
5. Open the generated URL.

### Option 2: Manual Static Site

1. In Render, click `New` -> `Static Site`.
2. Connect repo `CLDeve/InventoryNEW`.
3. Use these settings:
   - Build Command: (leave empty)
   - Publish Directory: `.`
4. Deploy.

## Entry URL

The app entry point is `index.html`, which redirects to `login-page.html`.
