# Halo Trade — Landing Page

A standalone marketing landing page for Halo Trade. Completely separate from the
main app: its own repo, its own Railway service, its own URL. Every button links
to the live app at https://halo-trade-api-production.up.railway.app

## What's here

- `server.js` — a tiny zero-dependency Node server that serves the page
- `public/index.html` — the landing page itself (edit this to change content)
- `package.json` — tells Railway to run `node server.js`

## Deploy to Railway (new, separate service)

1. Create a **new GitHub repo** (e.g. `halo-landing`) and upload these three items:
   `server.js`, `package.json`, and the `public/` folder (with `index.html` inside).
2. In Railway, click **New Project → Deploy from GitHub repo** and pick that repo.
   (This creates a service completely separate from your app.)
3. Railway auto-detects Node, runs `npm start`, and gives you a URL like
   `https://halo-landing-production.up.railway.app`.
4. That URL is your ad link. Visit it to confirm the page loads.

No environment variables are needed. No database. Nothing to configure.

## Custom domain (recommended for ads)

In the landing service: **Settings → Networking → Custom Domain**, add your domain
(e.g. `halotrade.app`), and follow Railway's DNS instructions at your registrar.
Then your ad link becomes just `halotrade.app` instead of the long Railway URL.

## Updating the page later

Edit `public/index.html` in the repo, commit, and Railway redeploys automatically.
The main app is never affected.
