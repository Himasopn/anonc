# anonc by ascloud • Encrypted Cloud Workspace

A modern, Apple iOS OLED dark-mode, high-speed multi-user cloud storage workspace powered by Telegram as the encrypted backend database.

## Features
- **Official Branding:** anonc by ascloud.
- **Telegram Channel Cloud Database (`userdatabase`):** Uses a dedicated private Telegram channel (`userdatabase`) as the persistent, distributed database. User accounts, folders, and uploaded files are synced across server restarts and Vercel cold boots.
- **Public Multi-User Platform with Strict Isolation:** Anyone can register with a unique username and password. Each user can only view, search, stream, download, and delete their own files and folders.
- **Cancel Upload Option:** Cancel running uploads with 1 click. Both browser-side and server-side Telegram transfers are aborted immediately.
- **Pipelined Concurrent Transfers:** Fast chunked MTProto streaming with C-accelerated `TgCrypto` hardware AES-NI encryption.
- **Accurate Real-Time Progress:** Shows live % completion, exact bytes transferred (`250 MB / 500 MB`), and live speed in MB/s.
- **Folder Organization:** Create folders and nested subfolders (`Files › Work › Projects`), organize files, and navigate via breadcrumbs.
- **Direct CDN / Stream Links:** Every file has a direct link (`/d/{id}` or `/api/stream/{id}`) with full HTTP 206 Range seeking for VLC, MX Player, or any browser.
- **Vercel Deployable:** Pre-configured with `vercel.json` and `@vercel/python`.

---

## 1. Running Locally (Localhost)

Simply double-click `run.bat` or run:
```bash
python main.py
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

Your Telegram API credentials:
- **API ID:** `38648695`
- **API Hash:** `9ea926414705c631aa6a908991cac059`
- Master session is auto-loaded from `data/session_string.txt`. Normal visitors to the site register an account and never need Telegram credentials.

---

## 2. Deploying to Vercel

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "anonc by ascloud release"
git branch -M main
git remote add origin https://github.com/<your-username>/<repo-name>.git
git push -u origin main
```

### Step 2: Import into Vercel
1. Go to [vercel.com](https://vercel.com) and click **"Add New Project"**.
2. Select your repository.
3. In **Environment Variables**, add:
   - `TELEGRAM_API_ID`: `38648695`
   - `TELEGRAM_API_HASH`: `9ea926414705c631aa6a908991cac059`
   - `TELEGRAM_SESSION`: *(Copy the StringSession from `data/session_string.txt`)*
4. Click **Deploy**.
