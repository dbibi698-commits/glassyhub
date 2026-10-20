# GlassHub — All-in-one website starter

GlassHub is a responsive liquid-glass style web app with a Python/Flask backend, HTML/CSS/JavaScript frontend, user accounts, admin-only dashboard, bookings, tool pages and shortcut directories.

## Included
- Dashboard with animated glass UI and right-side/mobile navigation
- Register/login/logout with salted PBKDF2 password hashing
- Admin dashboard restricted to `dbibi698@gmail.com` by default
- User list, account block/unblock, booking status management and recent app events
- Cyber cafe booking request form for printing/document assistance
- Comprehensive named feature grid (PDF tools, JPG/PNG to PDF, multi-image PDF, image resize, background remover integration, cyber cafe cards/printing/recharge, website builder requests, social/AI/search, settings and history)
- PDF rewrite/optimization attempt, multi-image to PDF, image resizer with optional GlassHub watermark, QR code generator
- Admin-published notifications for all users or a selected account, with mark-as-read
- AI/social shortcut directories and custom shortcuts
- Public website preview (some websites block iframe embedding)
- Local preferences and local tool history

## Run on computer or Termux
1. Install Python 3.10+.
2. Extract the ZIP and open a terminal in this folder.
3. Install dependencies:
   `python -m pip install -r requirements.txt`
4. Set a strong secret key before running. In Termux:
   `export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"`
   `export ADMIN_EMAIL="dbibi698@gmail.com"`
5. Start:
   `python app.py`
6. Open `http://127.0.0.1:5000` in the device browser.

For Termux, use `pkg update && pkg install python` before step 3 if needed. Keep the terminal running while using the local website.

## Admin access
Register an account using **exactly** `dbibi698@gmail.com`; that account is assigned the admin role. Choose a strong password and keep it private. Other emails become normal users. This starter does not send email verification or password-reset emails yet; those require configuring a mail provider. For a public deployment, use HTTPS, a production WSGI server, CSRF protection, rate limiting, verified email ownership and backups.

## Important limitations
- This is a starter project, not a production-ready government-service portal. Several services are booking/request pages rather than direct integrations.
- The background remover is a clearly marked integration placeholder. Put provider API keys on the server as environment variables; never paste secret API keys into frontend code.
- PDF optimizer rewrites the PDF but cannot promise a specific target size. Actual compression may need a server-side tool such as Ghostscript.
- Social/AI links open official service pages in a new tab. Website preview may fail for sites that block iframe embedding.
- App activity logs are limited to events inside this app. It does not secretly track GPS, other websites or a user's whole device. Tell users what is logged and follow applicable privacy law.
- Government document services are booking requests/guidance only. Use official portals and never collect OTPs, passwords or unnecessary sensitive ID numbers.
- No APK code or APK build configuration is included, as requested. This web project can later be wrapped with a suitable Android WebView/PWA workflow.
