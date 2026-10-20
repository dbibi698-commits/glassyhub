# GlassHub — All-in-one Web App Starter

## Run locally
1. Install Python 3.10+.
2. Open a terminal in this folder.
3. Install: `python -m pip install -r requirements.txt`
4. Set a strong session secret and admin email. Windows PowerShell: `$env:FLASK_SECRET_KEY="your-long-random-secret"; $env:ADMIN_EMAIL="dbibi698@gmail.com"`. Termux/Linux: `export FLASK_SECRET_KEY="your-long-random-secret"; export ADMIN_EMAIL="dbibi698@gmail.com"`.
5. Start: `python app.py`
6. Open `http://127.0.0.1:5000`.

## Admin
Register using `dbibi698@gmail.com` to receive the admin role. Other email addresses become regular users. This is not email ownership verification; add an email provider and verification flow before public deployment. Use a strong password and secret key.

## Included features
- Dashboard web search engine selector (Google, Brave, Bing, DuckDuckGo, YouTube)
- Login/register/logout, profile picture, display name, password change
- Separate admin dashboard tabs for users, bookings, feature toggles/add/edit, website settings, notifications, activity
- Admin can edit user display name, block/unblock accounts, accept/reject/review/complete bookings and attach a review message
- Admin-managed feature tiles and website About/Privacy/Guidelines settings
- PDF upload and rasterized PDF compression/download (text is converted to images; quality/size trade-off)
- Image upload preview, resize, quality control, optional GlassHub watermark
- Multiple JPG/PNG images to PDF
- AI and social shortcuts, add-your-own shortcuts
- Phone and PC wallpaper generator with download
- Local history/preferences export and admin JSON backup
- Cyber cafe booking categories for cards, printing, scan, recharge, website help and photo editing

## Important limits
- The background remover requires a provider-specific server-side integration. Never put API keys in public JavaScript.
- PDF compression rasterizes pages and cannot unlock password-protected PDFs. It cannot guarantee a precise KB target.
- Website shortcuts open external sites in new tabs; this app does not install or control native apps on the device.
- Bookings for government-document help are requests only, not direct government application APIs. Never collect OTPs or passwords.
- For production: use HTTPS, a production WSGI server, CSRF protection, login rate limits, verified email ownership, secure secrets, backups, privacy notice and consent for activity logs.
- Firebase is not connected in this starter. To connect Firebase free tier, create a Firebase project, enable Authentication > Email/Password, create Firestore, then add the Firebase Web SDK config and security rules. Never make Firestore public; backend authorization still must protect admin operations.
- No APK build files included.
