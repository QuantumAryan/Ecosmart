# EcoSmart (Node + Neon Postgres)

1. Install Node.js 18+ from nodejs.org
2. In this folder run:  npm install
3. Run:  npm start
4. Open http://localhost:3000  (not the HTML file directly)

Tables (users, survey_responses, subscribers) are created automatically on first start.
The .env file holds your database URL and JWT secret. Never upload it to GitHub or share it.

Deploy (Render/Railway): upload this folder, set DATABASE_URL and JWT_SECRET as environment variables,
build command "npm install", start command "npm start".

## Deploy on Vercel
1. Push this folder to GitHub (.env is ignored automatically).
2. vercel.com > Add New > Project > import the repo. Framework: Other. Leave build settings empty.
3. Settings > Environment Variables: add DATABASE_URL and JWT_SECRET, then Deploy.

## Database tables (created automatically)
users, survey_responses, subscribers, device_marks (devices people use / plan to buy), checklist (habit progress).

## Emails (no OTP)
After register and after each sign-in the site sends a "successful registration / sign-in" notification email.
Set SMTP_USER and SMTP_PASS (Gmail App Password) in .env and in Vercel. If they are missing, emails are skipped and sign-up still works.

Set SITE_URL (your live site address, no trailing slash) in Vercel so the logo (public/logo.png) shows in emails.
Edit the email wording in server.js between the 'EDIT YOUR EMAILS HERE' lines.
