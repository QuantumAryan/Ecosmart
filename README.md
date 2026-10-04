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

## Email verification (Gmail)
1. Sign in to leave.ecosmart@gmail.com > Google Account > Security > turn on 2-Step Verification.
2. Security > App passwords > create one named "EcoSmart" (16 characters).
3. Put it in .env as SMTP_PASS=... (no spaces) and add SMTP_USER and SMTP_PASS in Vercel > Settings > Environment Variables, then redeploy.
Without SMTP settings, local runs print the code in the terminal; on Vercel, sign-up shows an email error.
