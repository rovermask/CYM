# CYM

**CryptYourMind** is the website in which the user interacts with the website and enhances their knowledge. It is helpful for the user to increase the level of knowledge and the level of understanding. The storage facility of the project eases the task of the user to store the data securely. So in other words, this website is like a milestone in the field of cryptography, a correct base for their future prospective.


## Setup

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
cp .env.example .env        # then fill in the values
.venv/Scripts/python manage.py runserver
```

There is no SQL database. Sign-in is **Firebase Authentication** (Email/Password) and vault
entries live in **Firestore**; the server encrypts each note with a per-user key before storing it.

### Firebase console checklist
1. **Authentication → Get started → Sign-in method → Email/Password → Enable.**
2. **Firestore Database → Create database.** Start in *production mode*; the server uses the Admin SDK, so
   lock client access completely with the rule `allow read, write: if false;`.
3. **Project settings → Service accounts → Generate new private key** → save as `serviceAccountKey.json`
   (or put the JSON in `FIREBASE_SERVICE_ACCOUNT_JSON` on Vercel). Never commit it.
4. **Authentication → Settings → Authorized domains**: add your Vercel domain.

### Admin panel
`/manage/` is available only to users with the Firebase `admin` custom claim. Grant it after the account exists:

```bash
.venv/Scripts/python manage.py make_admin you@example.com   # sign out and in again afterwards
```

### Tests
```bash
.venv/Scripts/python manage.py test
```

## Deploying to Vercel

The repo is ready for Vercel (`vercel.json`, `.vercelignore`, `requirements.txt`). No build step is needed.

1. Push the repo to GitHub, then **Vercel → Add New → Project → import it** (Framework preset: *Other*).
2. Add these **Environment Variables** (Production, and Preview if you use it):

   | Name | Value |
   |---|---|
   | `DJANGO_SECRET_KEY` | a long random string. Keep it fixed: vault encryption keys derive from it |
   | `FIREBASE_WEB_CONFIG` | the one-line web config JSON from `.env` |
   | `FIREBASE_SERVICE_ACCOUNT_JSON` | the **entire contents** of `serviceAccountKey.json` |
   | `DJANGO_ALLOWED_HOSTS` | *(optional)* your custom domain(s), comma-separated |

3. Deploy. Then in **Firebase → Authentication → Settings → Authorized domains**, add your `*.vercel.app`
   domain (and custom domain), otherwise sign-in is blocked.

CLI alternative: `npx vercel` (preview) and `npx vercel --prod`, after adding the variables above.
