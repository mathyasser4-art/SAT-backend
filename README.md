# SAT Backend

Node.js/Express API server backed by MongoDB.

---

## Getting Started

```bash
npm install
npm start        # production
npm run dev      # development (nodemon)
```

### Required environment variables

| Variable              | Description                                      |
|-----------------------|--------------------------------------------------|
| `ONLINE_CONNECTION_DB`| MongoDB connection string                        |
| `TOKEN_SECRET_KEY`    | Secret used to sign JWT tokens                   |
| `SALTROUNDS`          | bcrypt salt rounds (e.g. `10`)                   |
| `PORT`                | HTTP port (default `3000`)                       |

### AI Copilot (teachers)

The Copilot (`src/modules/ai/copilot/`) runs on Claude. It answers only signed-in teacher, school,
supervisor, IT and admin accounts, and only reaches that account's own classes, courses and students.
Changes (create, edit, re-assign, delete homework) wait for the teacher to press Confirm, and every
confirmed change is logged in the `copilotaudits` collection.

| Variable                       | Description                                                      |
|--------------------------------|------------------------------------------------------------------|
| `ANTHROPIC_API_KEY`            | Claude API key. Used by the Copilot and by the students' AI mistakes analysis (which falls back to a built-in keyword classifier without it) |
| `COPILOT_MODEL`                | Optional, default `claude-opus-5-5`                              |
| `COPILOT_EFFORT`               | Optional, `low` / `medium` / `high`, default `medium`            |
| `COPILOT_DEFAULT_COUNTRY_CODE` | Optional, used for WhatsApp links when a phone number starts with 0 |

---

## Password Migration

Legacy user accounts created before bcrypt hashing was introduced store
passwords as plain text in MongoDB. The login controller includes a
transparent fallback that detects a plain-text match, logs the user in, and
immediately rehashes the password — so individual accounts are migrated
automatically on their next login.

To migrate **all** remaining plain-text passwords in one go, run the
migration script:

```bash
ONLINE_CONNECTION_DB=<uri> SALTROUNDS=10 node src/scripts/migratePasswordsToHash.js
```

The script is idempotent — accounts that already have a bcrypt hash are
skipped. Run it once after deploying this update to ensure every account is
fully migrated before the login fallback is removed in a future release.
