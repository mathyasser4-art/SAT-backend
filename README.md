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

### LiveClass (video meetings)

A course teacher starts a LiveClass from the course page and the course's enrolled students join it
(`src/modules/live/`). Video runs on [LiveKit](https://livekit.io) (LiveKit Cloud or self-hosted);
this API only checks who may join, hands out room tokens and runs the host controls (waiting room,
lock, mute, remove, end). Without these variables the `/live/*` routes answer 503.

Each course also has a guest invite link (`/live/join/<token>`, managed with
`GET/PUT /live/:courseId/guest-link`). People without an account, or from another course, enter a
name and always go to the waiting room; the public `/live/guest/:token/*` routes are rate-limited
and only hand out a LiveKit token (camera and mic only) after the host admits them.

| Variable             | Description                                         |
|----------------------|-----------------------------------------------------|
| `LIVEKIT_URL`        | LiveKit server URL, e.g. `wss://your-project.livekit.cloud` |
| `LIVEKIT_API_KEY`    | LiveKit API key                                     |
| `LIVEKIT_API_SECRET` | LiveKit API secret                                  |

**Cloud recording.** The host can record a LiveClass (`POST /live/:courseId/recording/start|stop`).
LiveKit Egress records the site's `/live/recorder` page (shared screen with its annotations,
whiteboard, cameras, opened on the https site the host started from) to a 720p MP4 and uploads it to
an S3-compatible bucket (Cloudflare R2 recommended: no fees when students watch). Recordings are listed with short-lived
signed links at `GET /live/:courseId/recordings` (teacher: all, students: ready ones) and deleted
with `DELETE /live/:courseId/recordings/:id`. Without these variables the Record button is hidden.

| Variable                  | Description                                                    |
|---------------------------|----------------------------------------------------------------|
| `RECORDING_S3_ENDPOINT`   | e.g. `https://<account-id>.r2.cloudflarestorage.com`           |
| `RECORDING_S3_BUCKET`     | Bucket name, e.g. `satarea-recordings`                         |
| `RECORDING_S3_ACCESS_KEY` | Access Key ID of an R2 API token with Object Read & Write      |
| `RECORDING_S3_SECRET`     | Secret Access Key of that token                                |
| `RECORDING_S3_REGION`     | Optional, defaults to `auto` (R2)                              |
| `RECORDING_PAGE_ORIGIN`   | Optional, site whose recorder page is recorded (e.g. a staging URL) |

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
