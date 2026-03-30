# Fix ERR_ERL_UNEXPECTED_X_FORWARDED_FOR + Railway Rate Limit Crash

## Plan Summary
**Files analyzed:**
- `backend-main/app.js`: Missing `app.set('trust proxy', 1);` before rate limiter
- `src/modules/admin/controller/admin.controller.js`: ✅ Uses correct `bcrypt.compareSync(password, findUser.password)`

**Root cause:** Railway proxy sends `X-Forwarded-For` → express-rate-limit crashes without trust proxy.

## Detailed Update Plan
### File: `backend-main/app.js`
- **Location**: After `app.use(express.json())` + DB connection, **before** rate limiter block
- **Change**: Add `app.set('trust proxy', 1);`
- **Lines**: ~65, before `const rateLimit = require('express-rate-limit');`

### Duplicate File: `app.js` (root)
- **Status**: Identical change needed (duplicated project structure)

## Dependent Files
- None

✅ **app.js files updated with `app.set('trust proxy', 1);`**

Next: Git commit/push/PR

