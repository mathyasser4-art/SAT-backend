const userModel = require('../../DB/models/user.model');

/**
 * Helpers that stop the same person from getting more than one account.
 * Emails are stored lowercased/trimmed from now on, and lookups are
 * case-insensitive so older mixed-case records are still matched.
 */

const normalizeEmail = (email) => (email == null ? '' : String(email).trim().toLowerCase());

const escapeRegex = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const emailQuery = (email) => ({ $regex: `^${escapeRegex(normalizeEmail(email))}$`, $options: 'i' });

// Returns the existing account using this email (any role), or null.
const findAccountByEmail = async (email, excludeId = null) => {
    const clean = normalizeEmail(email);
    if (!clean) return null;
    const query = { email: emailQuery(clean) };
    if (excludeId) query._id = { $ne: excludeId };
    return userModel.findOne(query).select('_id userName email role');
};

// Normalizes body.email in place and returns an error message if another
// account already uses it (pass excludeId when updating an existing account).
const checkEmailAvailable = async (body, excludeId = null) => {
    if (!body || body.email == null || body.email === '') return null;
    body.email = normalizeEmail(body.email);
    const existing = await findAccountByEmail(body.email, excludeId);
    return existing ? 'This email is already registered to another account' : null;
};

// Serializes async work per key inside this process so concurrent requests
// (e.g. several roster loads at once) can't each create the same record.
const locks = new Map();
const withLock = async (key, fn) => {
    const prev = locks.get(key) || Promise.resolve();
    let release;
    const current = new Promise((resolve) => { release = resolve; });
    const chained = prev.then(() => current);
    locks.set(key, chained);
    try {
        await prev;
        return await fn();
    } finally {
        release();
        if (locks.get(key) === chained) locks.delete(key);
    }
};

module.exports = { normalizeEmail, escapeRegex, emailQuery, findAccountByEmail, checkEmailAvailable, withLock };
