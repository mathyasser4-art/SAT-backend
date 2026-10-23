/**
 * Cleanup Script: find and merge duplicated accounts
 *
 * 1. Parent accounts: when a student is linked to more than one Parent account
 *    (created by parallel roster loads), the extra parents are merged into one —
 *    their children are moved over, students are re-pointed, and the extras removed.
 * 2. Every other role: accounts sharing the same email (ignoring upper/lower case)
 *    are reported only, because they may own homework answers and need a human
 *    decision on which one to keep.
 * 3. Emails are lowercased/trimmed on accounts where that causes no conflict.
 *
 * Usage (dry run — only prints what it would do):
 *   ONLINE_CONNECTION_DB=<uri> node src/scripts/dedupeAccounts.js
 * Apply the changes:
 *   ONLINE_CONNECTION_DB=<uri> node src/scripts/dedupeAccounts.js --apply
 */

require('dotenv').config();
const mongoose = require('mongoose');
const userModel = require('../../DB/models/user.model');

const APPLY = process.argv.includes('--apply');

async function mergeDuplicateParents() {
    const parents = await userModel.find({ role: 'Parent' }).select('_id userName email children parentPhone').lean();
    const parentsByChild = new Map();
    parents.forEach(p => (p.children || []).forEach(c => {
        const key = String(c);
        if (!parentsByChild.has(key)) parentsByChild.set(key, []);
        parentsByChild.get(key).push(p);
    }));

    const removed = new Set();
    let merged = 0;
    for (const [childId, list] of parentsByChild) {
        const live = list.filter(p => !removed.has(String(p._id)));
        if (live.length < 2) continue;

        const student = await userModel.findById(childId).select('userName parent').lean();
        // Keep the parent the student already points to, otherwise the oldest one
        const keep = live.find(p => student && String(p._id) === String(student.parent))
            || live.slice().sort((a, b) => String(a._id).localeCompare(String(b._id)))[0];
        const extras = live.filter(p => String(p._id) !== String(keep._id));

        console.log(`Student ${student?.userName || childId}: keep ${keep.userName} <${keep.email}>, merge ${extras.map(e => e.userName).join(', ')}`);
        merged += extras.length;
        extras.forEach(e => removed.add(String(e._id)));

        if (APPLY) {
            const allChildren = [...new Set([keep, ...extras].flatMap(p => (p.children || []).map(String)))];
            const phone = keep.parentPhone || extras.map(e => e.parentPhone).find(Boolean) || '';
            await userModel.updateOne({ _id: keep._id }, { children: allChildren, parentPhone: phone });
            await userModel.updateMany({ parent: { $in: extras.map(e => e._id) } }, { parent: keep._id });
            await userModel.deleteMany({ _id: { $in: extras.map(e => e._id) } });
        }
    }
    console.log(`\nDuplicate parent accounts ${APPLY ? 'merged' : 'to merge'}: ${merged}\n`);
}

async function reportDuplicateEmails() {
    const groups = await userModel.aggregate([
        { $match: { email: { $type: 'string', $ne: '' } } },
        { $group: { _id: { $toLower: { $trim: { input: '$email' } } }, users: { $push: { id: '$_id', userName: '$userName', role: '$role', email: '$email' } }, count: { $sum: 1 } } },
        { $match: { count: { $gt: 1 } } }
    ]);
    console.log(`Emails used by more than one account: ${groups.length}`);
    groups.forEach(g => {
        console.log(`  ${g._id}`);
        g.users.forEach(u => console.log(`    - ${u.role}  ${u.userName}  (${u.id})`));
    });
    return new Set(groups.map(g => g._id));
}

async function normalizeEmails(conflicts) {
    const users = await userModel.find({ email: { $type: 'string' } }).select('_id email').lean();
    const toFix = users.filter(u => u.email !== u.email.trim().toLowerCase() && !conflicts.has(u.email.trim().toLowerCase()));
    console.log(`\nEmails to lowercase: ${toFix.length}`);
    if (APPLY) {
        for (const u of toFix) await userModel.updateOne({ _id: u._id }, { email: u.email.trim().toLowerCase() });
    }
}

async function run() {
    const uri = process.env.ONLINE_CONNECTION_DB || process.env.DATABASE_URL || process.env.MONGODB_URI || process.env.MONGO_URI;
    if (!uri) {
        console.error('ERROR: ONLINE_CONNECTION_DB environment variable is not set.');
        process.exit(1);
    }
    await mongoose.connect(uri);
    console.log(APPLY ? '*** APPLY MODE — changes will be written ***\n' : 'Dry run — nothing will be changed (pass --apply to write)\n');

    await mergeDuplicateParents();
    const conflicts = await reportDuplicateEmails();
    await normalizeEmails(conflicts);

    await mongoose.disconnect();
}

run().catch(err => {
    console.error(err);
    process.exit(1);
});
