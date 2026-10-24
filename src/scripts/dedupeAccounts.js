/**
 * Cleanup Script: find and merge duplicated accounts
 *
 * 1. Parent accounts: when a student is linked to more than one Parent account
 *    (created by parallel roster loads), the extra parents are merged into one —
 *    their children are moved over, students are re-pointed, and the extras removed.
 * 2. Student accounts that share an email (ignoring upper/lower case) are merged
 *    into the one that works: the account that is in a class or course and has
 *    the most homework answers is kept. Everything the extra copies own is moved
 *    to it first — homework answers (as extra trials, so no mark is lost),
 *    attempt counters, course enrolments and progress, uploaded HW papers,
 *    practice history and parent links — then the extra copies are deleted.
 *    Add --by-name to also merge students with the exact same name created by
 *    the same teacher/school (use the dry run to check the list first).
 * 3. Every other role: accounts sharing an email are reported only.
 * 4. Emails are lowercased/trimmed on accounts where that causes no conflict.
 *
 * Usage (dry run — only prints what it would do):
 *   ONLINE_CONNECTION_DB=<uri> node src/scripts/dedupeAccounts.js
 * Apply the changes:
 *   ONLINE_CONNECTION_DB=<uri> node src/scripts/dedupeAccounts.js --apply
 */

require('dotenv').config();
const mongoose = require('mongoose');
const userModel = require('../../DB/models/user.model');
const answerModel = require('../../DB/models/answer.model');
const assignmentModel = require('../../DB/models/assignment.model');
const courseModel = require('../../DB/models/course.model');
const practiceAttemptModel = require('../../DB/models/practiceAttempt.model');
const journeyProgressModel = require('../../DB/models/journeyProgress.model');

const APPLY = process.argv.includes('--apply');
const BY_NAME = process.argv.includes('--by-name');

const idStr = (v) => String(v && v._id ? v._id : v);

// Groups of student accounts that belong to the same person
async function findStudentDuplicateGroups() {
    const students = await userModel.find({ role: 'Student' })
        .select('_id userName email class classList parent createdBy').lean();
    const groups = new Map();
    const add = (key, s) => {
        if (!groups.has(key)) groups.set(key, new Map());
        groups.get(key).set(idStr(s._id), s);
    };
    students.forEach(s => {
        const email = String(s.email || '').trim().toLowerCase();
        if (email) add(`email:${email}`, s);
        if (BY_NAME) {
            const name = String(s.userName || '').trim().toLowerCase().replace(/\s+/g, ' ');
            if (name) add(`name:${name}|${idStr(s.createdBy)}`, s);
        }
    });
    // Join groups that share an account so one person ends up in one group
    const merged = [];
    const seen = new Set();
    for (const [key, members] of groups) {
        if (members.size < 2 || seen.has(key)) continue;
        const all = new Map(members);
        let grew = true;
        while (grew) {
            grew = false;
            for (const [otherKey, otherMembers] of groups) {
                if (seen.has(otherKey) || otherMembers.size < 2 || otherKey === key) continue;
                if ([...otherMembers.keys()].some(id => all.has(id))) {
                    otherMembers.forEach((v, k) => all.set(k, v));
                    seen.add(otherKey);
                    grew = true;
                }
            }
        }
        seen.add(key);
        merged.push({ key, members: [...all.values()] });
    }
    return merged;
}

async function scoreStudent(s) {
    const [answers, courses, latest] = await Promise.all([
        answerModel.countDocuments({ solveBy: s._id }),
        courseModel.countDocuments({ students: s._id }),
        answerModel.findOne({ solveBy: s._id }).sort({ updatedAt: -1 }).select('updatedAt').lean()
    ]);
    const hasClass = Boolean(s.class) || (Array.isArray(s.classList) && s.classList.length > 0);
    return {
        s, answers, courses, hasClass,
        canSeeHomework: hasClass || courses > 0,
        lastActive: latest?.updatedAt ? new Date(latest.updatedAt).getTime() : 0
    };
}

// Keep the account that can see homework, then the one the student used most
// recently (the login they actually use), then the one with most work, then the oldest
const compareStudents = (a, b) =>
    (Number(b.canSeeHomework) - Number(a.canSeeHomework))
    || (b.lastActive - a.lastActive)
    || (b.answers - a.answers)
    || idStr(a.s._id).localeCompare(idStr(b.s._id));

async function moveStudentData(dup, keep) {
    const dupId = dup._id;
    const keepId = keep._id;

    // Homework answers: append the copy's trials after the kept account's trials
    const dupAnswers = await answerModel.find({ solveBy: dupId }).sort({ attemptNumber: 1, createdAt: 1 });
    const touchedAssignments = new Set();
    for (const ans of dupAnswers) {
        const last = await answerModel.findOne({ solveBy: keepId, assignment: ans.assignment }).sort({ attemptNumber: -1 }).select('attemptNumber').lean();
        ans.solveBy = keepId;
        ans.attemptNumber = (last?.attemptNumber || 0) + 1;
        await ans.save();
        touchedAssignments.add(idStr(ans.assignment));
    }

    // Attempt counters on assignments
    const assignments = await assignmentModel.find({ 'students.solveBy': { $in: [dupId, keepId] } });
    for (const a of assignments) {
        const hasDup = a.students.some(st => idStr(st.solveBy) === idStr(dupId));
        if (!hasDup && !touchedAssignments.has(idStr(a._id))) continue;
        const keepEntries = a.students.filter(st => [idStr(dupId), idStr(keepId)].includes(idStr(st.solveBy)));
        const last = await answerModel.findOne({ solveBy: keepId, assignment: a._id }).sort({ attemptNumber: -1 }).select('attemptNumber').lean();
        const attempts = Math.max(last?.attemptNumber || 0, ...keepEntries.map(st => st.attempts || 0));
        a.students = a.students.filter(st => ![idStr(dupId), idStr(keepId)].includes(idStr(st.solveBy)));
        a.students.push({ solveBy: keepId, attempts });
        await a.save();
    }

    // Courses: enrolment, session progress, uploaded homework papers
    const courses = await courseModel.find({
        $or: [{ students: dupId }, { 'progress.studentId': dupId }, { 'sessions.studentHwSubmissions.studentId': dupId }]
    });
    for (const c of courses) {
        if ((c.students || []).some(id => idStr(id) === idStr(dupId))) {
            c.students = [...new Set([...c.students.map(idStr).filter(id => id !== idStr(dupId)), idStr(keepId)])];
        }
        const dupProgress = (c.progress || []).find(p => idStr(p.studentId) === idStr(dupId));
        if (dupProgress) {
            let keepProgress = c.progress.find(p => idStr(p.studentId) === idStr(keepId));
            if (!keepProgress) {
                c.progress.push({ studentId: keepId, completedSessions: [] });
                keepProgress = c.progress[c.progress.length - 1];
            }
            keepProgress.completedSessions = [...new Set([...(keepProgress.completedSessions || []), ...(dupProgress.completedSessions || [])].map(idStr))];
            c.progress = c.progress.filter(p => idStr(p.studentId) !== idStr(dupId));
        }
        (c.sessions || []).forEach(sess => (sess.studentHwSubmissions || []).forEach(sub => {
            if (idStr(sub.studentId) === idStr(dupId)) sub.studentId = keepId;
        }));
        await c.save();
    }

    // Practice and journey history
    await practiceAttemptModel.updateMany({ studentId: dupId }, { studentId: keepId });
    const journeys = await journeyProgressModel.find({ studentId: dupId });
    for (const j of journeys) {
        j.studentId = keepId;
        await j.save().catch(() => {}); // kept account already has this subject: keep its own progress
    }

    // Parent links and the kept account's own details
    await userModel.updateMany({ children: dupId }, { $addToSet: { children: keepId } });
    await userModel.updateMany({ children: dupId }, { $pull: { children: dupId } });
    const keepDoc = await userModel.findById(keepId);
    const dupDoc = await userModel.findById(dupId).lean();
    if (keepDoc && dupDoc) {
        if (!keepDoc.class && dupDoc.class) keepDoc.class = dupDoc.class;
        keepDoc.classList = [...new Set([...(keepDoc.classList || []), ...(dupDoc.classList || [])].map(idStr))];
        if (!keepDoc.parent && dupDoc.parent) keepDoc.parent = dupDoc.parent;
        if (!keepDoc.parentPhone && dupDoc.parentPhone) keepDoc.parentPhone = dupDoc.parentPhone;
        if (!keepDoc.phone && dupDoc.phone) keepDoc.phone = dupDoc.phone;
        await keepDoc.save();
    }
    await userModel.deleteOne({ _id: dupId });
}

async function mergeDuplicateStudents() {
    const groups = await findStudentDuplicateGroups();
    let removed = 0;
    for (const group of groups) {
        const scored = await Promise.all(group.members.map(scoreStudent));
        scored.sort(compareStudents);
        const [keep, ...extras] = scored;
        const describe = (x) => `${x.s.userName} <${x.s.email || 'no email'}> (${idStr(x.s._id)}) — ${x.hasClass ? 'has class' : 'NO class'}, ${x.courses} course(s), ${x.answers} answer(s), last active ${x.lastActive ? new Date(x.lastActive).toISOString().slice(0, 10) : 'never'}`;
        console.log(`Student group ${group.key}`);
        console.log(`  keep   ${describe(keep)}`);
        extras.forEach(x => console.log(`  merge  ${describe(x)}`));
        removed += extras.length;
        if (APPLY) {
            for (const x of extras) await moveStudentData(x.s, keep.s);
        }
    }
    console.log(`\nDuplicate student accounts ${APPLY ? 'merged' : 'to merge'}: ${removed}\n`);
}

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
    await mergeDuplicateStudents();
    const conflicts = await reportDuplicateEmails();
    await normalizeEmails(conflicts);

    await mongoose.disconnect();
}

run().catch(err => {
    console.error(err);
    process.exit(1);
});
