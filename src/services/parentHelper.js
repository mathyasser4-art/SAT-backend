const userModel = require('../../DB/models/user.model');
const bcrypt = require('bcryptjs');
const { withLock, findAccountByEmail } = require('./accountGuard');

/**
 * Ensures every student in the list has an associated Parent account.
 * If a student is missing a parent reference:
 * 1. Checks if a parent account already links to this student via `children`
 * 2. Checks if a parent account exists matching the student's username/email
 * 3. If neither exists, automatically creates a dedicated Parent user account:
 *    - userName: `parent_${cleanStudentName}`
 *    - email: `${cleanStudentName}.parent@mrshahin.com`
 *    - password: hashed `${studentName}123`
 *    - role: 'Parent'
 *    - verify: true
 *    - children: [student._id]
 *    - parentPhone: student.parentPhone || student.phone || ''
 * 4. Links `student.parent = parentDoc._id` and persists it in MongoDB
 * 5. Populates `student.parent = { _id, userName, email, parentPhone }` in memory
 *
 * @param {Array} students - Array of Mongoose student documents or plain objects
 * @param {ObjectId|string} defaultCreatorId - Fallback user ID to set as createdBy
 * @returns {Promise<Array>} The enriched students array
 */
async function ensureStudentParents(students, defaultCreatorId = null) {
    if (!Array.isArray(students) || students.length === 0) return students;

    try {
        const missingParentStudents = students.filter(s => s && !s.parent);
        if (missingParentStudents.length === 0) return students;

        const missingIds = missingParentStudents.map(s => s._id).filter(Boolean);

        // 1. Check if parent user already exists with this student in their `children` array
        const existingParentsByChildren = await userModel.find({
            role: 'Parent',
            children: { $in: missingIds }
        }).select('_id userName email parentPhone children').lean();

        const parentByChildMap = new Map();
        existingParentsByChildren.forEach(p => {
            if (Array.isArray(p.children)) {
                p.children.forEach(cId => {
                    if (cId) {
                        parentByChildMap.set(cId.toString(), {
                            _id: p._id,
                            userName: p.userName,
                            email: p.email,
                            parentPhone: p.parentPhone
                        });
                    }
                });
            }
        });

        // 2. Iterate each student missing a parent
        for (const st of missingParentStudents) {
            if (!st || !st._id) continue;
            const sIdStr = st._id.toString();

            if (parentByChildMap.has(sIdStr)) {
                const pInfo = parentByChildMap.get(sIdStr);
                st.parent = pInfo;
                if (!st.parentPhone && pInfo.parentPhone) st.parentPhone = pInfo.parentPhone;
                userModel.findByIdAndUpdate(st._id, { parent: pInfo._id }).catch(() => {});
            } else {
                // Lock per student and re-check inside the lock: roster pages load
                // several lists in parallel, which used to create duplicate parents.
                const parentDoc = await withLock(`parent:${sIdStr}`, async () => {
                    const fresh = await userModel.findById(st._id).select('parent').lean();
                    if (fresh && fresh.parent) {
                        const linked = await userModel.findById(fresh.parent);
                        if (linked) return linked;
                    }
                    const byChild = await userModel.findOne({ role: 'Parent', children: st._id });
                    if (byChild) {
                        await userModel.findByIdAndUpdate(st._id, { parent: byChild._id });
                        return byChild;
                    }

                    const rawName = st.userName || 'student';
                    const cleanName = rawName.replace(/[^a-zA-Z0-9]/g, '_').toLowerCase();
                    let targetParentUserName = `parent_${cleanName}`;
                    let targetParentEmail = `${cleanName}.parent@mrshahin.com`;

                    let doc = await userModel.findOne({
                        role: 'Parent',
                        $or: [
                            { userName: targetParentUserName },
                            { email: targetParentEmail },
                            { email: `${cleanName}.parent@school.com` }
                        ]
                    });

                    if (doc) {
                        if (!Array.isArray(doc.children)) doc.children = [];
                        if (!doc.children.some(c => c && c.toString() === sIdStr)) {
                            doc.children.push(st._id);
                        }
                        if (!doc.parentPhone && (st.parentPhone || st.phone)) {
                            doc.parentPhone = st.parentPhone || st.phone;
                        }
                        await doc.save().catch(() => {});
                    } else {
                        // Never take over a non-parent account that shares the name/email
                        if (await findAccountByEmail(targetParentEmail) || await userModel.exists({ userName: targetParentUserName })) {
                            const suffix = sIdStr.slice(-4);
                            targetParentUserName = `${targetParentUserName}_${suffix}`;
                            targetParentEmail = `${cleanName}.parent${suffix}@mrshahin.com`;
                        }
                        const phoneNum = st.parentPhone || st.phone || '';
                        const rawPassword = rawName.replace(/\s+/g, '') + '123';
                        const hashedPassword = await bcrypt.hash(rawPassword, parseInt(process.env.SALTROUNDS) || 10);
                        doc = new userModel({
                            userName: targetParentUserName,
                            email: targetParentEmail,
                            password: hashedPassword,
                            role: 'Parent',
                            verify: true,
                            children: [st._id],
                            parentPhone: phoneNum,
                            createdBy: st.createdBy || defaultCreatorId
                        });
                        await doc.save();
                    }
                    await userModel.findByIdAndUpdate(st._id, { parent: doc._id });
                    return doc;
                }).catch((e) => {
                    console.warn('ensureStudentParents create error:', e.message);
                    return null;
                });

                if (parentDoc && parentDoc._id) {
                    st.parent = {
                        _id: parentDoc._id,
                        userName: parentDoc.userName,
                        email: parentDoc.email,
                        parentPhone: parentDoc.parentPhone || st.parentPhone || st.phone || ''
                    };
                    if (!st.parentPhone && parentDoc.parentPhone) st.parentPhone = parentDoc.parentPhone;
                }
            }
        }
    } catch (err) {
        console.warn('ensureStudentParents error:', err);
    }

    return students;
}

module.exports = { ensureStudentParents };
