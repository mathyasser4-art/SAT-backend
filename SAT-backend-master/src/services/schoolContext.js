const mongoose = require('mongoose');
const userModel = require('../../DB/models/user.model');
const classModel = require('../../DB/models/class.model');

/**
 * Resolves the root School ID, all associated IT/creator account IDs, and any teacher IDs assigned to school classes.
 * @param {Object} userData The authenticated user from req.userData
 * @returns {Promise<{ schoolId: Object, associatedIds: Array, assignedTeacherIds: Array }>}
 */
const getSchoolHierarchy = async (userData) => {
    if (!userData) return { schoolId: null, associatedIds: [], assignedTeacherIds: [] };

    let schoolId;
    if (userData.role === 'School') {
        schoolId = userData._id;
    } else if (userData.role === 'IT' || userData.role === 'Teacher' || userData.role === 'Supervisor') {
        schoolId = userData.createdBy?._id || userData.createdBy || userData._id;
    } else {
        schoolId = userData._id;
    }

    // Find all IT accounts belonging to this school (only if DB connected)
    let itIds = [];
    if (mongoose.connection.readyState === 1) {
        try {
            const itUsers = await userModel.find({ role: 'IT', createdBy: schoolId }).select('_id');
            itIds = itUsers.map(u => u._id);
        } catch (e) {
            // Safe fallback
        }
    }

    const currentUserIdStr = userData._id ? userData._id.toString() : '';
    const schoolIdStr = schoolId ? schoolId.toString() : '';
    
    const uniqueIds = Array.from(new Set([
        schoolIdStr,
        currentUserIdStr,
        ...itIds.map(id => id ? id.toString() : '')
    ])).filter(Boolean);

    const associatedIds = uniqueIds.map(id => {
        try {
            return mongoose.Types.ObjectId.isValid(id) ? new mongoose.Types.ObjectId(id) : id;
        } catch (e) {
            return id;
        }
    });

    // Find all teacher IDs attached to classes belonging to this school or with legacy structure
    let assignedTeacherIds = [];
    if (mongoose.connection.readyState === 1) {
        try {
            const schoolClasses = await classModel.find({
                $or: [
                    { school: { $in: associatedIds } },
                    { createdBy: { $in: associatedIds } },
                    { school: { $exists: false } },
                    { school: null }
                ]
            }).select('_id teachers');
            
            const rawTeacherIds = schoolClasses.flatMap(c => c.teachers || []);
            const classIds = schoolClasses.map(c => c._id);

            const teachersWithClasses = await userModel.find({
                role: 'Teacher',
                classList: { $in: classIds }
            }).select('_id');
            const teacherIdsFromList = teachersWithClasses.map(t => t._id);

            const allTeacherIdStrings = Array.from(new Set([
                ...rawTeacherIds.map(id => id ? id.toString() : ''),
                ...teacherIdsFromList.map(id => id ? id.toString() : '')
            ])).filter(Boolean);

            assignedTeacherIds = allTeacherIdStrings.map(id => {
                try {
                    return mongoose.Types.ObjectId.isValid(id) ? new mongoose.Types.ObjectId(id) : id;
                } catch (e) {
                    return id;
                }
            });
        } catch (e) {
            // Safe fallback
        }
    }

    return { schoolId, associatedIds, assignedTeacherIds };
};

module.exports = { getSchoolHierarchy };
