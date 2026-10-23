const mongoose = require('mongoose');
const classModel = require('../../../../DB/models/class.model');
const userModel = require('../../../../DB/models/user.model');
const { getSchoolHierarchy } = require('../../../services/schoolContext');
const { ensureStudentParents } = require('../../../services/parentHelper');

const buildClassQuery = (associatedIds, userData) => {
    // If the user is a Teacher, strictly restrict to classes assigned to or created by THIS teacher
    if (userData && userData.role === 'Teacher') {
        const teacherId = userData._id;
        const teacherConditions = [
            { teachers: teacherId },
            { createdBy: teacherId }
        ];
        if (Array.isArray(userData.classList) && userData.classList.length > 0) {
            teacherConditions.push({ _id: { $in: userData.classList } });
        }
        return { $or: teacherConditions };
    }

    // For School, IT, Admin, Supervisor: can see all classes belonging to the school hierarchy
    const orConditions = [
        { school: { $in: associatedIds } },
        { createdBy: { $in: associatedIds } },
        { school: { $exists: false } },
        { school: null }
    ];
    return { $or: orConditions };
};

const addClass = async (req, res) => {
    try {
        const { schoolId, associatedIds } = await getSchoolHierarchy(req.userData);
        req.body.school = schoolId;
        req.body.createdBy = req.userData._id;
        if (req.userData.role === 'Teacher') {
            if (!req.body.teachers) req.body.teachers = [];
            if (!req.body.teachers.includes(req.userData._id)) {
                req.body.teachers.push(req.userData._id);
            }
        }
        const addClass = new classModel(req.body);
        await addClass.save();

        if (req.userData.role === 'Teacher') {
            try {
                await userModel.findByIdAndUpdate(req.userData._id, {
                    $addToSet: { classList: addClass._id }
                });
            } catch (te) {}
        }

        const allClasses = await classModel.find(buildClassQuery(associatedIds, req.userData)).populate({ path: 'teachers', select: 'userName email' });
        res.json({ message: "success", allClasses: allClasses || [] });
    } catch (error) {
        console.error('addClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getAllClass = async (req, res) => {
    try {
        const { associatedIds } = await getSchoolHierarchy(req.userData);
        const allClasses = await classModel.find(buildClassQuery(associatedIds, req.userData)).populate({ path: 'teachers', select: 'userName email' });
        if (allClasses && allClasses.length !== 0) {
            res.json({ message: "success", allClasses });
        } else {
            res.json({ message: "There are no any classes now", allClasses: [] });
        }
    } catch (error) {
        console.error('getAllClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const updateClass = async (req, res) => {
    try {
        const { classID } = req.params;
        const { associatedIds } = await getSchoolHierarchy(req.userData);
        const findClass = await classModel.findById(classID);
        if (findClass) {
            const updateClass = await classModel.findByIdAndUpdate(classID, req.body, { new: true });
            if (updateClass) {
                const allClasses = await classModel.find(buildClassQuery(associatedIds, req.userData)).populate({ path: 'teachers', select: 'userName email' });
                res.json({ message: "success", allClasses: allClasses || [] });
            } else {
                res.json({ message: "an error is happend" });
            }
        } else {
            res.json({ message: "There is no class with this id" });
        }
    } catch (error) {
        console.error('updateClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const removeClass = async (req, res) => {
    try {
        const { classID } = req.params;
        const { associatedIds } = await getSchoolHierarchy(req.userData);
        const isObjectId = mongoose.Types.ObjectId.isValid(classID);
        const findQuery = isObjectId ? { _id: classID } : { class: classID };
        const findClass = await classModel.findOne(findQuery);
        if (findClass) {
            await classModel.findByIdAndDelete(findClass._id);
            await userModel.updateMany(
                { classList: findClass._id },
                { $pull: { classList: findClass._id } }
            );
            await userModel.updateMany(
                { class: findClass._id },
                { $set: { class: null }, $pull: { classList: findClass._id } }
            );
        }
        const allClasses = await classModel.find(buildClassQuery(associatedIds, req.userData)).populate({ path: 'teachers', select: 'userName email' });
        res.json({ message: "success", allClasses: allClasses || [] });
    } catch (error) {
        console.error('removeClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getStudent = async (req, res) => {
    try {
        const { classID } = req.params;
        const findStudent = await userModel.find({
            role: { $in: ["Student", "User"] },
            $or: [
                { classList: classID },
                { class: classID }
            ]
        })
        .select('userName email class classList parent parentPhone parentName')
        .populate({ path: 'class', select: 'class' })
        .populate({ path: 'parent', select: 'userName email parentPhone' });

        // Auto-resolve / auto-provision parent accounts for any student missing a parent
        if (findStudent && findStudent.length > 0) {
            await ensureStudentParents(findStudent, req.userData?._id);
        }

        if (findStudent && findStudent.length !== 0) {
            res.json({ message: "success", findStudent, allStudent: findStudent });
        } else {
            res.json({ message: "There is no student yet", findStudent: [], allStudent: [] });
        }
    } catch (error) {
        console.error('getStudent error:', error);
        res.status(502).json({ message: error.message });
    }
};

module.exports = {
    addClass,
    getAllClass,
    updateClass,
    removeClass,
    getStudent
};