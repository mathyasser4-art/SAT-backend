const classModel = require('../../../../DB/models/class.model');
const userModel = require('../../../../DB/models/user.model');
const { getSchoolHierarchy } = require('../../../services/schoolContext');

const buildClassQuery = (associatedIds) => {
    return {
        $or: [
            { school: { $in: associatedIds } },
            { createdBy: { $in: associatedIds } },
            { school: { $exists: false } },
            { school: null }
        ]
    };
};

const addClass = async (req, res) => {
    try {
        const { schoolId, associatedIds } = await getSchoolHierarchy(req.userData);
        req.body.school = schoolId;
        req.body.createdBy = req.userData._id;
        const addClass = new classModel(req.body);
        await addClass.save();
        const allClasses = await classModel.find(buildClassQuery(associatedIds)).populate({ path: 'teachers', select: 'userName email' });
        res.json({ message: "success", allClasses: allClasses || [] });
    } catch (error) {
        console.error('addClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getAllClass = async (req, res) => {
    try {
        const { associatedIds } = await getSchoolHierarchy(req.userData);
        const allClasses = await classModel.find(buildClassQuery(associatedIds)).populate({ path: 'teachers', select: 'userName email' });
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
                const allClasses = await classModel.find(buildClassQuery(associatedIds)).populate({ path: 'teachers', select: 'userName email' });
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
        const findClass = await classModel.findById(classID);
        if (findClass) {
            const removeClass = await classModel.findByIdAndDelete(classID);
            if (removeClass) {
                const allClasses = await classModel.find(buildClassQuery(associatedIds)).populate({ path: 'teachers', select: 'userName email' });
                res.json({ message: "success", allClasses: allClasses || [] });
            } else {
                res.json({ message: "an error is happend" });
            }
        } else {
            res.json({ message: "There is no class with this id" });
        }
    } catch (error) {
        console.error('removeClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getStudent = async (req, res) => {
    try {
        const { classID } = req.params;
        const findStudent = await userModel.find({
            role: "Student",
            $or: [
                { classList: classID },
                { class: classID }
            ]
        })
        .select('userName email class classList')
        .populate({ path: 'class', select: 'class' });

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