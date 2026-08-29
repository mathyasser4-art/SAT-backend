const classModel = require('../../../../DB/models/class.model');
const userModel = require('../../../../DB/models/user.model');
const { getSchoolHierarchy } = require('../../../services/schoolContext');

const addClass = async (req, res) => {
    try {
        const { schoolId } = await getSchoolHierarchy(req.userData);
        req.body.school = schoolId;
        const addClass = new classModel(req.body);
        await addClass.save();
        const allClasses = await classModel.find({ school: schoolId }).populate({ path: 'teachers', select: 'userName' });
        res.json({ message: "success", allClasses: allClasses || [] });
    } catch (error) {
        console.error('addClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getAllClass = async (req, res) => {
    try {
        const { schoolId } = await getSchoolHierarchy(req.userData);
        const allClasses = await classModel.find({ school: schoolId }).populate({ path: 'teachers', select: 'userName' });
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
        const { schoolId } = await getSchoolHierarchy(req.userData);
        const findClass = await classModel.findById(classID);
        if (findClass) {
            const updateClass = await classModel.findByIdAndUpdate(classID, req.body);
            if (updateClass) {
                const allClasses = await classModel.find({ school: schoolId }).populate({ path: 'teachers', select: 'userName' });
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
        const { schoolId } = await getSchoolHierarchy(req.userData);
        const findClass = await classModel.findById(classID);
        if (findClass) {
            // Unassign students from this class
            await userModel.updateMany({ class: findClass._id }, { $unset: { class: 1 } });
            // Unassign teachers from this class
            await userModel.updateMany({ classList: findClass._id }, { $pull: { classList: findClass._id } });

            const removeClass = await classModel.findByIdAndDelete(classID);
            if (removeClass) {
                const allClasses = await classModel.find({ school: schoolId }).populate({ path: 'teachers', select: 'userName' });
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
        const { schoolId, associatedIds } = await getSchoolHierarchy(req.userData);
        const allStudent = await userModel.find({ 
            role: "Student",
            class: classID,
            $or: [
                { createdBy: { $in: associatedIds } },
                { class: classID }
            ]
        }).select('userName email');

        if (allStudent && allStudent.length !== 0) {
            res.json({ message: "success", allStudent });
        } else {
            res.json({ message: "There are no any student yet.", allStudent: [] });
        }
    } catch (error) {
        console.error('getStudent in class error:', error);
        res.status(502).json({ message: error.message });
    }
};

module.exports = { addClass, getAllClass, updateClass, removeClass, getStudent };