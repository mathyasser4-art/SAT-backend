const userModel = require('../../../../DB/models/user.model');
const assignmentModel = require('../../../../DB/models/assignment.model');
const bcrypt = require('bcryptjs');
const { getSchoolHierarchy } = require('../../../services/schoolContext');

const getSupervisor = async (req, res) => {
    try {
        const { schoolId, associatedIds } = await getSchoolHierarchy(req.userData);
        const supervisorQuery = { role: "Supervisor", createdBy: { $in: associatedIds } };
        const allSupervisor = await userModel.find(supervisorQuery).select('userName email teacherList').populate({ path: 'teacherList', select: 'userName' });
        const countSupervisor = await userModel.countDocuments(supervisorQuery);
        res.json({
            message: "success",
            allSupervisor: allSupervisor || [],
            numberOfSupervisor: countSupervisor || 0
        });
    } catch (error) {
        console.error('getSupervisor error:', error);
        res.status(502).json({ message: error.message });
    }
};

const addSupervisor = async (req, res) => {
    try {
        const { userName, password } = req.body;
        const { schoolId, associatedIds } = await getSchoolHierarchy(req.userData);
        const findSupervisor = await userModel.findOne({ userName, role: "Supervisor", createdBy: { $in: associatedIds } });

        if (findSupervisor) {
            res.json({ message: "This supervisor name is already registered" });
        } else {
            try {
                const hashPassword = await bcrypt.hash(password, parseInt(process.env.SALTROUNDS) || 10);
                req.body.password = hashPassword;
            } catch (bcryptError) {
                return res.status(500).json({ message: 'Error hashing password' });
            }
            req.body.verify = true;
            req.body.role = 'Supervisor';
            req.body.createdBy = schoolId;

            const addSupervisor = new userModel(req.body);
            await addSupervisor.save();

            const supervisorQuery = { role: "Supervisor", createdBy: { $in: associatedIds } };
            const allSupervisor = await userModel.find(supervisorQuery).select('userName email teacherList').populate({ path: 'teacherList', select: 'userName' });
            const countSupervisor = await userModel.countDocuments(supervisorQuery);
            res.json({ message: "success", allSupervisor: allSupervisor || [], numberOfSupervisor: countSupervisor || 0 });
        }
    } catch (error) {
        console.error('addSupervisor error:', error);
        res.status(502).json({ message: error.message });
    }
};

const updateSupervisor = async (req, res) => {
    try {
        const { supervisorID } = req.params;
        if (req.body.password !== undefined && req.body.password !== '') {
            try {
                const hashPassword = await bcrypt.hash(req.body.password, parseInt(process.env.SALTROUNDS) || 10);
                req.body.password = hashPassword;
            } catch (bcryptError) {
                return res.status(500).json({ message: 'Error hashing password' });
            }
        } else {
            delete req.body.password;
        }

        const updateSupervisor = await userModel.findByIdAndUpdate(supervisorID, req.body);
        if (updateSupervisor) {
            const { schoolId, associatedIds } = await getSchoolHierarchy(req.userData);
            const supervisorQuery = { role: "Supervisor", createdBy: { $in: associatedIds } };
            const allSupervisor = await userModel.find(supervisorQuery).select('userName email teacherList').populate({ path: 'teacherList', select: 'userName' });
            const countSupervisor = await userModel.countDocuments(supervisorQuery);
            res.json({ message: "success", allSupervisor: allSupervisor || [], numberOfSupervisor: countSupervisor || 0 });
        } else {
            res.json({ message: "This supervisor is not found" });
        }
    } catch (error) {
        console.error('updateSupervisor error:', error);
        res.status(502).json({ message: error.message });
    }
};

const deleteSupervisor = async (req, res) => {
    try {
        const { supervisorID } = req.params;
        const findSupervisor = await userModel.findById(supervisorID);
        if (findSupervisor) {
            const deleteSupervisor = await userModel.findByIdAndDelete(supervisorID);
            if (deleteSupervisor) {
                const { schoolId, associatedIds } = await getSchoolHierarchy(req.userData);
                const supervisorQuery = { role: "Supervisor", createdBy: { $in: associatedIds } };
                const allSupervisor = await userModel.find(supervisorQuery).select('userName email teacherList').populate({ path: 'teacherList', select: 'userName' });
                const countSupervisor = await userModel.countDocuments(supervisorQuery);
                res.json({ message: "success", allSupervisor: allSupervisor || [], numberOfSupervisor: countSupervisor || 0 });
            } else {
                res.json({ message: "an error is happend" });
            }
        } else {
            res.json({ message: "This supervisor is not found" });
        }
    } catch (error) {
        console.error('deleteSupervisor error:', error);
        res.status(502).json({ message: error.message });
    }
};

const supervisorDeatails = async (req, res) => {
    try {
        const supervisorID = req.userData._id;
        const supervisor = await userModel.findById(supervisorID).select('userName email teacherList').populate({ path: 'teacherList', select: 'userName' });
        if (supervisor) {
            res.json({ message: "success", supervisor });
        } else {
            res.json({ message: "There is no any supervisor yet." });
        }
    } catch (error) {
        console.error('supervisorDeatails error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getAllTeachers = async (req, res) => {
    try {
        const { schoolId, associatedIds, assignedTeacherIds } = await getSchoolHierarchy(req.userData);
        const orConditions = [];
        if (associatedIds && associatedIds.length > 0) orConditions.push({ createdBy: { $in: associatedIds } });
        if (assignedTeacherIds && assignedTeacherIds.length > 0) orConditions.push({ _id: { $in: assignedTeacherIds } });

        const teacherQuery = orConditions.length > 0 ? { role: "Teacher", $or: orConditions } : { role: "Teacher" };
        const allTeachers = await userModel.find(teacherQuery).select('userName');
        if (allTeachers && allTeachers.length !== 0) {
            res.json({ message: "success", allTeachers });
        } else {
            res.json({ message: "There is no any teacher yet.", allTeachers: [] });
        }
    } catch (error) {
        console.error('getAllTeachers error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getAssignment = async (req, res) => {
    try {
        const { teacherID } = req.params;
        const getAssignment = await assignmentModel.find({ createdBy: teacherID }).select('-questions').sort({ _id: -1 });
        if (getAssignment && getAssignment.length !== 0) {
            res.json({ message: 'success', allAssignment: getAssignment });
        } else {
            res.json({ message: 'There are no assignment available now', allAssignment: [] });
        }
    } catch (error) {
        console.error('getAssignment error:', error);
        res.status(502).json({ message: error.message });
    }
};

module.exports = { addSupervisor, getSupervisor, updateSupervisor, deleteSupervisor, getAllTeachers, supervisorDeatails, getAssignment };