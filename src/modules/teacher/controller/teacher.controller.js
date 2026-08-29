const userModel = require('../../../../DB/models/user.model')
const classModel = require('../../../../DB/models/class.model')
const assignmentModel = require('../../../../DB/models/assignment.model')
const answerModel = require('../../../../DB/models/answer.model')
const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require("cloudinary").v2;
cloudinaryConfig()
const bcrypt = require('bcryptjs');
const { getSchoolHierarchy } = require('../../../services/schoolContext');

const buildTeacherQuery = (associatedIds, assignedTeacherIds, additionalFilter = {}) => {
    const orConditions = [];
    if (associatedIds && associatedIds.length > 0) {
        orConditions.push({ createdBy: { $in: associatedIds } });
    }
    if (assignedTeacherIds && assignedTeacherIds.length > 0) {
        orConditions.push({ _id: { $in: assignedTeacherIds } });
    }
    orConditions.push({ classList: { $exists: true, $ne: [] } });
    orConditions.push({ createdBy: { $exists: false } });
    orConditions.push({ createdBy: null });

    return {
        role: "Teacher",
        $or: orConditions,
        ...additionalFilter
    };
};

const getTeachers = async (req, res) => {
    try {
        const pageNumber = Math.max(1, parseInt(req.params.pageNumber) || 1);
        const skippedNumber = (pageNumber - 1) * 20;
        const { schoolId, associatedIds, assignedTeacherIds } = await getSchoolHierarchy(req.userData);
        const teacherQuery = buildTeacherQuery(associatedIds, assignedTeacherIds);

        const allTeachers = await userModel.find(teacherQuery)
            .select('userName email subject classList')
            .populate([
                { path: 'classList', select: 'class' },
                { path: 'subject', select: 'schoolSubjectName' }
            ])
            .skip(skippedNumber)
            .limit(20);

        const countTeacher = await userModel.countDocuments(teacherQuery);
        res.json({
            message: "success",
            allTeachers: allTeachers || [],
            numberOfTeacher: countTeacher || 0,
            totalPage: Math.max(1, Math.ceil(countTeacher / 20))
        });
    } catch (error) {
        console.error('getTeachers error:', error);
        res.status(502).json({ message: error.message });
    }
};

const addTeacher = async (req, res) => {
    try {
        const { userName, password } = req.body;
        const { schoolId, associatedIds, assignedTeacherIds } = await getSchoolHierarchy(req.userData);
        
        const existingTeacher = await userModel.findOne({
            userName,
            role: 'Teacher',
            createdBy: { $in: associatedIds }
        });

        if (existingTeacher) {
            return res.json({ message: "This teacher name is already registered" });
        }

        const pageNumber = Math.max(1, parseInt(req.params.pageNumber) || 1);
        const skippedNumber = (pageNumber - 1) * 20;

        try {
            const hashPassword = await bcrypt.hash(password, parseInt(process.env.SALTROUNDS) || 10);
            req.body.password = hashPassword;
        } catch (bcryptError) {
            return res.status(500).json({ message: 'Error hashing password' });
        }

        req.body.verify = true;
        req.body.role = 'Teacher';
        req.body.createdBy = schoolId;

        const newTeacher = new userModel(req.body);
        await newTeacher.save();

        const teacherQuery = buildTeacherQuery(associatedIds, assignedTeacherIds);
        const countTeacher = await userModel.countDocuments(teacherQuery);
        const allTeachers = await userModel.find(teacherQuery)
            .select('userName email subject classList')
            .populate([
                { path: 'classList', select: 'class' },
                { path: 'subject', select: 'schoolSubjectName' }
            ])
            .skip(skippedNumber)
            .limit(20);

        res.json({
            message: "success",
            allTeachers: allTeachers || [],
            numberOfTeacher: countTeacher || 0,
            totalPage: Math.max(1, Math.ceil(countTeacher / 20))
        });
    } catch (error) {
        console.error('addTeacher error:', error);
        res.status(502).json({ message: error.message });
    }
};

const updateTeacher = async (req, res) => {
    try {
        const { TeacherID, pageNumber } = req.params;
        const page = Math.max(1, parseInt(pageNumber) || 1);

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

        const updateTeacher = await userModel.findByIdAndUpdate(TeacherID, req.body);
        if (updateTeacher) {
            const skippedNumber = (page - 1) * 20;
            const { schoolId, associatedIds, assignedTeacherIds } = await getSchoolHierarchy(req.userData);
            const teacherQuery = buildTeacherQuery(associatedIds, assignedTeacherIds);

            const countTeacher = await userModel.countDocuments(teacherQuery);
            const allTeachers = await userModel.find(teacherQuery)
                .select('userName email subject classList')
                .populate([
                    { path: 'classList', select: 'class' },
                    { path: 'subject', select: 'schoolSubjectName' }
                ])
                .skip(skippedNumber)
                .limit(20);

            res.json({
                message: "success",
                allTeachers: allTeachers || [],
                numberOfTeacher: countTeacher || 0,
                totalPage: Math.max(1, Math.ceil(countTeacher / 20))
            });
        } else {
            res.json({ message: "This teacher is not found" });
        }
    } catch (error) {
        console.error('updateTeacher error:', error);
        res.status(502).json({ message: error.message });
    }
};

const deleteTeacher = async (req, res) => {
    try {
        const { TeacherID, pageNumber } = req.params;
        const page = Math.max(1, parseInt(pageNumber) || 1);
        const findTeacher = await userModel.findById(TeacherID);
        if (findTeacher) {
            const deleteTeacher = await userModel.findByIdAndDelete(TeacherID);
            if (deleteTeacher) {
                // Clean up classes where this teacher was added
                await classModel.updateMany(
                    { teachers: deleteTeacher._id },
                    { $pull: { teachers: deleteTeacher._id } }
                );

                const findAssignment = await assignmentModel.find({ createdBy: deleteTeacher._id });
                for (let index = 0; index < findAssignment.length; index++) {
                    const element = findAssignment[index];
                    const findAnswer = await answerModel.find({ assignment: element._id });
                    for (let index = 0; index < findAnswer.length; index++) {
                        const subElement = findAnswer[index];
                        for (let index = 0; index < subElement.questions.length; index++) {
                            const subElement2 = subElement.questions[index];
                            if (subElement2.stepsPicID) {
                                try {
                                    await cloudinary.uploader.destroy(subElement2.stepsPicID);
                                } catch (e) {}
                            }
                        }
                        await answerModel.findByIdAndDelete(subElement._id);
                    }
                }
                await assignmentModel.deleteMany({ createdBy: deleteTeacher._id });

                const skippedNumber = (page - 1) * 20;
                const { schoolId, associatedIds, assignedTeacherIds } = await getSchoolHierarchy(req.userData);
                const teacherQuery = buildTeacherQuery(associatedIds, assignedTeacherIds);

                const countTeacher = await userModel.countDocuments(teacherQuery);
                const allTeachers = await userModel.find(teacherQuery)
                    .select('userName email subject classList')
                    .populate([
                        { path: 'classList', select: 'class' },
                        { path: 'subject', select: 'schoolSubjectName' }
                    ])
                    .skip(skippedNumber)
                    .limit(20);

                res.json({
                    message: "success",
                    allTeachers: allTeachers || [],
                    numberOfTeacher: countTeacher || 0,
                    totalPage: Math.max(1, Math.ceil(countTeacher / 20))
                });
            } else {
                res.json({ message: "an error is happend" });
            }
        } else {
            res.json({ message: "This teacher is not found" });
        }
    } catch (error) {
        console.error('deleteTeacher error:', error);
        res.status(502).json({ message: error.message });
    }
};

const addTeacherToClass = async (req, res) => {
    try {
        const { classID, teacherID } = req.params;
        const findTeacher = await userModel.findById(teacherID);
        if (findTeacher) {
            const findClass = await classModel.findById(classID);
            if (findClass) {
                const isFound = (findClass.teachers || []).some(e => e.toString() === teacherID.toString());
                if (isFound) {
                    res.json({ message: "This teacher is already added to this class" });
                } else {
                    if (!findClass.teachers) findClass.teachers = [];
                    findClass.teachers.push(teacherID);
                    await findClass.save();

                    if (!findTeacher.classList) findTeacher.classList = [];
                    if (!findTeacher.classList.some(c => c.toString() === classID.toString())) {
                        findTeacher.classList.push(classID);
                        await findTeacher.save();
                    }

                    const { schoolId } = await getSchoolHierarchy(req.userData);
                    const allClasses = await classModel.find({ school: schoolId }).populate({ path: 'teachers', select: 'userName' });
                    res.json({ message: "success", allClasses });
                }
            } else {
                res.json({ message: "This class is not found" });
            }
        } else {
            res.json({ message: "This teacher is not found" });
        }
    } catch (error) {
        console.error('addTeacherToClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const removeTeacherFromClass = async (req, res) => {
    try {
        const { classID, teacherID } = req.params;
        const findTeacher = await userModel.findById(teacherID);
        if (findTeacher) {
            const findClass = await classModel.findById(classID);
            if (findClass) {
                const { schoolId } = await getSchoolHierarchy(req.userData);
                findClass.teachers = (findClass.teachers || []).filter(e => e.toString() !== teacherID.toString());
                await findClass.save();

                findTeacher.classList = (findTeacher.classList || []).filter(e => e.toString() !== classID.toString());
                await findTeacher.save();

                const newClass = await classModel.findById(classID).populate({ path: 'teachers', select: 'userName' });
                const allClasses = await classModel.find({ school: schoolId }).populate({ path: 'teachers', select: 'userName' });
                res.json({ message: 'success', newClass, allClasses });
            } else {
                res.json({ message: "This class is not found" });
            }
        } else {
            res.json({ message: "This teacher is not found" });
        }
    } catch (error) {
        console.error('removeTeacherFromClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const search = async (req, res) => {
    try {
        const { searchKey } = req.params;
        const { schoolId, associatedIds, assignedTeacherIds } = await getSchoolHierarchy(req.userData);
        
        const teacherQuery = buildTeacherQuery(associatedIds, assignedTeacherIds, {
            userName: { $regex: searchKey, $options: 'i' }
        });

        const findTeacher = await userModel.find(teacherQuery)
            .select('userName email subject classList')
            .populate([
                { path: 'classList', select: 'class' },
                { path: 'subject', select: 'schoolSubjectName' }
            ]);

        if (findTeacher && findTeacher.length !== 0) {
            res.json({ message: 'success', allTeachers: findTeacher });
        } else {
            res.json({ message: 'There are no teacher available with this name', allTeachers: [] });
        }
    } catch (error) {
        console.error('search teacher error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getTeacherToClass = async (req, res) => {
    try {
        const { schoolId, associatedIds, assignedTeacherIds } = await getSchoolHierarchy(req.userData);
        const teacherQuery = buildTeacherQuery(associatedIds, assignedTeacherIds);

        const allTeachers = await userModel.find(teacherQuery).select('userName');
        if (allTeachers && allTeachers.length !== 0) {
            res.json({ message: 'success', allTeachers });
        } else {
            res.json({ message: "There is no any teacher yet.", allTeachers: [] });
        }
    } catch (error) {
        console.error('getTeacherToClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getTeacherClass = async (req, res) => {
    try {
        const teacherID = req.userData._id;
        let findTeacher = await userModel.findById(teacherID).select('createdBy').populate({ path: 'createdBy', select: 'userName' });
        if (findTeacher) {
            const classes = await classModel.find({ teachers: teacherID }).select('class');
            const teacherClasessObj = {
                _id: findTeacher._id,
                createdBy: findTeacher.createdBy,
                classList: classes
            };
            res.json({ message: 'success', teacherClasess: teacherClasessObj });
        } else {
            res.json({ message: 'There are no teacher available with this id' });
        }
    } catch (error) {
        console.error('getTeacherClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getAllAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id;
        const getAssignment = await assignmentModel.find({ createdBy: teacherID }).select('-createdBy').populate([{ path: 'questions', select: '-chapter' }, { path: 'classes', select: 'class' }, { path: 'students.solveBy', select: 'userName' }]).sort({ _id: -1 });
        if (getAssignment.length !== 0) {
            res.json({ message: 'success', allAssignment: getAssignment });
        } else {
            res.json({ message: 'There are no assignment available now' });
        }
    } catch (error) {
        console.error('getAllAssignment error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getStudentHistory = async (req, res) => {
    try {
        const { studentID } = req.params;
        const teacherID = req.userData._id;

        let student = await userModel.findById(studentID).select('userName email');
        if (!student) {
            const answerDoc = await answerModel.findOne({ solveBy: studentID }).populate('solveBy', 'userName email');
            if (answerDoc && answerDoc.solveBy) {
                student = answerDoc.solveBy;
            } else {
                student = { _id: studentID, userName: 'Student', email: '' };
            }
        }

        const studentAnswers = await answerModel.find({ solveBy: studentID })
            .populate({
                path: 'assignment',
                select: 'title totalPoints createdAt startDate endDate createdBy'
            })
            .sort({ _id: -1 });

        const validAnswers = studentAnswers.filter(answer => {
            if (!answer.assignment) return false;
            if (!answer.assignment.createdBy) return true;
            return String(answer.assignment.createdBy) === String(teacherID);
        });

        if (validAnswers.length === 0) {
            return res.json({
                message: 'success',
                student: {
                    _id: student._id,
                    userName: student.userName || 'Student',
                    email: student.email || ''
                },
                assignments: [],
                statistics: {
                    totalAssignments: 0,
                    averageScore: 0,
                    highestScore: 0,
                    lowestScore: 0
                }
            });
        }

        const scores = validAnswers.map(answer => {
            const totalPossible = answer.assignment?.totalPoints || 1;
            const percentage = totalPossible > 0 ? (answer.total / totalPossible) * 100 : 0;
            return isNaN(percentage) ? 0 : percentage;
        });

        const totalAssignments = validAnswers.length;
        const averageScore = scores.reduce((acc, score) => acc + score, 0) / totalAssignments;
        const highestScore = Math.max(...scores);
        const lowestScore = Math.min(...scores);

        const assignments = validAnswers.map(answer => {
            const totalPossible = answer.assignment?.totalPoints || 1;
            const percentage = totalPossible > 0 ? (answer.total / totalPossible) * 100 : 0;
            const safePercentage = isNaN(percentage) ? 0 : percentage;
            let grade = 'F';
            if (safePercentage >= 90) grade = 'A';
            else if (safePercentage >= 80) grade = 'B';
            else if (safePercentage >= 70) grade = 'C';
            else if (safePercentage >= 60) grade = 'D';

            return {
                _id: answer._id,
                assignmentID: answer.assignment._id,
                assignmentTitle: answer.assignment.title || 'Assignment',
                score: answer.total || 0,
                totalPossible: totalPossible,
                percentage: Math.round(safePercentage * 100) / 100,
                grade: grade,
                completedAt: answer.completedAt || answer.createdAt || answer.updatedAt,
                totalQuestions: answer.questionsNumber || 0,
                answeredQuestions: answer.questionsNumber || 0,
                timeSpent: answer.time || '0:00'
            };
        });

        res.json({
            message: 'success',
            student: {
                _id: student._id,
                userName: student.userName || 'Student',
                email: student.email || ''
            },
            assignments: assignments,
            statistics: {
                totalAssignments: totalAssignments,
                averageScore: isNaN(averageScore) ? 0 : Math.round(averageScore * 100) / 100,
                highestScore: isNaN(highestScore) ? 0 : Math.round(highestScore * 100) / 100,
                lowestScore: isNaN(lowestScore) ? 0 : Math.round(lowestScore * 100) / 100
            }
        });
    } catch (error) {
        console.error('getStudentHistory error:', error);
        res.status(502).json({ message: error.message });
    }
};

module.exports = { 
    addTeacher, 
    getTeachers, 
    updateTeacher, 
    deleteTeacher, 
    addTeacherToClass, 
    search, 
    getTeacherToClass, 
    removeTeacherFromClass, 
    getTeacherClass, 
    getAllAssignment, 
    getStudentHistory 
};