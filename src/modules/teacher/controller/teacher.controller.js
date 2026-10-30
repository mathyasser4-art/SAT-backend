const userModel = require('../../../../DB/models/user.model')
const classModel = require('../../../../DB/models/class.model')
const assignmentModel = require('../../../../DB/models/assignment.model')
const answerModel = require('../../../../DB/models/answer.model')
const { idOf, gradeAttempts, countedAttemptsBy } = require('../../../services/grading')
const courseModel = require('../../../../DB/models/course.model')
const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require("cloudinary").v2;
cloudinaryConfig()
const bcrypt = require('bcryptjs');
const { getSchoolHierarchy } = require('../../../services/schoolContext');
const { checkEmailAvailable } = require('../../../services/accountGuard');

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

        const emailError = await checkEmailAvailable(req.body);
        if (emailError) return res.json({ message: emailError });

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

        const emailError = await checkEmailAvailable(req.body, TeacherID);
        if (emailError) return res.json({ message: emailError });

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
        let findTeacher = await userModel.findById(teacherID).select('createdBy classList').populate({ path: 'createdBy', select: 'userName' });
        if (findTeacher) {
            const classConditions = [
                { teachers: teacherID },
                { createdBy: teacherID }
            ];
            if (Array.isArray(findTeacher.classList) && findTeacher.classList.length > 0) {
                classConditions.push({ _id: { $in: findTeacher.classList } });
            }
            const classes = await classModel.find({ $or: classConditions }).select('class teachers school createdBy');
            const teacherClasessObj = {
                _id: findTeacher._id,
                createdBy: findTeacher.createdBy,
                classList: classes
            };
            res.json({ message: 'success', teacherClasess: teacherClasessObj, classList: classes });
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
                select: 'title questions countingRule createdAt startDate endDate createdBy'
            })
            .sort({ _id: -1 })
            .lean();

        const isPrivileged = ['Admin', 'School', 'Supervisor', 'IT'].includes(req.userData?.role);
        
        let teacherCourseAssignmentIds = new Set();
        if (!isPrivileged) {
            try {
                const teacherCourses = await courseModel.find({ teacherID: teacherID }).select('sessions assignment');
                teacherCourses.forEach(c => {
                    if (c.assignment && Array.isArray(c.assignment)) {
                        c.assignment.forEach(aId => teacherCourseAssignmentIds.add(String(aId)));
                    }
                    if (c.sessions && Array.isArray(c.sessions)) {
                        c.sessions.forEach(sess => {
                            (sess.onlineHw || []).forEach(hw => teacherCourseAssignmentIds.add(String(hw._id || hw)));
                            (sess.onlineTest || []).forEach(t => teacherCourseAssignmentIds.add(String(t._id || t)));
                        });
                    }
                });
            } catch (e) {
                console.warn('Error querying teacher courses for history:', e.message);
            }
        }

        const validAnswers = studentAnswers.filter(answer => {
            if (!answer.assignment) return false;
            if (isPrivileged) return true;
            if (!answer.assignment.createdBy) return true;
            if (String(answer.assignment.createdBy) === String(teacherID)) return true;
            if (teacherCourseAssignmentIds.has(String(answer.assignment._id))) return true;
            return false;
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

        // One row per assignment: the attempt that counts, marked like every other report
        const assignmentsById = new Map(validAnswers.map(a => [String(a.assignment._id), a.assignment]));
        const grades = await gradeAttempts(validAnswers, { assignmentsById });
        const byAssignment = countedAttemptsBy(validAnswers, grades, a => idOf(a.assignment));

        const assignments = [...byAssignment.values()].map(({ counted, attempts }) => {
            const { answer, grade } = counted;
            const percentage = grade.percentage;
            let letter = 'F';
            if (percentage >= 90) letter = 'A';
            else if (percentage >= 80) letter = 'B';
            else if (percentage >= 70) letter = 'C';
            else if (percentage >= 60) letter = 'D';

            return {
                _id: answer._id,
                assignmentID: answer.assignment._id,
                assignmentTitle: answer.assignment.title || 'Assignment',
                status: answer.completedAt ? 'Completed' : 'In Progress',
                attemptNumber: answer.attemptNumber || 1,
                attemptsCount: attempts.length,
                score: grade.score,
                totalPossible: grade.totalPoints,
                percentage,
                grade: letter,
                completedAt: answer.completedAt || answer.createdAt || answer.updatedAt,
                totalQuestions: grade.questions.length,
                answeredQuestions: grade.answeredCount,
                correctQuestions: grade.correctCount,
                timeSpent: answer.time || '0:00'
            };
        }).sort((a, b) => new Date(b.completedAt || 0) - new Date(a.completedAt || 0));

        // Statistics over submitted work only
        const scores = assignments.filter(a => a.status === 'Completed').map(a => a.percentage);
        const totalAssignments = scores.length;
        const averageScore = totalAssignments ? scores.reduce((acc, v) => acc + v, 0) / totalAssignments : 0;
        const highestScore = totalAssignments ? Math.max(...scores) : 0;
        const lowestScore = totalAssignments ? Math.min(...scores) : 0;

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