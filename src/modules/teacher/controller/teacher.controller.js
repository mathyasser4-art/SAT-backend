const userModel = require('../../../../DB/models/user.model')
const classModel = require('../../../../DB/models/class.model')
const assignmentModel = require('../../../../DB/models/assignment.model')
const answerModel = require('../../../../DB/models/answer.model')
const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require("cloudinary").v2;
cloudinaryConfig()
const bcrypt = require('bcryptjs');

const getTeachers = async (req, res) => {
    try {
        const { pageNumber } = req.params
        const skippedNumber = (pageNumber - 1) * 20
        const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
        const allTeachers = await userModel.find({ role: "Teacher", createdBy: schoolID }).select('userName email subject classList').populate([{ path: 'classList', select: 'class' }, { path: 'subject', select: 'schoolSubjectName' }]).skip(skippedNumber).limit(20)
        const countTeacher = await userModel.countDocuments({ role: "Teacher", createdBy: schoolID });
        if (allTeachers.length != 0) {
            res.json({ message: "success", allTeachers, numberOfTeacher: countTeacher, totalPage: Math.ceil(countTeacher / 20) })
        } else {
            res.json({ message: "There is no any teacher yet." })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const addTeacher = async (req, res) => {
    try {
        const { userName, password } = req.body
        const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
        const findTeacher = await userModel.findOne({ userName, role: 'Teacher', createdBy: schoolID })
        if (findTeacher) {
            res.json({ message: "This teacher name is already registered" })
        } else {
            const { pageNumber } = req.params
            const skippedNumber = (pageNumber - 1) * 20
            try {
                const hashPassword = await bcrypt.hash(password, parseInt(process.env.SALTROUNDS))
                req.body.password = hashPassword
            } catch (bcryptError) {
                return res.status(500).json({ message: 'Error hashing password' })
            }
            req.body.verify = true
            req.body.role = 'Teacher'
            req.body.createdBy = schoolID
            const addTeacher = new userModel(req.body)
            await addTeacher.save()
            const countTeacher = await userModel.countDocuments({ role: "Teacher", createdBy: schoolID });
            const allTeachers = await userModel.find({ role: "Teacher", createdBy: schoolID }).select('userName email subject classList').populate([{ path: 'classList', select: 'class' }, { path: 'subject', select: 'schoolSubjectName' }]).skip(skippedNumber).limit(20)
            res.json({ message: "success", allTeachers, numberOfTeacher: countTeacher, totalPage: Math.ceil(countTeacher / 20) })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const updateTeacher = async (req, res) => {
    try {
        const { TeacherID, pageNumber } = req.params
        if (req.body.password != undefined) {
            try {
                const hashPassword = await bcrypt.hash(req.body.password, parseInt(process.env.SALTROUNDS))
                req.body.password = hashPassword
            } catch (bcryptError) {
                return res.status(500).json({ message: 'Error hashing password' })
            }
        }
        const updateTeacher = await userModel.findByIdAndUpdate(TeacherID, req.body)
        if (updateTeacher) {
            const skippedNumber = (pageNumber - 1) * 20
            const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
            const countTeacher = await userModel.countDocuments({ role: "Teacher", createdBy: schoolID });
            const allTeachers = await userModel.find({ role: "Teacher", createdBy: schoolID }).select('userName email subject classList').populate([{ path: 'classList', select: 'class' }, { path: 'subject', select: 'schoolSubjectName' }]).skip(skippedNumber).limit(20)
            res.json({ message: "success", allTeachers, numberOfTeacher: countTeacher, totalPage: Math.ceil(countTeacher / 20) })
        } else {
            res.json({ message: "This teacher is not found" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const deleteTeacher = async (req, res) => {
    try {
        const { TeacherID, pageNumber } = req.params
        const findTeacher = await userModel.findById(TeacherID)
        if (findTeacher) {
            const deleteTeacher = await userModel.findByIdAndDelete(TeacherID)
            if (deleteTeacher) {
                const findAssignment = await assignmentModel.find({ createdBy: deleteTeacher._id })
                for (let index = 0; index < findAssignment.length; index++) {
                    const element = findAssignment[index];
                    const findAnswer = await answerModel.find({ assignment: element._id })
                    for (let index = 0; index < findAnswer.length; index++) {
                        const subElement = findAnswer[index];
                        for (let index = 0; index < subElement.questions.length; index++) {
                            const subElement2 = subElement.questions[index];
                            if (subElement2.stepsPicID) {
                                await cloudinary.uploader.destroy(subElement2.stepsPicID)
                            }
                        }
                        await answerModel.findByIdAndDelete(subElement._id)
                    }
                }
                await assignmentModel.deleteMany({ createdBy: deleteTeacher._id })
                const skippedNumber = (pageNumber - 1) * 20
                const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
                const countTeacher = await userModel.countDocuments({ role: "Teacher", createdBy: schoolID });
                const allTeachers = await userModel.find({ role: "Teacher", createdBy: schoolID }).select('userName email subject classList').populate([{ path: 'classList', select: 'class' }, { path: 'subject', select: 'schoolSubjectName' }]).skip(skippedNumber).limit(20)
                res.json({ message: "success", allTeachers, numberOfTeacher: countTeacher, totalPage: Math.ceil(countTeacher / 20) })
            } else {
                res.json({ message: "an error is happend" })
            }
        } else {
            res.json({ message: "This teacher is not found" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const addTeacherToClass = async (req, res) => {
    try {
        const { classID, teacherID } = req.params
        const findTeacher = await userModel.findById(teacherID)
        if (findTeacher) {
            const findClass = await classModel.findById(classID)
            if (findClass) {
                const isFound = findClass.teachers.filter(e => e == teacherID)[0]
                if (isFound) {
                    res.json({ message: "This teacher is already added to this class" })
                } else {
                    findClass.teachers.push(teacherID)
                    await findClass.save()
                    findTeacher.classList.push(classID)
                    await findTeacher.save()
                    const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
                    const allClasses = await classModel.find({ school: schoolID }).populate({ path: 'teachers', select: 'userName' })
                    res.json({ message: "success", allClasses })
                }
            } else {
                res.json({ message: "This class is not found" })
            }
        } else {
            res.json({ message: "This teacher is not found" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const removeTeacherFromClass = async (req, res) => {
    try {
        const { classID, teacherID } = req.params
        const findTeacher = await userModel.findById(teacherID)
        if (findTeacher) {
            const findClass = await classModel.findById(classID)
            if (findClass) {
                const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
                const removeFromClass = findClass.teachers.filter(e => e != teacherID)
                const removeFromTeacher = findTeacher.classList.filter(e => e != classID)
                findClass.teachers = removeFromClass
                await findClass.save()
                findTeacher.classList = removeFromTeacher
                await findTeacher.save()
                const newClass = await classModel.findById(classID).populate({ path: 'teachers', select: 'userName' })
                const allClasses = await classModel.find({ school: schoolID }).populate({ path: 'teachers', select: 'userName' })
                res.json({ message: 'success', newClass, allClasses })
            } else {
                res.json({ message: "This class is not found" })
            }
        } else {
            res.json({ message: "This teacher is not found" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const search = async (req, res) => {
    try {
        const { searchKey } = req.params
        const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
        let findTeacher = await userModel.find({ 'userName': { $regex: searchKey, $options: 'i' }, role: "Teacher", createdBy: schoolID }).select('userName email subject classList').populate([{ path: 'classList', select: 'class' }, { path: 'subject', select: 'schoolSubjectName' }])
        if (findTeacher.length != 0) {
            res.json({ message: 'success', allTeachers: findTeacher })
        } else {
            res.json({ message: 'There are no teacher available with this name' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const getTeacherToClass = async (req, res) => {
    try {
        const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
        const allTeachers = await userModel.find({ role: "Teacher", createdBy: schoolID }).select('userName')
        if (allTeachers.length != 0) {
            res.json({ message: 'success', allTeachers })
        } else {
            res.json({ message: "There is no any teacher yet." })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const getTeacherClass = async (req, res) => {
    try {
        const teacherID = req.userData._id
        let findTeacher = await userModel.findById(teacherID).select('createdBy').populate({ path: 'createdBy', select: 'userName' })
        if (findTeacher) {
            const classes = await classModel.find({ teachers: teacherID }).select('class')
            const teacherClasessObj = {
                _id: findTeacher._id,
                createdBy: findTeacher.createdBy,
                classList: classes
            }
            res.json({ message: 'success', teacherClasess: teacherClasessObj })
        } else {
            res.json({ message: 'There are no teacher available with this id' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const getAllAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id
        const getAssignment = await assignmentModel.find({ createdBy: teacherID }).select('-createdBy').populate([{ path: 'questions', select: '-chapter' }, { path: 'classes', select: 'class' }, { path: 'students.solveBy', select: 'userName' }]).sort({ _id: -1 })
        if (getAssignment.length != 0) {
            res.json({ message: 'success', allAssignment: getAssignment })
        } else {
            res.json({ message: 'There are no assignment available now' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const getStudentHistory = async (req, res) => {
    try {
        const { studentID } = req.params;
        const teacherID = req.userData._id;

        // Find the student or fallback to answer document population
        let student = await userModel.findById(studentID).select('userName email');
        if (!student) {
            const answerDoc = await answerModel.findOne({ solveBy: studentID }).populate('solveBy', 'userName email');
            if (answerDoc && answerDoc.solveBy) {
                student = answerDoc.solveBy;
            } else {
                student = { _id: studentID, userName: 'Student', email: '' };
            }
        }

        // Find all answers by this student for assignments created by this teacher
        const studentAnswers = await answerModel.find({ solveBy: studentID })
            .populate({
                path: 'assignment',
                select: 'title totalPoints createdAt startDate endDate createdBy'
            })
            .sort({ _id: -1 });

        // Filter out answers where assignment is null
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

        // Calculate statistics safely avoiding NaN
        const scores = validAnswers.map(answer => {
            const totalPossible = answer.assignment?.totalPoints || 1;
            const percentage = totalPossible > 0 ? (answer.total / totalPossible) * 100 : 0;
            return isNaN(percentage) ? 0 : percentage;
        });

        const totalAssignments = validAnswers.length;
        const averageScore = scores.reduce((acc, score) => acc + score, 0) / totalAssignments;
        const highestScore = Math.max(...scores);
        const lowestScore = Math.min(...scores);

        // Format assignments data
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

module.exports = { addTeacher, getTeachers, updateTeacher, deleteTeacher, addTeacherToClass, search, getTeacherToClass, removeTeacherFromClass, getTeacherClass, getAllAssignment, getStudentHistory }