const userModel = require('../../../../DB/models/user.model')
const assignmentModel = require('../../../../DB/models/assignment.model')
const answerModel = require('../../../../DB/models/answer.model')
const questionModel = require('../../../../DB/models/question.model')
const checkExpiration = require('../../../services/checkExpiration')
const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require("cloudinary").v2;
cloudinaryConfig()
const bcrypt = require('bcryptjs');

const getStudent = async (req, res) => {
    try {
        const { pageNumber } = req.params
        const skippedNumber = (pageNumber - 1) * 20
        const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
        const allStudent = await userModel.find({ role: "Student", createdBy: schoolID }).select('userName email class').populate({ path: 'class', select: 'class' }).skip(skippedNumber).limit(20)
        const countStudent = await userModel.countDocuments({ role: "Student", createdBy: schoolID });
        if (allStudent.length != 0) {
            res.json({ message: "success", allStudent, numberOfStudent: countStudent, totalPage: Math.ceil(countStudent / 20) })
        } else {
            res.json({ message: "There is no any student yet." })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const addStudent = async (req, res) => {
    try {
        const { userName, password } = req.body
        const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
        const findStudent = await userModel.findOne({ userName, role: "Student", createdBy: schoolID })
        if (findStudent) {
            res.json({ message: "This student name is already registered" })
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
            req.body.role = 'Student'
            req.body.createdBy = schoolID
            const addStudent = new userModel(req.body)
            await addStudent.save()
            const allStudent = await userModel.find({ role: "Student", createdBy: schoolID }).select('userName email class').populate({ path: 'class', select: 'class' }).skip(skippedNumber).limit(20)
            const countStudent = await userModel.countDocuments({ role: "Student", createdBy: schoolID });
            res.json({ message: "success", allStudent, numberOfStudent: countStudent, totalPage: Math.ceil(countStudent / 20) })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const updateStudent = async (req, res) => {
    try {
        const { studentID, pageNumber } = req.params
        if (req.body.password != undefined) {
            try {
                const hashPassword = await bcrypt.hash(req.body.password, parseInt(process.env.SALTROUNDS))
                req.body.password = hashPassword
            } catch (bcryptError) {
                return res.status(500).json({ message: 'Error hashing password' })
            }
        }
        const updateStudent = await userModel.findByIdAndUpdate(studentID, req.body)
        if (updateStudent) {
            const skippedNumber = (pageNumber - 1) * 20
            const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
            const countStudent = await userModel.countDocuments({ role: "Student", createdBy: schoolID });
            const allStudent = await userModel.find({ role: "Student", createdBy: schoolID }).select('userName email class').populate({ path: 'class', select: 'class' }).skip(skippedNumber).limit(20)
            res.json({ message: "success", allStudent, numberOfStudent: countStudent, totalPage: Math.ceil(countStudent / 20) })
        } else {
            res.json({ message: "This student is not found" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const deleteStudent = async (req, res) => {
    try {
        const { studentID, pageNumber } = req.params
        const findStudent = await userModel.findById(studentID)
        if (findStudent) {
            const deleteStudent = await userModel.findByIdAndDelete(studentID)
            if (deleteStudent) {
                const findAnswer = await answerModel.find({ solveBy: deleteStudent._id })
                for (let index = 0; index < findAnswer.length; index++) {
                    const element = findAnswer[index];
                    for (let index = 0; index < element.questions.length; index++) {
                        const subElement = element.questions[index];
                        if (subElement.stepsPicID) {
                            await cloudinary.uploader.destroy(subElement.stepsPicID)
                        }
                    }
                }
                await answerModel.deleteMany({ solveBy: deleteStudent._id })
                const skippedNumber = (pageNumber - 1) * 20
                const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
                const countStudent = await userModel.countDocuments({ role: "Student", createdBy: schoolID });
                const allStudent = await userModel.find({ role: "Student", createdBy: schoolID }).select('userName email class').populate({ path: 'class', select: 'class' }).skip(skippedNumber).limit(20)
                res.json({ message: "success", allStudent, numberOfStudent: countStudent, totalPage: Math.ceil(countStudent / 20) })
            } else {
                res.json({ message: "an error is happend" })
            }
        } else {
            res.json({ message: "This student is not found" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const removeStudentFromClass = async (req, res) => {
    try {
        const { studentID, classID } = req.params
        const findStudent = await userModel.findById(studentID)
        if (findStudent) {
            const removeFromClass = await userModel.findByIdAndUpdate(studentID, { $unset: { class: 1 } })
            if (removeFromClass) {
                const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
                const allStudent = await userModel.find({ createdBy: schoolID, class: classID }).select('userName')
                res.json({ message: "success", allStudent })
            } else {
                res.json({ message: "an error is happend" })
            }
        } else {
            res.json({ message: "This student is not found" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const search = async (req, res) => {
    try {
        const { searchKey } = req.params
        const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id
        let findStudent = await userModel.find({ 'userName': { $regex: searchKey, $options: 'i' }, role: "Student", createdBy: schoolID }).select('userName email class').populate({ path: 'class', select: 'class' })
        if (findStudent.length != 0) {
            res.json({ message: 'success', allStudent: findStudent })
        } else {
            res.json({ message: 'There are no student available with this name' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const getClass = async (req, res) => {
    try {
        const studentID = req.userData._id
        let findStudent = await userModel.findById(studentID).select('class').populate({
            path: 'class',
            select: 'class teachers',
            populate: {
                path: 'teachers',
                select: 'userName subject',
                populate: {
                    path: 'subject',
                    select: 'schoolSubjectName',
                }
            }
        })
        if (findStudent) {
            res.json({ message: 'success', studentData: findStudent })
        } else {
            res.json({ message: 'There are no student available with this id' })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const getAssignment = async (req, res) => {
    try {
        const studentID = req.userData._id;
        const { teacherID } = req.params;
        let findStudent = await userModel.findById(studentID).select('class');
        if (findStudent) {
            const getAssignment = await assignmentModel.find({ createdBy: teacherID }).select('-questions').sort({ _id: -1 });
            if (getAssignment.length != 0) {
                const allAssignment = [];
                for (let index = 0; index < getAssignment.length; index++) {
                    const element = getAssignment[index];
                    if (findStudent.class && element.classes.some(c => (c && c._id ? c._id : c).toString() === findStudent.class.toString())) {
                        const assignmentObj = element.toObject();
                        
                        // Check if student has completed an attempt for this assignment
                        const studentAnswer = await answerModel.findOne({
                            solveBy: studentID,
                            assignment: element._id,
                            completedAt: { $ne: null }
                        }).sort({ attemptNumber: -1, createdAt: -1 });

                        if (studentAnswer) {
                            assignmentObj.isCompleted = true;
                            assignmentObj.score = studentAnswer.total || 0;
                            assignmentObj.totalPossible = element.totalPoints || 0;
                            assignmentObj.timeSpent = studentAnswer.time || '0:00';
                            assignmentObj.completedAt = studentAnswer.completedAt;
                        } else {
                            assignmentObj.isCompleted = false;
                            assignmentObj.score = 0;
                            assignmentObj.totalPossible = element.totalPoints || 0;
                        }
                        
                        allAssignment.push(assignmentObj);
                    }
                }
                res.json({ message: 'success', allAssignment });
            } else {
                res.json({ message: 'There are no assignment available now' });
            }
        } else {
            res.json({ message: 'There are no student available with this id' });
        }
    } catch (error) {
        res.status(502).json({ message: error.message });
    }
};

const getAssignmentDetails = async (req, res) => {
    try {
        const { assignmentID } = req.params
        const studentID = req.userData._id
        let assignment = await assignmentModel.findById(assignmentID).select('-classes -createdBy').populate({ path: 'questions', select: '-correctAnswer -questionPicID -wrongAnswerID -chapter' })
        if (assignment) {
            if (assignment.startDate) {
                if (checkExpiration(assignment.startDate, assignment.endDate)) {
                    res.json({ message: "Oops!!You can't open this assignment, it has expired." })
                    return;
                }
            }
            const findStudent = assignment.students?.filter(e => String(e.solveBy) == String(studentID))[0]
            if (findStudent) {
                // Check if they have already COMPLETED their CURRENT attempt
                // FIX: Only consider an attempt "submitted" if completedAt is set
                // An answer document without completedAt means student is still in progress
                const completedAnswer = await answerModel.findOne({
                    solveBy: studentID,
                    assignment: assignmentID,
                    attemptNumber: findStudent.attempts,
                    completedAt: { $ne: null }
                });
                if (completedAnswer) {
                    // They HAVE completed their current attempt.
                    if (findStudent.attempts >= assignment.attemptsNumber) {
                        res.json({ message: "Oops!!You can't open this assignment, your number of attempts has expired." })
                    } else {
                        const findIndex = assignment.students?.findIndex(object => String(object.solveBy) == String(studentID))
                        const currentAttemptNumber = findStudent.attempts + 1
                        assignment.students[findIndex].attempts = currentAttemptNumber
                        await assignment.save()

                        assignment = assignment.toObject();
                        assignment.currentAttempt = currentAttemptNumber;
                        assignment.totalAttempts = assignment.attemptsNumber;
                        assignment.remainingAttempts = assignment.attemptsNumber - currentAttemptNumber;

                        res.json({ message: "success", assignment })
                    }
                } else {
                    // They HAVEN'T completed their current attempt (either no answer doc, or in-progress)
                    // Let them continue their current attempt. DO NOT increment.
                    assignment = assignment.toObject();
                    assignment.currentAttempt = findStudent.attempts;
                    assignment.totalAttempts = assignment.attemptsNumber;
                    assignment.remainingAttempts = assignment.attemptsNumber - findStudent.attempts;

                    res.json({ message: "success", assignment })
                }
            } else {
                const newStudent = {}
                newStudent.attempts = 1
                newStudent.solveBy = studentID
                assignment.students.push(newStudent)
                await assignment.save()
                
                assignment = assignment.toObject();
                assignment.currentAttempt = 1;
                assignment.totalAttempts = assignment.attemptsNumber;
                assignment.remainingAttempts = assignment.attemptsNumber - 1;
                
                res.json({ message: "success", assignment })
            }
        } else {
            res.json({ message: "There is no any assignment yet." })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}


const getAllStudents = async (req, res) => {
    try {
        const schoolID = (req.userData.role == 'IT' || req.userData.role == 'Teacher') ? (req.userData.createdBy?._id || req.userData.createdBy) : req.userData._id;
        const allStudents = await userModel.find({ role: "Student", createdBy: schoolID }).select('userName email');
        res.json({ message: "success", allStudents });
    } catch (error) {
        res.status(502).json({ message: error.message });
    }
};

const getMyMistakes = async (req, res) => {
    try {
        const studentID = req.userData._id;

        // Find all answer documents for this student
        const attempts = await answerModel.find({ solveBy: studentID }).populate({
            path: 'assignment',
            select: 'title'
        });

        // Collect all wrong questions
        let wrongQuestionsMap = {};
        for (const attempt of attempts) {
            const assignmentTitle = attempt.assignment ? attempt.assignment.title : 'Assignment';
            for (const qAns of attempt.questions) {
                if (qAns.isCorrect === false) {
                    const questionId = qAns.question.toString();
                    wrongQuestionsMap[questionId] = {
                        questionId,
                        assignmentTitle,
                        firstAnswer: qAns.firstAnswer,
                        secondAnswer: qAns.secondAnswer,
                        point: qAns.point
                    };
                }
            }
        }

        const wrongQuestionIds = Object.keys(wrongQuestionsMap);
        if (wrongQuestionIds.length === 0) {
            return res.json({ message: "success", mistakes: [] });
        }

        // Fetch question details
        const questions = await questionModel.find({ _id: { $in: wrongQuestionIds } });

        // Map and format the mistakes
        const mistakes = questions.map(q => {
            const meta = wrongQuestionsMap[q._id.toString()];
            return {
                _id: q._id,
                question: q.question,
                questionPic: q.questionPic?.secure_url || null,
                choices: q.choices || [],
                correctAnswers: q.correctAnswers || [],
                explanation: q.explanation || '',
                assignmentTitle: meta.assignmentTitle,
                studentAnswers: [meta.firstAnswer, meta.secondAnswer].filter(Boolean)
            };
        });

        res.json({ message: "success", mistakes });
    } catch (error) {
        res.status(500).json({ message: "Error fetching mistakes", error: error.message });
    }
};

module.exports = { 
    addStudent, 
    getStudent, 
    updateStudent, 
    deleteStudent, 
    removeStudentFromClass, 
    search, 
    getClass, 
    getAssignment, 
    getAssignmentDetails, 
    getAllStudents,
    getMyMistakes
};