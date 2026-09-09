const userModel = require('../../../../DB/models/user.model')
const classModel = require('../../../../DB/models/class.model')
const assignmentModel = require('../../../../DB/models/assignment.model')
const answerModel = require('../../../../DB/models/answer.model')
const questionModel = require('../../../../DB/models/question.model')
const checkExpiration = require('../../../services/checkExpiration')
const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require("cloudinary").v2;
cloudinaryConfig()
const bcrypt = require('bcryptjs');
const { getSchoolHierarchy } = require('../../../services/schoolContext');

const buildStudentQuery = async (userData, additionalFilter = {}) => {
    const { schoolId, associatedIds } = await getSchoolHierarchy(userData);
    
    let schoolClassIds = [];
    try {
        const classConditions = [
            { school: { $in: associatedIds } },
            { createdBy: { $in: associatedIds } },
            { teachers: { $in: associatedIds } },
            { school: { $exists: false } },
            { school: null }
        ];
        if (userData && userData._id) {
            classConditions.push({ teachers: userData._id });
            classConditions.push({ createdBy: userData._id });
        }
        if (userData && Array.isArray(userData.classList) && userData.classList.length > 0) {
            classConditions.push({ _id: { $in: userData.classList } });
        }
        const classes = await classModel.find({ $or: classConditions }).select('_id');
        schoolClassIds = classes.map(c => c._id);
    } catch(e) {}

    const orConditions = [
        { createdBy: { $in: associatedIds } },
        { class: { $in: schoolClassIds } },
        { classList: { $in: schoolClassIds } },
        { createdBy: { $exists: false } },
        { createdBy: null }
    ];
    if (userData && userData._id) {
        orConditions.push({ createdBy: userData._id });
    }

    return {
        role: "Student",
        $or: orConditions,
        ...additionalFilter
    };
};

const getStudent = async (req, res) => {
    try {
        const pageNumber = Math.max(1, parseInt(req.params.pageNumber) || 1);
        const skippedNumber = (pageNumber - 1) * 20;
        const studentQuery = await buildStudentQuery(req.userData);

        const allStudent = await userModel.find(studentQuery)
            .select('userName email class parent parentPhone')
            .populate({ path: 'class', select: 'class' })
            .populate({ path: 'parent', select: 'userName email parentPhone' })
            .skip(skippedNumber)
            .limit(20);

        const countStudent = await userModel.countDocuments(studentQuery);
        res.json({
            message: "success",
            allStudent: allStudent || [],
            numberOfStudent: countStudent || 0,
            totalPage: Math.max(1, Math.ceil(countStudent / 20))
        });
    } catch (error) {
        console.error('getStudent error:', error);
        res.status(502).json({ message: error.message });
    }
};

const addStudent = async (req, res) => {
    try {
        const { userName, password, parentPhone, parentEmail, parentUserName, parentPassword } = req.body;
        const { schoolId, associatedIds } = await getSchoolHierarchy(req.userData);
        const findStudent = await userModel.findOne({ userName, role: "Student", createdBy: { $in: associatedIds } });

        if (findStudent) {
            res.json({ message: "This student name is already registered" });
        } else {
            const pageNumber = Math.max(1, parseInt(req.params.pageNumber) || 1);
            const skippedNumber = (pageNumber - 1) * 20;

            try {
                const hashPassword = await bcrypt.hash(password, parseInt(process.env.SALTROUNDS) || 10);
                req.body.password = hashPassword;
            } catch (bcryptError) {
                return res.status(500).json({ message: 'Error hashing password' });
            }

            req.body.verify = true;
            req.body.role = 'Student';
            req.body.createdBy = schoolId || req.userData._id;
            if (parentPhone) {
                req.body.parentPhone = parentPhone;
            }
            if (req.body.class && (!req.body.classList || req.body.classList.length === 0)) {
                req.body.classList = [req.body.class];
            }

            const addStudent = new userModel(req.body);
            await addStudent.save();

            // --- AUTO CREATE & LINK PARENT ACCOUNT ---
            let parentAccountInfo = null;
            try {
                const cleanStudentName = userName.replace(/\s+/g, '_').toLowerCase();
                let targetParentUserName = (parentUserName && parentUserName.trim()) || `parent_${cleanStudentName}`;
                let targetParentEmail = (parentEmail && parentEmail.trim().toLowerCase()) 
                    || `${cleanStudentName}.parent@school.com`;

                // Check if a parent user already exists with this email or username
                let existingParent = await userModel.findOne({
                    $or: [{ email: targetParentEmail }, { userName: targetParentUserName }]
                });

                if (existingParent && existingParent.role === 'Parent') {
                    if (!existingParent.children) existingParent.children = [];
                    if (!existingParent.children.includes(addStudent._id)) {
                        existingParent.children.push(addStudent._id);
                    }
                    if (parentPhone && !existingParent.parentPhone) {
                        existingParent.parentPhone = parentPhone;
                    }
                    await existingParent.save();

                    addStudent.parent = existingParent._id;
                    await addStudent.save();

                    parentAccountInfo = {
                        _id: existingParent._id,
                        userName: existingParent.userName,
                        email: existingParent.email,
                        parentPhone: existingParent.parentPhone,
                        role: 'Parent',
                        isExisting: true
                    };
                } else {
                    if (existingParent) {
                        const randomSuffix = Math.floor(100 + Math.random() * 900);
                        targetParentUserName = `${targetParentUserName}_${randomSuffix}`;
                        targetParentEmail = `${cleanStudentName}.parent${randomSuffix}@school.com`;
                    }

                    const rawParentPassword = (parentPassword && parentPassword.trim()) || password;
                    const hashedParentPassword = await bcrypt.hash(rawParentPassword, parseInt(process.env.SALTROUNDS) || 10);

                    const newParent = new userModel({
                        userName: targetParentUserName,
                        email: targetParentEmail,
                        password: hashedParentPassword,
                        role: 'Parent',
                        verify: true,
                        createdBy: schoolId,
                        parentPhone: parentPhone || '',
                        children: [addStudent._id]
                    });
                    await newParent.save();

                    addStudent.parent = newParent._id;
                    await addStudent.save();

                    parentAccountInfo = {
                        _id: newParent._id,
                        userName: newParent.userName,
                        email: newParent.email,
                        rawPassword: rawParentPassword,
                        parentPhone: newParent.parentPhone,
                        role: 'Parent',
                        isNew: true
                    };
                }
            } catch (pErr) {
                console.error('Error auto-creating parent account:', pErr);
            }

            const studentQuery = await buildStudentQuery(req.userData);
            const allStudent = await userModel.find(studentQuery)
                .select('userName email class parent parentPhone')
                .populate({ path: 'class', select: 'class' })
                .populate({ path: 'parent', select: 'userName email parentPhone' })
                .skip(skippedNumber)
                .limit(20);
            const countStudent = await userModel.countDocuments(studentQuery);

            res.json({
                message: "success",
                allStudent: allStudent || [],
                numberOfStudent: countStudent || 0,
                totalPage: Math.max(1, Math.ceil(countStudent / 20)),
                parentAccount: parentAccountInfo
            });
        }
    } catch (error) {
        console.error('addStudent error:', error);
        res.status(502).json({ message: error.message });
    }
};

const updateStudent = async (req, res) => {
    try {
        const { studentID, pageNumber } = req.params;
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

        if (req.body.parentPhone) {
            try {
                const studentDoc = await userModel.findById(studentID);
                if (studentDoc && studentDoc.parent) {
                    await userModel.findByIdAndUpdate(studentDoc.parent, { parentPhone: req.body.parentPhone });
                }
            } catch (pe) {}
        }

        const updateStudent = await userModel.findByIdAndUpdate(studentID, req.body);
        if (updateStudent) {
            const skippedNumber = (page - 1) * 20;
            const studentQuery = await buildStudentQuery(req.userData);

            const countStudent = await userModel.countDocuments(studentQuery);
            const allStudent = await userModel.find(studentQuery)
                .select('userName email class parent parentPhone')
                .populate({ path: 'class', select: 'class' })
                .populate({ path: 'parent', select: 'userName email parentPhone' })
                .skip(skippedNumber)
                .limit(20);

            res.json({
                message: "success",
                allStudent: allStudent || [],
                numberOfStudent: countStudent || 0,
                totalPage: Math.max(1, Math.ceil(countStudent / 20))
            });
        } else {
            res.json({ message: "This student is not found" });
        }
    } catch (error) {
        console.error('updateStudent error:', error);
        res.status(502).json({ message: error.message });
    }
};

const deleteStudent = async (req, res) => {
    try {
        const { studentID, pageNumber } = req.params;
        const page = Math.max(1, parseInt(pageNumber) || 1);
        const findStudent = await userModel.findById(studentID);

        if (findStudent) {
            const deleteStudent = await userModel.findByIdAndDelete(studentID);
            if (deleteStudent) {
                if (deleteStudent.parent) {
                    try {
                        await userModel.findByIdAndUpdate(deleteStudent.parent, {
                            $pull: { children: deleteStudent._id }
                        });
                    } catch (pe) {}
                }

                const findAnswer = await answerModel.find({ solveBy: deleteStudent._id });
                for (let index = 0; index < findAnswer.length; index++) {
                    const element = findAnswer[index];
                    for (let qIdx = 0; qIdx < element.questions.length; qIdx++) {
                        const subElement2 = element.questions[qIdx];
                        if (subElement2.stepsPicID) {
                            try {
                                await cloudinary.uploader.destroy(subElement2.stepsPicID);
                            } catch (e) {}
                        }
                    }
                }
                await answerModel.deleteMany({ solveBy: deleteStudent._id });

                const skippedNumber = (page - 1) * 20;
                const studentQuery = await buildStudentQuery(req.userData);

                const countStudent = await userModel.countDocuments(studentQuery);
                const allStudent = await userModel.find(studentQuery)
                    .select('userName email class parent parentPhone')
                    .populate({ path: 'class', select: 'class' })
                    .populate({ path: 'parent', select: 'userName email parentPhone' })
                    .skip(skippedNumber)
                    .limit(20);

                res.json({
                    message: "success",
                    allStudent: allStudent || [],
                    numberOfStudent: countStudent || 0,
                    totalPage: Math.max(1, Math.ceil(countStudent / 20))
                });
            } else {
                res.json({ message: "an error is happend" });
            }
        } else {
            res.json({ message: "This student is not found" });
        }
    } catch (error) {
        console.error('deleteStudent error:', error);
        res.status(502).json({ message: error.message });
    }
};

const removeStudentFromClass = async (req, res) => {
    try {
        const { studentID, classID } = req.params;
        const findStudent = await userModel.findById(studentID);
        if (findStudent) {
            const removeFromClass = await userModel.findByIdAndUpdate(studentID, { $unset: { class: 1 } });
            if (removeFromClass) {
                const { associatedIds } = await getSchoolHierarchy(req.userData);
                const allStudent = await userModel.find({ 
                    createdBy: { $in: associatedIds }, 
                    class: classID 
                }).select('userName parent parentPhone').populate({ path: 'parent', select: 'userName email parentPhone' });
                res.json({ message: "success", allStudent: allStudent || [] });
            } else {
                res.json({ message: "an error is happend" });
            }
        } else {
            res.json({ message: "This student is not found" });
        }
    } catch (error) {
        console.error('removeStudentFromClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const search = async (req, res) => {
    try {
        const { searchKey } = req.params;
        const studentQuery = await buildStudentQuery(req.userData, {
            'userName': { $regex: searchKey, $options: 'i' }
        });
        const findStudent = await userModel.find(studentQuery)
            .select('userName email class parent parentPhone')
            .populate({ path: 'class', select: 'class' })
            .populate({ path: 'parent', select: 'userName email parentPhone' });

        if (findStudent && findStudent.length !== 0) {
            res.json({ message: 'success', allStudent: findStudent });
        } else {
            res.json({ message: 'There are no student available with this name', allStudent: [] });
        }
    } catch (error) {
        console.error('search student error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getClass = async (req, res) => {
    try {
        const studentID = req.userData._id;
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
        });
        if (findStudent) {
            res.json({ message: 'success', studentData: findStudent });
        } else {
            res.json({ message: 'There are no student available with this id' });
        }
    } catch (error) {
        console.error('getClass error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getAssignment = async (req, res) => {
    try {
        const studentID = req.userData._id;
        const { teacherID } = req.params;
        let findStudent = await userModel.findById(studentID).select('class');
        if (findStudent) {
            const getAssignment = await assignmentModel.find({ createdBy: teacherID }).select('-questions').sort({ _id: -1 });
            if (getAssignment.length !== 0) {
                const allAssignment = [];
                for (let index = 0; index < getAssignment.length; index++) {
                    const element = getAssignment[index];
                    if (findStudent.class && element.classes.some(c => (c && c._id ? c._id : c).toString() === findStudent.class.toString())) {
                        const assignmentObj = element.toObject();
                        
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
                res.json({ message: 'There are no assignment available now', allAssignment: [] });
            }
        } else {
            res.json({ message: 'There are no student available with this id' });
        }
    } catch (error) {
        console.error('getAssignment error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getAssignmentDetails = async (req, res) => {
    try {
        const { assignmentID } = req.params;
        const studentID = req.userData._id;
        let assignment = await assignmentModel.findById(assignmentID).select('-classes -createdBy').populate({ path: 'questions', select: '-correctAnswer -questionPicID -wrongAnswerID -chapter' });
        if (assignment) {
            if (assignment.startDate) {
                if (checkExpiration(assignment.startDate, assignment.endDate)) {
                    res.json({ message: "Oops!!You can't open this assignment, it has expired." });
                    return;
                }
            }
            const findStudent = assignment.students?.filter(e => String(e.solveBy) === String(studentID))[0];
            if (findStudent) {
                const completedAnswer = await answerModel.findOne({
                    solveBy: studentID,
                    assignment: assignmentID,
                    attemptNumber: findStudent.attempts,
                    completedAt: { $ne: null }
                });
                if (completedAnswer) {
                    if (findStudent.attempts >= assignment.attemptsNumber) {
                        res.json({ message: "Oops!!You can't open this assignment, your number of attempts has expired." });
                    } else {
                        const findIndex = assignment.students?.findIndex(object => String(object.solveBy) === String(studentID));
                        const currentAttemptNumber = findStudent.attempts + 1;
                        assignment.students[findIndex].attempts = currentAttemptNumber;
                        await assignment.save();

                        assignment = assignment.toObject();
                        assignment.currentAttempt = currentAttemptNumber;
                        assignment.totalAttempts = assignment.attemptsNumber;
                        assignment.remainingAttempts = assignment.attemptsNumber - currentAttemptNumber;

                        res.json({ message: "success", assignment });
                    }
                } else {
                    assignment = assignment.toObject();
                    assignment.currentAttempt = findStudent.attempts;
                    assignment.totalAttempts = assignment.attemptsNumber;
                    assignment.remainingAttempts = assignment.attemptsNumber - findStudent.attempts;

                    res.json({ message: "success", assignment });
                }
            } else {
                const newStudent = {};
                newStudent.attempts = 1;
                newStudent.solveBy = studentID;
                assignment.students.push(newStudent);
                await assignment.save();
                
                assignment = assignment.toObject();
                assignment.currentAttempt = 1;
                assignment.totalAttempts = assignment.attemptsNumber;
                assignment.remainingAttempts = assignment.attemptsNumber - 1;
                
                res.json({ message: "success", assignment });
            }
        } else {
            res.json({ message: "There is no any assignment yet." });
        }
    } catch (error) {
        console.error('getAssignmentDetails error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getAllStudents = async (req, res) => {
    try {
        const studentQuery = await buildStudentQuery(req.userData);
        const allStudents = await userModel.find(studentQuery)
            .select('userName email class parent parentPhone')
            .populate({ path: 'parent', select: 'userName email parentPhone' });
        res.json({ message: "success", allStudents: allStudents || [] });
    } catch (error) {
        console.error('getAllStudents error:', error);
        res.status(502).json({ message: error.message });
    }
};

const getMyMistakes = async (req, res) => {
    try {
        const studentID = req.userData._id;

        const attempts = await answerModel.find({ solveBy: studentID }).populate({
            path: 'assignment',
            select: 'title'
        });

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

        const questions = await questionModel.find({ _id: { $in: wrongQuestionIds } });

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
        console.error('getMyMistakes error:', error);
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