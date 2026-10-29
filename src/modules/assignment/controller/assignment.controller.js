const assignmentModel = require('../../../../DB/models/assignment.model')
const answerModel = require('../../../../DB/models/answer.model')
const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require("cloudinary").v2;
cloudinaryConfig()
const mongoose = require('mongoose')
const userModel = require('../../../../DB/models/user.model')
const courseModel = require('../../../../DB/models/course.model')
const questionModel = require('../../../../DB/models/question.model')
const { idOf, sumPoints, gradeAttempts, countedAttemptsBy } = require('../../../services/grading')

// Points of a list of question ids, so totalPoints never depends on what the page sent
const pointsOfQuestionIds = async (ids) => {
    const list = (Array.isArray(ids) ? ids : [ids]).filter(id => id && mongoose.Types.ObjectId.isValid(String(idOf(id))))
    if (list.length === 0) return 0
    const questions = await questionModel.find({ _id: { $in: list.map(idOf) } }).select('questionPoints').lean()
    const byId = new Map(questions.map(q => [String(q._id), q]))
    return sumPoints(list.map(id => byId.get(idOf(id))))
}

const createAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id
        
        if (req.body.classes) {
            // FormData sends a string if only one item is appended, so we ensure it's an array
            const classesArray = Array.isArray(req.body.classes) ? req.body.classes : [req.body.classes];
            req.body.classes = classesArray; // Update req.body.classes to be an array for MongoDB

        }

        const today = new Date().toISOString().slice(0, 10)
        req.body.createdAt = today
        req.body.createdBy = teacherID
        if (req.body.questions !== undefined) req.body.totalPoints = await pointsOfQuestionIds(req.body.questions)
        const addAssignment = new assignmentModel(req.body)
        await addAssignment.save()
        res.json({ message: "success", assignment: addAssignment, addAssignment })
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const getAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id
        const allAssignment = await assignmentModel.find({ createdBy: teacherID }).populate({ path: 'questions', select: '-correctAnswer -questionPicID -wrongAnswerID -chapter' }).sort({ _id: -1 })
        // Out-of points always match the questions, even for assignments saved with a wrong total
        allAssignment.forEach(a => {
            const points = sumPoints(a.questions)
            if (a.totalPoints !== points) assignmentModel.updateOne({ _id: a._id }, { totalPoints: points }).exec().catch(() => {})
            a.totalPoints = points
        })
        if (allAssignment.length != 0) {
            res.json({ message: "success", allAssignment })
        } else {
            res.json({ message: "There is no any assignment yet." })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const updateAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id
        const { assignmentID } = req.params
        const findAssignment = await assignmentModel.findById(assignmentID)
        if (findAssignment) {
            const isPrivileged = ['Admin', 'School', 'Supervisor', 'IT'].includes(req.userData?.role)
            if (!isPrivileged && findAssignment.createdBy && String(findAssignment.createdBy) !== String(teacherID)) {
                const ownsCourse = await courseModel.exists({
                    teacher: teacherID,
                    $or: [{ 'sessions.onlineHw': assignmentID }, { 'sessions.onlineClasswork': assignmentID }]
                })
                if (!ownsCourse) return res.status(403).json({ message: "Access denied - You don't own this assignment" })
            }
            // Student attempt records and ownership are never changed through an edit
            const { students, createdBy, createdAt, _id, ...changes } = req.body
            delete changes.totalPoints
            if (changes.questions !== undefined) changes.totalPoints = await pointsOfQuestionIds(changes.questions)
            if (changes.timer === '' || changes.timer === null) {
                delete changes.timer
                changes.$unset = { timer: 1 }
            }
            const updateAssignment = await assignmentModel.findByIdAndUpdate(assignmentID, changes)
            if (updateAssignment) {
                const getAssignment = await assignmentModel.find({ createdBy: teacherID }).select('-createdBy').populate([{ path: 'questions', select: '-chapter' }, { path: 'classes', select: 'class' }, { path: 'students.solveBy', select: 'userName' }]).sort({ _id: -1 })
                res.json({ message: "success", allAssignment: getAssignment })
            } else {
                res.json({ message: "an error is happend" })
            }
        } else {
            res.json({ message: "This assignment is not found" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const deleteAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id
        const { assignmentID } = req.params
        const findAssignment = await assignmentModel.findById(assignmentID)
        if (!findAssignment) return res.json({ message: "This assignment is not found" })
        // Only the creator or a privileged role. No course-owner branch (unlike updateAssignment):
        // a teacher can put any assignment id into their own course's sessions, so that proves nothing.
        // teacherID is undefined on the no-token dashboard bypass, so it must never count as the creator.
        const isPrivileged = ['Admin', 'School', 'Supervisor', 'IT'].includes(req.userData?.role)
        const isCreator = Boolean(teacherID && findAssignment.createdBy) && String(findAssignment.createdBy) === String(teacherID)
        if (!isPrivileged && !isCreator) return res.status(403).json({ message: "Access denied - You don't own this assignment" })
        const removeAssignment = await assignmentModel.findByIdAndDelete(assignmentID)
        if (removeAssignment) {
            const getAssignment = await assignmentModel.find({ createdBy: teacherID }).select('-createdBy').populate([{ path: 'questions', select: '-chapter' }, { path: 'classes', select: 'class' }, { path: 'students.solveBy', select: 'userName' }]).sort({ _id: -1 })
            res.json({ message: "success", allAssignment: getAssignment })
        } else {
            res.json({ message: "This assignment is not found" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

// NEW: Duplicate/Re-assign an assignment
const duplicateAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id;
        const { assignmentID } = req.params;
        
        console.log('=== duplicateAssignment START ===');
        console.log('Teacher ID:', teacherID);
        console.log('Assignment ID to duplicate:', assignmentID);
        console.log('New assignment data:', req.body);

        // Find the original assignment
        const originalAssignment = await assignmentModel.findById(assignmentID);
        
        if (!originalAssignment) {
            console.log('ERROR: Original assignment not found');
            return res.status(404).json({ message: "Original assignment not found" });
        }

        // Verify teacher owns this assignment
        if (String(originalAssignment.createdBy) !== String(teacherID)) {
            console.log('ERROR: Teacher does not own this assignment');
            return res.status(403).json({ message: "You don't have permission to duplicate this assignment" });
        }

        console.log('Original assignment found:', originalAssignment.title);

        // Create new assignment based on original, but with new data from request
        const today = new Date().toISOString().slice(0, 10);
        
        const newAssignmentData = {
            // Copy from original assignment
            questions: originalAssignment.questions, // Same questions
            totalPoints: await pointsOfQuestionIds(originalAssignment.questions),
            
            // Use new data from request body (title, dates, timer, attempts, classes)
            title: req.body.title,
            timer: req.body.timer !== undefined ? req.body.timer : originalAssignment.timer,
            attemptsNumber: req.body.attemptsNumber || originalAssignment.attemptsNumber || 1,
            explanationMode: req.body.explanationMode || originalAssignment.explanationMode || 'independent',
            startDate: req.body.startDate,
            endDate: req.body.endDate,
            classes: req.body.classes,
            
            // New metadata
            createdBy: teacherID,
            createdAt: today,
            students: [] // Start with no students (they haven't taken it yet)
        };

        console.log('Creating new assignment with data:', newAssignmentData);

        const newAssignment = new assignmentModel(newAssignmentData);
        await newAssignment.save();

        console.log('New assignment created with ID:', newAssignment._id);

        // Get all assignments to return to frontend
        const allAssignments = await assignmentModel
            .find({ createdBy: teacherID })
            .select('-createdBy')
            .populate([
                { path: 'questions', select: '-chapter' },
                { path: 'classes', select: 'class' },
                { path: 'students.solveBy', select: 'userName' }
            ])
            .sort({ _id: -1 });

        console.log('=== duplicateAssignment END ===');
        
        res.json({ 
            message: "success", 
            allAssignment: allAssignments,
            newAssignmentId: newAssignment._id
        });
        
    } catch (error) {
        console.error('=== duplicateAssignment ERROR ===');
        console.error('Error details:', error.message);
        console.error('Stack trace:', error.stack);
        res.status(502).json({ message: error.message });
    }
};

const PRIVILEGED_ROLES = ['Admin', 'School', 'Supervisor', 'IT'];

// Check permissions: Privileged roles (Admin, School, Supervisor, IT), creator, or course teacher
const canViewAssignmentResults = async (userData, assignment, assignmentID) => {
    const teacherID = userData._id;
    const isPrivileged = PRIVILEGED_ROLES.includes(userData?.role);
    if (isPrivileged || !assignment.createdBy || String(assignment.createdBy) === String(teacherID)) return true;

    const courseWithAssignment = await courseModel.exists({
        teacher: teacherID,
        $or: [
            { 'sessions.onlineHw': assignmentID },
            { 'sessions.onlineClasswork': assignmentID }
        ]
    });
    return !!courseWithAssignment;
};

// Highest-scoring submitted attempt per student (see services/grading.js), with every attempt's mark
const gradeAssignmentAnswers = async (assignment, answers) => {
    const grades = await gradeAttempts(answers, { assignmentsById: new Map([[String(assignment._id), assignment]]) })
    const byStudent = countedAttemptsBy(answers, grades, a => a.solveBy && a.solveBy._id ? String(a.solveBy._id) : null)
    return { grades, byStudent }
}

const getStudentResults = async (req, res) => {
    try {
        const { assignmentID } = req.params;

        // Get assignment and populate questions and classes
        const assignment = await assignmentModel.findById(assignmentID)
            .populate('questions')
            .populate({ path: 'classes', select: 'class' });

        if (!assignment) {
            return res.status(404).json({ message: "Assignment not found" });
        }

        if (!(await canViewAssignmentResults(req.userData, assignment, assignmentID))) {
            return res.status(403).json({ message: "Access denied - You don't own this assignment" });
        }

        // 1. Get all answers submitted for this assignment (sorted by latest attempt first)
        const answers = await answerModel.find({ 
            assignment: assignmentID
        })
            .sort({ attemptNumber: -1, createdAt: -1 })
            .populate('solveBy', 'userName email class')
            .select('total totalPossible questionSet questionsNumber time createdAt completedAt questions solveBy attemptNumber');

        // 2. Get all students in assigned classes
        let assignedStudents = [];
        if (assignment.classes && assignment.classes.length > 0) {
            const classIds = assignment.classes.map(c => c._id || c);
            assignedStudents = await userModel.find({ 
                role: 'Student', 
                class: { $in: classIds } 
            }).select('userName email class');
        }

        // Fallback: If no assigned classes or no students found, use solveBy from answer documents
        if (assignedStudents.length === 0) {
            assignedStudents = answers
                .filter(a => a.solveBy)
                .map(a => a.solveBy);
        }

        // Deduplicate students by ID to prevent duplicate rows in reports
        const uniqueStudentMap = new Map();
        assignedStudents.forEach(st => {
            if (st && (st._id || st.id)) {
                const sKey = (st._id || st.id).toString();
                if (!uniqueStudentMap.has(sKey)) {
                    uniqueStudentMap.set(sKey, st);
                }
            }
        });
        assignedStudents = Array.from(uniqueStudentMap.values());

        // Out of the assignment's current questions (an attempt keeps its own total if they changed)
        const totalPoints = sumPoints(assignment.questions);
        const totalQuestions = (assignment.questions || []).filter(Boolean).length;
        // Repair a stored total saved wrong by older pages, so course pages show the same "out of"
        if (assignment.totalPoints !== totalPoints) assignmentModel.updateOne({ _id: assignment._id }, { totalPoints }).exec().catch(() => {});
        const { byStudent } = await gradeAssignmentAnswers(assignment, answers);

        // 3. One row per student: the attempt that counts (best submitted), plus every trial's mark
        const maxAttempts = assignment.attemptsNumber || 1;
        const students = assignedStudents.map(student => {
            const sId = student._id.toString();
            const group = byStudent.get(sId);
            const counted = group ? group.counted : null;
            const attempts = (group ? group.attempts : [])
                .map(({ answer, grade }) => ({
                    answerId: answer._id,
                    attemptNumber: answer.attemptNumber || 1,
                    score: grade.score,
                    totalPossible: grade.totalPoints,
                    percentage: grade.percentage,
                    timeSpent: answer.time || '0:00',
                    completed: !!answer.completedAt,
                    completedAt: answer.completedAt || null
                }))
                .sort((a, b) => a.attemptNumber - b.attemptNumber);
            const attemptInfo = {
                attempts,
                attemptsUsed: attempts.filter(a => a.completed).length,
                maxAttempts,
                bestAttemptNumber: counted ? (counted.answer.attemptNumber || 1) : null
            };

            if (counted) {
                const { answer, grade } = counted;
                return {
                    _id: answer._id,
                    studentId: student._id,
                    userName: student.userName || 'Student',
                    email: student.email || '',
                    status: answer.completedAt ? 'Completed' : 'In Progress',
                    answeredQuestions: grade.answeredCount,
                    correctQuestions: grade.correctCount,
                    score: grade.score,
                    totalPossible: grade.totalPoints,
                    timeSpent: answer.time || '0:00',
                    percentage: grade.percentage,
                    completedAt: answer.completedAt || answer.createdAt,
                    totalQuestions: grade.questions.length,
                    ...attemptInfo
                };
            }
            // Student has not started this assignment yet
            return {
                _id: student._id,
                studentId: student._id,
                userName: student.userName || 'Student',
                email: student.email || '',
                status: 'Not Started',
                answeredQuestions: 0,
                correctQuestions: 0,
                score: 0,
                totalPossible: totalPoints,
                timeSpent: '0:00',
                percentage: 0,
                completedAt: null,
                totalQuestions,
                ...attemptInfo
            };
        });

        res.json({
            message: "success",
            students,
            assignment: {
                _id: assignment._id,
                title: assignment.title,
                totalPoints: totalPoints,
                totalQuestions,
                attemptsNumber: maxAttempts,
                createdAt: assignment.createdAt
            }
        });
    } catch (error) {
        console.error('Error in getStudentResults:', error.message);
        res.status(502).json({ message: error.message });
    }
};

const isFilled = (value) => value !== null && value !== undefined && String(value).trim() !== '';

// Pictures are stored as a URL string; older records may hold a cloudinary object
const getPicUrl = (pic) => {
    if (!pic) return null;
    if (typeof pic === 'string') return pic;
    return pic.secure_url || null;
};

const byUserName = (a, b) => String(a.userName).localeCompare(String(b.userName));

// Per-question breakdown of who solved it correctly, wrongly, or skipped it (best attempt per student)
const getQuestionStats = async (req, res) => {
    try {
        const { assignmentID } = req.params;
        const { courseId } = req.query;

        const assignment = await assignmentModel.findById(assignmentID)
            .select('questions createdBy title totalPoints timer attemptsNumber explanationMode')
            .populate({
                path: 'questions',
                select: 'question questionPic questionPoints typeOfAnswer correctAnswer wrongAnswer answer correctPicAnswer wrongPicAnswer explanation answerPic'
            })
            .lean();

        if (!assignment) {
            return res.status(404).json({ message: "Assignment not found" });
        }

        if (!(await canViewAssignmentResults(req.userData, assignment, assignmentID))) {
            return res.status(403).json({ message: "Access denied - You don't own this assignment" });
        }

        // Skip deleted questions; index stays the 1-based position among the remaining ones
        assignment.questions = (assignment.questions || []).filter(q => q && q._id);

        // Optional roster: only a course the requester teaches (or any course for privileged roles)
        let course = null;
        let roster = null;
        if (typeof courseId === 'string' && mongoose.Types.ObjectId.isValid(courseId)) {
            const foundCourse = await courseModel.findById(courseId)
                .select('name teacher students')
                .populate({ path: 'students', select: 'userName' })
                .lean();
            const isPrivileged = PRIVILEGED_ROLES.includes(req.userData?.role);
            if (foundCourse && (isPrivileged || String(foundCourse.teacher) === String(req.userData._id))) {
                course = { _id: foundCourse._id, name: foundCourse.name };
                const rosterMap = new Map();
                (foundCourse.students || []).forEach(st => {
                    if (st && st._id && !rosterMap.has(st._id.toString())) rosterMap.set(st._id.toString(), st);
                });
                roster = Array.from(rosterMap.values());
            }
        }

        const answerFilter = { assignment: assignmentID };
        if (roster) answerFilter.solveBy = { $in: roster.map(st => st._id) };
        const answers = await answerModel.find(answerFilter)
            .sort({ attemptNumber: -1, createdAt: -1 })
            .populate('solveBy', 'userName')
            .select('total totalPossible questionSet completedAt questions solveBy attemptNumber createdAt')
            .lean();

        // Same attempt getStudentResults reports for each student
        const { byStudent } = await gradeAssignmentAnswers(assignment, answers);
        const studentAnswerMap = {};
        const gradeByAnswer = new Map();
        byStudent.forEach((group, sId) => {
            studentAnswerMap[sId] = group.counted.answer;
            gradeByAnswer.set(String(group.counted.answer._id), group.counted.grade);
        });

        const notStarted = [];
        let counted = [];
        if (roster) {
            roster.forEach(st => {
                const sId = st._id.toString();
                const userName = st.userName || 'Student';
                const answer = studentAnswerMap[sId];
                if (answer) counted.push({ studentId: st._id, userName, attemptNumber: answer.attemptNumber || 1, answer });
                else notStarted.push({ studentId: st._id, userName });
            });
        } else {
            counted = Object.values(studentAnswerMap).map(answer => ({
                studentId: answer.solveBy._id,
                userName: answer.solveBy.userName || 'Student',
                attemptNumber: answer.attemptNumber || 1,
                answer
            }));
        }
        notStarted.sort(byUserName);
        counted.sort(byUserName);

        const totalPoints = sumPoints(assignment.questions);
        const averagePercent = counted.length > 0
            ? Math.round(counted.reduce((sum, st) => sum + gradeByAnswer.get(String(st.answer._id)).percentage, 0) / counted.length)
            : null;

        // Per student: question id -> answer entry (entry.question may be populated or a raw id)
        const entryMaps = counted.map(st => {
            const entryMap = new Map();
            (st.answer.questions || []).forEach(entry => {
                if (!entry || !entry.question) return;
                const qId = (entry.question._id || entry.question).toString();
                if (!entryMap.has(qId)) entryMap.set(qId, entry);
            });
            return entryMap;
        });

        const questions = assignment.questions.map((q, i) => {
            const qId = q._id.toString();
            const correctStudents = [];
            const wrongStudents = [];
            const notAnsweredStudents = [];

            counted.forEach((st, sIdx) => {
                const entry = entryMaps[sIdx].get(qId);
                const finalAnswer = entry
                    ? [entry.fourthAnswer, entry.thirdAnswer, entry.secondAnswer, entry.firstAnswer].find(isFilled)
                    : undefined;
                // attemptNumber lets the report link open the same attempt these lists were built from
                if (entry && entry.isCorrect) {
                    correctStudents.push({ studentId: st.studentId, userName: st.userName, attemptNumber: st.attemptNumber });
                } else if (entry && finalAnswer !== undefined) {
                    wrongStudents.push({
                        studentId: st.studentId,
                        userName: st.userName,
                        attemptNumber: st.attemptNumber,
                        answer: String(finalAnswer),
                        stepsPic: (entry.stepPicture && entry.stepPicture.secure_url) || null
                    });
                } else {
                    notAnsweredStudents.push({ studentId: st.studentId, userName: st.userName, attemptNumber: st.attemptNumber });
                }
            });

            const answered = correctStudents.length + wrongStudents.length;
            // lean() skips schema defaults, so a question saved without a type is the default Essay
            const typeOfAnswer = q.typeOfAnswer || 'Essay';
            const acceptedAnswers = typeOfAnswer === 'Essay' ? (q.answer || []).filter(isFilled) : [];
            let correctAnswer = '';
            if (typeOfAnswer === 'MCQ') correctAnswer = q.correctAnswer || '';
            else if (typeOfAnswer === 'Essay') correctAnswer = acceptedAnswers.join(', ');
            else if (typeOfAnswer === 'Graph') correctAnswer = q.correctPicAnswer || '';

            return {
                _id: q._id,
                index: i + 1,
                question: q.question,
                questionPic: getPicUrl(q.questionPic),
                typeOfAnswer,
                questionPoints: (typeof q.questionPoints === 'number' && q.questionPoints > 0) ? q.questionPoints : 1,
                // Same choice order the homework page shows: unique, non-empty, first four
                choices: typeOfAnswer === 'MCQ' ? Array.from(new Set((q.wrongAnswer || []).filter(isFilled))).slice(0, 4) : [],
                correctAnswer: correctAnswer || 'N/A',
                acceptedAnswers,
                correctPicAnswer: q.correctPicAnswer || '',
                wrongPicAnswer: Array.isArray(q.wrongPicAnswer) ? q.wrongPicAnswer : [],
                explanation: q.explanation || '',
                answerPic: getPicUrl(q.answerPic) || '',
                stats: {
                    correct: correctStudents.length,
                    wrong: wrongStudents.length,
                    notAnswered: notAnsweredStudents.length,
                    answered,
                    percentCorrect: answered > 0 ? Math.round((correctStudents.length / answered) * 100) : null
                },
                correctStudents,
                wrongStudents,
                notAnsweredStudents
            };
        });

        res.json({
            message: "success",
            assignment: {
                _id: assignment._id,
                title: assignment.title,
                totalPoints,
                totalQuestions: assignment.questions.length,
                timer: assignment.timer ?? null,
                attemptsNumber: assignment.attemptsNumber || 1,
                explanationMode: assignment.explanationMode || 'independent'
            },
            course,
            summary: {
                rosterCount: roster ? roster.length : null,
                startedCount: counted.length,
                completedCount: counted.filter(st => !!st.answer.completedAt).length,
                averagePercent,
                notStarted
            },
            questions
        });
    } catch (error) {
        console.error('Error in getQuestionStats:', error.message);
        res.status(502).json({ message: error.message });
    }
};

// FIXED: Add getStudentResults and duplicateAssignment to the exports
module.exports = {
    createAssignment,
    getAssignment,
    updateAssignment,
    deleteAssignment,
    getStudentResults,
    getQuestionStats,
    duplicateAssignment  // ADD THIS LINE
}
