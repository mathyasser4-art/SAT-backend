const questionModel = require('../../../../DB/models/question.model')
const answerModel = require('../../../../DB/models/answer.model')
const assignmentModel = require('../../../../DB/models/assignment.model')
const checkAnswer = require('../../../services/checkAnswer')
const { submitAttempt } = require('../../../services/submitAttempt')
const { idOf, pointsOf, sumPoints, countingRuleOf, questionSetOf, gradeAttempt, gradeAttempts, pickCountedAttempt } = require('../../../services/grading')
const { questionOrderFor } = require('../../../services/shuffle')
const cloudinaryConfig = require('../../../services/cloudinary')
cloudinaryConfig()
const fs = require('fs');

// Fields a report shows for each question
const REPORT_FIELDS = 'question questionPic questionPoints typeOfAnswer correctAnswer wrongAnswer answer correctPicAnswer wrongPicAnswer explanation'

// The attempt a student is on, from the assignment's students[] record
const currentAttemptOf = (assignment, studentID) => {
    const record = assignment?.students?.find(s => String(s.solveBy) === String(studentID));
    return record?.attempts || 1;
};

// The trial the homework page was opened on. Answers from a page left open on an older
// trial (another tab or device) must not land in a newer trial or change a submitted one.
const sentAttemptOf = (req) => {
    const n = parseInt(req.body?.attempt ?? req.query?.attempt, 10);
    return Number.isFinite(n) && n > 0 ? n : null;
};
const TRIAL_CLOSED = 'This trial is closed. Reload the homework to continue.';

const getResult = async (req, res) => {
    try {
        const { assignmentID } = req.params;
        const { time } = req.query;
        const studentID = req.userData._id;

        const assignment = await assignmentModel.findById(assignmentID).select('questions students shuffle');
        if (!assignment) return res.status(404).json({ message: 'Assignment not found' });
        const currentAttemptNumber = currentAttemptOf(assignment, studentID);
        const sentAttempt = sentAttemptOf(req);
        if (sentAttempt && sentAttempt !== currentAttemptNumber) return res.status(409).json({ message: TRIAL_CLOSED });

        // Submit THIS attempt only, never an earlier one: an empty trial is submitted as empty
        let findAnswer = await answerModel.findOne({ solveBy: studentID, assignment: assignmentID, attemptNumber: currentAttemptNumber });
        if (!findAnswer) {
            findAnswer = new answerModel({
                solveBy: studentID,
                assignment: assignmentID,
                attemptNumber: currentAttemptNumber,
                questionSet: questionOrderFor(assignment, studentID, currentAttemptNumber),
                questionsNumber: 0,
                questions: [],
                time: "0:00"
            });
        }

        const grade = await submitAttempt(findAnswer, assignment, time);

        return res.json({
            message: "success",
            result: {
                total: grade.score,
                totalPoints: grade.totalPoints,
                percentage: grade.percentage,
                questionsNumber: grade.answeredCount,
                attemptNumber: findAnswer.attemptNumber,
                time: findAnswer.time
            },
            totalSummation: grade.totalPoints,
        });
    } catch (error) {
        // Not "success": the attempt was not saved as submitted, and the page must keep the
        // student's saved progress so they can submit again.
        console.error('getResult error:', error.message);
        return res.status(500).json({ message: 'Could not submit your homework, please try again' });
    }
};

const checkAssinmentAnswer = async (req, res) => {
    try {
        const { questionID, assignmentID } = req.params;
        const studentID = req.userData._id;

        const { firstAnswer, secondAnswer, thirdAnswer, fourthAnswer, questionAnswer } = req.body;

        const question = await questionModel.findById(questionID);
        if (!question) {
            return res.status(404).json({ message: "Question not found" });
        }

        // Cleanup any uploaded temp files if sent in request
        const uploadedFile = req.file || (req.files && req.files[0]);
        if (uploadedFile && uploadedFile.path && fs.existsSync(uploadedFile.path)) {
            try { fs.unlinkSync(uploadedFile.path); } catch (e) {}
        }

        const assignment = await assignmentModel.findById(assignmentID).select('questions students shuffle');
        if (!assignment) return res.status(404).json({ message: 'Assignment not found' });
        const currentAttemptNumber = currentAttemptOf(assignment, studentID);
        const sentAttempt = sentAttemptOf(req);
        if (sentAttempt && sentAttempt !== currentAttemptNumber) return res.status(409).json({ message: TRIAL_CLOSED });

        // Find or create answer document for THIS attempt
        let findAnswer = await answerModel.findOne({ solveBy: studentID, assignment: assignmentID, attemptNumber: currentAttemptNumber });
        // A submitted trial is final: its answers cannot be changed afterwards
        if (findAnswer && findAnswer.completedAt) return res.status(409).json({ message: 'This trial is already submitted.' });

        if (!findAnswer) {
            findAnswer = new answerModel({
                solveBy: studentID,
                assignment: assignmentID,
                attemptNumber: currentAttemptNumber,
                // The questions this attempt is given, in the order shown; its mark is out of these
                questionSet: questionOrderFor(assignment, studentID, currentAttemptNumber),
                questionsNumber: 0,
                questions: [],
                time: "0:00"
            });
        } else if (!findAnswer.questionSet || findAnswer.questionSet.length === 0) {
            findAnswer.questionSet = questionSetOf(findAnswer, assignment.questions);
        }

        const qPoints = pointsOf(question);
        const answerToSave = (questionAnswer !== undefined && questionAnswer !== null) ? String(questionAnswer) : (firstAnswer !== undefined && firstAnswer !== null ? String(firstAnswer) : '');

        const isCorrect = checkAnswer(question, answerToSave);

        const questionIndex = findAnswer.questions.findIndex(
            q => q && q.question && idOf(q.question) === String(questionID)
        );

        if (questionIndex > -1) {
            findAnswer.questions[questionIndex].firstAnswer = answerToSave;
            findAnswer.questions[questionIndex].isCorrect = isCorrect;
            findAnswer.questions[questionIndex].point = isCorrect ? qPoints : 0;
            if (secondAnswer) findAnswer.questions[questionIndex].secondAnswer = String(secondAnswer);
            if (thirdAnswer) findAnswer.questions[questionIndex].thirdAnswer = String(thirdAnswer);
            if (fourthAnswer) findAnswer.questions[questionIndex].fourthAnswer = String(fourthAnswer);
        } else {
            findAnswer.questions.push({
                question: question._id,
                firstAnswer: answerToSave,
                secondAnswer: secondAnswer ? String(secondAnswer) : '',
                thirdAnswer: thirdAnswer ? String(thirdAnswer) : '',
                fourthAnswer: fourthAnswer ? String(fourthAnswer) : '',
                attempts: 1,
                isCorrect: isCorrect,
                point: isCorrect ? qPoints : 0
            });
        }

        // Running mark, by the same rules every report uses
        const setIds = questionSetOf(findAnswer, assignment?.questions || []);
        const setQuestions = await questionModel.find({ _id: { $in: setIds } }).select('questionPoints').lean();
        const grade = gradeAttempt(findAnswer, setIds, new Map(setQuestions.map(q => [String(q._id), q])));
        findAnswer.total = grade.score;
        findAnswer.totalPossible = grade.totalPoints;
        findAnswer.questionsNumber = grade.answeredCount;
        await findAnswer.save();

        const savedQuestion = findAnswer.questions.find(
            q => q && q.question && idOf(q.question) === String(questionID)
        );

        return res.status(200).json({
            message: "success",
            isCorrect: isCorrect,
            correctAnswer: buildCorrectAnswerStr(question),
            explanation: question.explanation || '',
            answer: savedQuestion || { question: questionID, firstAnswer: answerToSave, isCorrect }
        });

    } catch (error) {
        console.error('checkAssinmentAnswer error:', error.message);
        const uploadedFile = req.file || (req.files && req.files[0]);
        if (uploadedFile && uploadedFile.path && fs.existsSync(uploadedFile.path)) {
            try { fs.unlinkSync(uploadedFile.path); } catch (e) {}
        }
        // Not "success": the answer was not saved, so the page must not show it as marked
        return res.status(500).json({ message: 'Could not save your answer, please try again' });
    }
};

/**
 * Helper: Build correctAnswer string from question data
 */
function buildCorrectAnswerStr(question) {
    if (!question) return 'N/A';

    if (question.typeOfAnswer === 'Graph') {
        return question.correctPicAnswer || 'View Image';
    }

    // For MCQ: use correctAnswer field
    if (question.typeOfAnswer === 'MCQ' && question.correctAnswer && String(question.correctAnswer).trim() !== '') {
        return String(question.correctAnswer);
    }

    // For Essay: use answer[] array (list of acceptable answers)
    if (Array.isArray(question.answer) && question.answer.length > 0) {
        const filtered = question.answer.filter(Boolean);
        if (filtered.length > 0) return filtered.join(', ');
    }

    // Fallback: single string answer
    if (typeof question.answer === 'string' && question.answer.trim() !== '') {
        return question.answer;
    }

    // Final fallback for MCQ correctAnswer (even if it looked empty before)
    if (question.correctAnswer && String(question.correctAnswer).trim() !== '') {
        return String(question.correctAnswer);
    }

    return 'N/A';
}

const reportRow = (question, entry, points, earned, isCorrect, answered) => ({
    _id: (entry && entry._id) || question._id,
    questionId: String(question._id),
    question: question.question || '',
    questionPic: question.questionPic?.secure_url || null,
    firstAnswer: entry?.firstAnswer || '',
    secondAnswer: entry?.secondAnswer || '',
    stepsPic: entry?.stepPicture?.secure_url || null,
    isCorrect,
    notAnswer: !answered,
    questionPoints: points,
    point: earned,
    correctAnswer: buildCorrectAnswerStr(question),
    wrongAnswer: question.wrongAnswer || [],
    wrongPicAnswer: question.wrongPicAnswer || [],
    typeOfAnswer: question.typeOfAnswer || 'Essay',
    explanation: question.explanation || ''
});

// Report of one attempt. With no attempt asked for, it opens the attempt that counts,
// the same one the teacher's sheets and the student's dashboard show.
const buildAttemptReport = async (studentID, assignmentID, requestedAttempt) => {
    const assignment = await assignmentModel.findById(assignmentID).select('title questions attemptsNumber countingRule').lean();
    const attempts = await answerModel.find({ solveBy: studentID, assignment: assignmentID })
        .sort({ attemptNumber: 1, createdAt: 1 }).lean();

    const assignmentInfo = (totalPoints) => ({
        _id: assignment?._id || assignmentID,
        title: assignment?.title || 'Assignment Report',
        totalPoints,
        attemptsNumber: assignment?.attemptsNumber || 1
    });

    if (attempts.length === 0) {
        // Not started: every question unanswered
        const ids = (assignment?.questions || []).map(idOf);
        const found = await questionModel.find({ _id: { $in: ids } }).select(REPORT_FIELDS).lean();
        const byId = new Map(found.map(q => [String(q._id), q]));
        const questions = ids.map(id => byId.get(id)).filter(Boolean);
        const totalPoints = sumPoints(questions);
        return {
            answers: {
                assignment: assignmentInfo(totalPoints),
                time: "0:00",
                total: 0,
                totalPoints,
                percentage: 0,
                questionsNumber: 0,
                attemptNumber: null,
                countedAttemptNumber: null,
                completed: false,
                attemptsList: []
            },
            report: { questions: questions.map(q => reportRow(q, null, pointsOf(q), 0, false, false)) }
        };
    }

    const assignmentsById = assignment ? new Map([[String(assignment._id), assignment]]) : undefined;
    const grades = await gradeAttempts(attempts, { assignmentsById, questionFields: REPORT_FIELDS });
    const graded = attempts.map(answer => ({ answer, grade: grades.get(idOf(answer._id)) }));
    const counted = pickCountedAttempt(graded);
    const selected = (requestedAttempt && graded.find(a => (a.answer.attemptNumber || 1) === requestedAttempt)) || counted;
    const { answer, grade } = selected;

    return {
        answers: {
            assignment: assignmentInfo(grade.totalPoints),
            time: answer.time || "0:00",
            total: grade.score,
            totalPoints: grade.totalPoints,
            percentage: grade.percentage,
            questionsNumber: grade.answeredCount,
            attemptNumber: answer.attemptNumber || 1,
            countedAttemptNumber: counted.answer.attemptNumber || 1,
            countingRule: countingRuleOf(assignment),
            // How the counted trial was chosen: by the teacher, or by the assignment's rule
            countedByTeacher: counted.answer.countedByTeacher === true,
            // This trial's mark was typed in by the teacher
            manual: grade.manual,
            autoScore: grade.autoScore,
            completed: !!answer.completedAt,
            completedAt: answer.completedAt || null,
            attemptsList: graded.map(a => ({
                attemptNumber: a.answer.attemptNumber || 1,
                total: a.grade.score,
                totalPoints: a.grade.totalPoints,
                percentage: a.grade.percentage,
                manual: a.grade.manual,
                completed: !!a.answer.completedAt,
                isCounted: a === counted,
                time: a.answer.time,
                completedAt: a.answer.completedAt
            }))
        },
        report: { questions: grade.questions.map(g => reportRow(g.question, g.entry, g.points, g.earned, g.isCorrect, g.answered)) }
    };
};

const attemptQuery = (req) => {
    const value = parseInt(req.query.attempt || req.query.attemptNumber, 10);
    return Number.isFinite(value) && value > 0 ? value : null;
};

// Teacher view of a student's report (?attempt=N opens a specific attempt)
const getAssignmentAnswer = async (req, res) => {
    try {
        const { studentID, assignmentID } = req.params;
        const result = await buildAttemptReport(studentID, assignmentID, attemptQuery(req));
        return res.json({ message: "success", ...result });
    } catch (error) {
        console.error('getAssignmentAnswer error:', error.message);
        // A real error, not an empty 0/0 report that looks like a result
        return res.status(500).json({ message: 'Could not load this report. Please try again.' });
    }
};

const getStudentOwnReport = async (req, res) => {
    try {
        const { assignmentID } = req.params;
        const result = await buildAttemptReport(req.userData._id, assignmentID, attemptQuery(req));
        return res.json({ message: "success", ...result });
    } catch (error) {
        console.error('getStudentOwnReport error:', error.message);
        // Report a real error instead of an empty 0/0 report that looks like a result
        return res.status(500).json({ message: 'Could not load your report. Please try again.' });
    }
};

// Debug endpoint to inspect answer documents
const debugAnswerDocument = async (req, res) => {
    try {
        const { studentID, assignmentID } = req.params;

        const answer = await answerModel.findOne({
            solveBy: studentID,
            assignment: assignmentID
        }).populate('assignment').populate('questions.question');

        if (!answer) {
            return res.json({
                found: false,
                message: 'No answer document found for this student/assignment'
            });
        }

        const debugInfo = {
            found: true,
            documentId: answer._id,
            studentId: answer.solveBy,
            assignmentId: answer.assignment?._id,
            assignmentTitle: answer.assignment?.title,
            time: answer.time,
            total: answer.total,
            questionsNumber: answer.questionsNumber,
            questionsCount: answer.questions.length,
            questions: answer.questions.map((q, index) => ({
                index: index + 1,
                questionId: q.question?._id,
                questionText: q.question?.question?.substring(0, 50) + '...',
                questionType: q.question?.typeOfAnswer,
                firstAnswer: q.firstAnswer,
                secondAnswer: q.secondAnswer,
                isCorrect: q.isCorrect,
                point: q.point,
                attempts: q.attempts
            }))
        };

        res.json(debugInfo);

    } catch (error) {
        console.error('Debug endpoint error:', error);
        res.status(500).json({ error: error.message });
    }
};

// Get all attempts for a student on an assignment
const getAllAttempts = async (req, res) => {
    try {
        const { assignmentID } = req.params;
        const studentID = req.userData._id;

        const assignment = await assignmentModel.findById(assignmentID).select('title attemptsNumber students questions countingRule').lean();
        if (!assignment) return res.status(404).json({ message: 'Assignment not found' });

        const allAttempts = await answerModel.find({ solveBy: studentID, assignment: assignmentID })
            .sort({ attemptNumber: 1 }).lean();
        const grades = await gradeAttempts(allAttempts, { assignmentsById: new Map([[String(assignment._id), assignment]]) });
        const graded = allAttempts.map(answer => ({ answer, grade: grades.get(idOf(answer._id)) }));
        const counted = pickCountedAttempt(graded);

        const studentRecord = assignment.students?.find(s => String(s.solveBy) === String(studentID));
        const currentAttemptNumber = studentRecord?.attempts || 0;
        const completed = graded.filter(a => a.answer.completedAt);
        const maxAttempts = assignment.attemptsNumber || 1;
        // A trial that was opened but not submitted can still be resumed
        const hasOpenAttempt = currentAttemptNumber > completed.length;
        const averagePercentage = completed.length > 0
            ? Math.round(completed.reduce((sum, a) => sum + a.grade.percentage, 0) / completed.length)
            : 0;
        const totalPossiblePoints = counted ? counted.grade.totalPoints : 0;

        res.json({
            message: "success",
            attempts: graded.map(a => ({
                _id: a.answer._id,
                attemptNumber: a.answer.attemptNumber || 1,
                total: a.grade.score,
                totalPossible: a.grade.totalPoints,
                percentage: a.grade.percentage,
                manual: a.grade.manual,
                completed: !!a.answer.completedAt,
                isCounted: a === counted,
                time: a.answer.time,
                completedAt: a.answer.completedAt,
                createdAt: a.answer.createdAt
            })),
            statistics: {
                totalAttempts: allAttempts.length,
                completedAttempts: completed.length,
                currentAttempt: currentAttemptNumber,
                // Counts trials not yet submitted, including one that is open
                remainingAttempts: Math.max(0, maxAttempts - completed.length),
                hasOpenAttempt,
                maxAttempts,
                countingRule: countingRuleOf(assignment),
                countedByTeacher: Boolean(counted && counted.answer.countedByTeacher),
                // The mark that counts: the trial chosen by the teacher or by the assignment's rule
                bestScore: counted && counted.answer.completedAt ? counted.grade.score : 0,
                bestPercentage: counted && counted.answer.completedAt ? counted.grade.percentage : 0,
                countedAttemptNumber: counted && counted.answer.completedAt ? (counted.answer.attemptNumber || 1) : null,
                averagePercentage,
                averageScore: completed.length > 0 ? Math.round((completed.reduce((sum, a) => sum + a.grade.score, 0) / completed.length) * 100) / 100 : 0,
                totalPossiblePoints
            }
        });
    } catch (error) {
        console.error('getAllAttempts error:', error);
        res.status(500).json({ message: error.message });
    }
};

module.exports = { checkAssinmentAnswer, getAssignmentAnswer, getResult, getStudentOwnReport, debugAnswerDocument, getAllAttempts }
