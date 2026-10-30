const userModel = require('../../../../DB/models/user.model');
const assignmentModel = require('../../../../DB/models/assignment.model');
const answerModel = require('../../../../DB/models/answer.model');
const questionModel = require('../../../../DB/models/question.model');
const { idOf, percentOf, gradeAttempts, countedAttemptsBy } = require('../../../services/grading');

// Submitted attempts of a student, marked by the shared rules, grouped per assignment
const gradedSubmittedWork = async (studentId) => {
    const answers = await answerModel.find({ solveBy: studentId, completedAt: { $ne: null } })
        .populate({ path: 'assignment', select: 'title attemptsNumber questions countingRule startDate endDate' })
        .sort({ completedAt: -1 })
        .lean();
    const withAssignment = answers.filter(a => a.assignment);
    const assignmentsById = new Map(withAssignment.map(a => [String(a.assignment._id), a.assignment]));
    const grades = await gradeAttempts(withAssignment, { assignmentsById });
    return { answers, grades, byAssignment: countedAttemptsBy(withAssignment, grades, a => idOf(a.assignment)) };
};

const getMyChildren = async (req, res) => {
    try {
        const parentId = req.userData._id;
        const parent = await userModel.findById(parentId)
            .select('userName email parentPhone children')
            .populate({ path: 'children', select: 'userName email class parentPhone', populate: { path: 'class', select: 'class teachers' } });
        if (!parent) return res.status(404).json({ message: 'Parent not found' });
        const children = parent.children || [];
        const enrichedChildren = await Promise.all(children.map(async (child) => {
            try {
                const childObj = child.toObject ? child.toObject() : child;
                const allAnswers = await answerModel.find({ solveBy: child._id }).select('questions.question questions.isCorrect').lean();
                // Average of the counted mark of each assignment, the same marks the teacher sees
                const { byAssignment } = await gradedSubmittedWork(child._id);
                let totalScore = 0; let totalPossible = 0;
                byAssignment.forEach(({ counted }) => { totalScore += counted.grade.score; totalPossible += counted.grade.totalPoints; });
                const wrongSet = new Set();
                allAnswers.forEach(ans => { (ans.questions || []).forEach(q => { if (q.isCorrect === false) wrongSet.add(q.question.toString()); }); });
                return { ...childObj, stats: { totalAssignments: byAssignment.size, averageScore: percentOf(totalScore, totalPossible), mistakesCount: wrongSet.size } };
            } catch (e) { return child.toObject ? child.toObject() : child; }
        }));
        res.json({ message: 'success', parent: { _id: parent._id, userName: parent.userName, email: parent.email, parentPhone: parent.parentPhone }, children: enrichedChildren });
    } catch (error) { console.error('getMyChildren error:', error); res.status(502).json({ message: error.message }); }
};

const getChildAssignments = async (req, res) => {
    try {
        const parentId = req.userData._id;
        const { childId } = req.params;
        const parent = await userModel.findById(parentId).select('children');
        const isMyChild = parent && parent.children && parent.children.some(c => c.toString() === childId);
        const isAdmin = ['Admin', 'School', 'Teacher'].includes(req.userData.role);
        if (!isMyChild && !isAdmin) return res.status(403).json({ message: 'Access denied: not your child' });
        const child = await userModel.findById(childId).select('userName email class').populate({ path: 'class', select: 'class' });
        if (!child) return res.status(404).json({ message: 'Student not found' });
        const { byAssignment } = await gradedSubmittedWork(childId);
        const assignments = [...byAssignment.values()].map(({ counted, attempts }) => {
            const a = counted.answer.assignment;
            const sorted = [...attempts].sort((x, y) => (x.answer.attemptNumber || 1) - (y.answer.attemptNumber || 1));
            return {
                _id: a._id,
                title: a.title || 'Assignment',
                // The counted (best) attempt: what the teacher's sheet shows
                totalPoints: counted.grade.totalPoints,
                bestScore: counted.grade.score,
                bestPercentage: counted.grade.percentage,
                countedAttemptNumber: counted.answer.attemptNumber || 1,
                startDate: a.startDate,
                endDate: a.endDate,
                attempts: sorted.map(({ answer, grade }) => ({ attemptNumber: answer.attemptNumber || 1, score: grade.score, totalPossible: grade.totalPoints, percentage: grade.percentage, timeSpent: answer.time || '0:00', completedAt: answer.completedAt })),
                latestCompletedAt: sorted.reduce((latest, x) => (!latest || x.answer.completedAt > latest) ? x.answer.completedAt : latest, null)
            };
        }).sort((x, y) => new Date(y.latestCompletedAt || 0) - new Date(x.latestCompletedAt || 0));
        res.json({ message: 'success', child: { _id: child._id, userName: child.userName, email: child.email, class: child.class }, assignments });
    } catch (error) { console.error('getChildAssignments error:', error); res.status(502).json({ message: error.message }); }
};

const getChildMistakes = async (req, res) => {
    try {
        const parentId = req.userData._id;
        const { childId } = req.params;
        const parent = await userModel.findById(parentId).select('children');
        const isMyChild = parent && parent.children && parent.children.some(c => c.toString() === childId);
        const isAdmin = ['Admin', 'School', 'Teacher'].includes(req.userData.role);
        if (!isMyChild && !isAdmin) return res.status(403).json({ message: 'Access denied: not your child' });
        const child = await userModel.findById(childId).select('userName email');
        if (!child) return res.status(404).json({ message: 'Student not found' });
        const attempts = await answerModel.find({ solveBy: childId }).populate({ path: 'assignment', select: 'title' });
        let wrongQuestionsMap = {};
        for (const attempt of attempts) {
            const assignmentTitle = attempt.assignment ? attempt.assignment.title : 'Assignment';
            for (const qAns of attempt.questions) {
                if (qAns.isCorrect === false) wrongQuestionsMap[qAns.question.toString()] = { questionId: qAns.question.toString(), assignmentTitle, firstAnswer: qAns.firstAnswer, secondAnswer: qAns.secondAnswer, point: qAns.point };
            }
        }
        const wrongQuestionIds = Object.keys(wrongQuestionsMap);
        if (wrongQuestionIds.length === 0) return res.json({ message: 'success', child: { _id: child._id, userName: child.userName }, mistakes: [] });
        const questions = await questionModel.find({ _id: { $in: wrongQuestionIds } });
        const mistakes = questions.map(q => { const meta = wrongQuestionsMap[q._id.toString()]; return { _id: q._id, question: q.question, questionPic: q.questionPic?.secure_url || null, choices: q.choices || [], correctAnswers: q.correctAnswers || [], explanation: q.explanation || '', assignmentTitle: meta.assignmentTitle, studentAnswers: [meta.firstAnswer, meta.secondAnswer].filter(Boolean) }; });
        res.json({ message: 'success', child: { _id: child._id, userName: child.userName }, mistakes });
    } catch (error) { console.error('getChildMistakes error:', error); res.status(500).json({ message: error.message }); }
};

module.exports = { getMyChildren, getChildAssignments, getChildMistakes };
