const userModel = require('../../../../DB/models/user.model');
const assignmentModel = require('../../../../DB/models/assignment.model');
const answerModel = require('../../../../DB/models/answer.model');
const questionModel = require('../../../../DB/models/question.model');

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
                const allAnswers = await answerModel.find({ solveBy: child._id });
                const completedAnswers = allAnswers.filter(a => a.completedAt);
                let totalScore = 0; let totalPossible = 0;
                completedAnswers.forEach(a => { totalScore += a.total || 0; totalPossible += a.totalPossible || 0; });
                const wrongSet = new Set();
                allAnswers.forEach(ans => { (ans.questions || []).forEach(q => { if (q.isCorrect === false) wrongSet.add(q.question.toString()); }); });
                return { ...childObj, stats: { totalAssignments: completedAnswers.length, averageScore: totalPossible > 0 ? Math.round((totalScore / totalPossible) * 100) : 0, mistakesCount: wrongSet.size } };
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
        const answers = await answerModel.find({ solveBy: childId, completedAt: { $ne: null } })
            .populate({ path: 'assignment', select: 'title attemptsNumber totalPoints startDate endDate' })
            .sort({ completedAt: -1 });
        const assignmentMap = {};
        answers.forEach(a => {
            if (!a.assignment) return;
            const aid = a.assignment._id.toString();
            if (!assignmentMap[aid]) assignmentMap[aid] = { _id: a.assignment._id, title: a.assignment.title || 'Assignment', totalPoints: a.assignment.totalPoints || 0, startDate: a.assignment.startDate, endDate: a.assignment.endDate, attempts: [], bestScore: 0, latestCompletedAt: null };
            const score = a.total || 0;
            assignmentMap[aid].attempts.push({ attemptNumber: a.attemptNumber, score, totalPossible: a.assignment.totalPoints || 0, percentage: a.assignment.totalPoints ? Math.round((score / a.assignment.totalPoints) * 100) : 0, timeSpent: a.time || '0:00', completedAt: a.completedAt });
            if (score > assignmentMap[aid].bestScore) assignmentMap[aid].bestScore = score;
            if (!assignmentMap[aid].latestCompletedAt || a.completedAt > assignmentMap[aid].latestCompletedAt) assignmentMap[aid].latestCompletedAt = a.completedAt;
        });
        res.json({ message: 'success', child: { _id: child._id, userName: child.userName, email: child.email, class: child.class }, assignments: Object.values(assignmentMap) });
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
