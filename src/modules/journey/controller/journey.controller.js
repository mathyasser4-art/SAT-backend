const journeyProgressModel = require('../../../../DB/models/journeyProgress.model');
const systemModel = require('../../../../DB/models/system.model');
const unitModel = require('../../../../DB/models/unit.model');

// Save or update student journey progress for a subject/chapter
const saveProgress = async (req, res) => {
    try {
        const studentId = req.userData?._id || req.body.studentId;
        const { subjectId, chapterId, stars, percentage, totalQuestions, progress } = req.body;

        if (!studentId) {
            return res.status(400).json({ message: 'studentId is required' });
        }
        if (!subjectId) {
            return res.status(400).json({ message: 'subjectId is required' });
        }

        let doc = await journeyProgressModel.findOne({ studentId, subjectId });
        if (!doc) {
            doc = new journeyProgressModel({
                studentId,
                subjectId,
                completedChapters: [],
                stars: new Map(),
                scores: new Map(),
                totalQuestionsSolved: 0
            });
        }

        // If batch progress payload provided
        if (progress) {
            if (Array.isArray(progress.completedChapters)) {
                progress.completedChapters.forEach(cId => {
                    if (!doc.completedChapters.includes(String(cId))) {
                        doc.completedChapters.push(String(cId));
                    }
                });
            }
            if (progress.stars && typeof progress.stars === 'object') {
                Object.entries(progress.stars).forEach(([cId, sVal]) => {
                    const current = doc.stars.get(cId) || 0;
                    doc.stars.set(cId, Math.max(current, Number(sVal) || 0));
                });
            }
            if (progress.scores && typeof progress.scores === 'object') {
                Object.entries(progress.scores).forEach(([cId, scVal]) => {
                    const current = doc.scores.get(cId) || 0;
                    doc.scores.set(cId, Math.max(current, Number(scVal) || 0));
                });
            }
        }

        // If single chapter completion update
        if (chapterId) {
            const cStr = String(chapterId);
            const scoreNum = Number(percentage) || 0;
            const starNum = Number(stars) || (scoreNum >= 90 ? 3 : scoreNum >= 70 ? 2 : scoreNum >= 50 ? 1 : 0);

            if (scoreNum >= 70) {
                if (!doc.completedChapters.includes(cStr)) {
                    doc.completedChapters.push(cStr);
                }
            }

            const currentStars = doc.stars.get(cStr) || 0;
            doc.stars.set(cStr, Math.max(currentStars, starNum));

            const currentScore = doc.scores.get(cStr) || 0;
            doc.scores.set(cStr, Math.max(currentScore, scoreNum));

            if (totalQuestions) {
                doc.totalQuestionsSolved = (doc.totalQuestionsSolved || 0) + (Number(totalQuestions) || 0);
            }
        }

        doc.lastUpdated = new Date();
        await doc.save();

        res.status(200).json({
            message: 'success',
            progress: {
                subjectId: doc.subjectId,
                completedChapters: doc.completedChapters,
                stars: Object.fromEntries(doc.stars || []),
                scores: Object.fromEntries(doc.scores || []),
                totalQuestionsSolved: doc.totalQuestionsSolved,
                lastUpdated: doc.lastUpdated
            }
        });
    } catch (error) {
        console.error('saveProgress error:', error);
        res.status(500).json({ message: error.message });
    }
};

// Get progress for a specific student and subject
const getProgress = async (req, res) => {
    try {
        const studentId = req.userData?._id || req.params.studentId;
        const { subjectId } = req.params;

        if (!studentId || !subjectId) {
            return res.status(400).json({ message: 'studentId and subjectId are required' });
        }

        const doc = await journeyProgressModel.findOne({ studentId, subjectId }).lean();
        if (!doc) {
            return res.status(200).json({
                message: 'success',
                progress: {
                    completedChapters: [],
                    stars: {},
                    scores: {},
                    totalQuestionsSolved: 0
                }
            });
        }

        res.status(200).json({
            message: 'success',
            progress: {
                subjectId: doc.subjectId,
                completedChapters: doc.completedChapters || [],
                stars: doc.stars ? (doc.stars instanceof Map ? Object.fromEntries(doc.stars) : doc.stars) : {},
                scores: doc.scores ? (doc.scores instanceof Map ? Object.fromEntries(doc.scores) : doc.scores) : {},
                totalQuestionsSolved: doc.totalQuestionsSolved || 0,
                lastUpdated: doc.lastUpdated
            }
        });
    } catch (error) {
        console.error('getProgress error:', error);
        res.status(500).json({ message: error.message });
    }
};

// Get all progress for a student across all subjects
const getAllProgress = async (req, res) => {
    try {
        const studentId = req.userData?._id || req.params.studentId;
        if (!studentId) {
            return res.status(400).json({ message: 'studentId is required' });
        }

        const docs = await journeyProgressModel.find({ studentId }).lean();
        const progressBySubject = {};

        docs.forEach(doc => {
            const sId = String(doc.subjectId);
            progressBySubject[sId] = {
                completedChapters: doc.completedChapters || [],
                stars: doc.stars ? (doc.stars instanceof Map ? Object.fromEntries(doc.stars) : doc.stars) : {},
                scores: doc.scores ? (doc.scores instanceof Map ? Object.fromEntries(doc.scores) : doc.scores) : {},
                totalQuestionsSolved: doc.totalQuestionsSolved || 0,
                lastUpdated: doc.lastUpdated
            };
        });

        res.status(200).json({
            message: 'success',
            progressBySubject
        });
    } catch (error) {
        console.error('getAllProgress error:', error);
        res.status(500).json({ message: error.message });
    }
};

// System Overview: Calculate live completion percentage for each level/realm
const getSystemOverview = async (req, res) => {
    try {
        const studentId = req.userData?._id || req.params.studentId;
        if (!studentId) {
            return res.status(400).json({ message: 'studentId is required' });
        }

        // 1. Fetch all systems and progress in parallel
        const [systems, progressDocs] = await Promise.all([
            systemModel.find().lean(),
            journeyProgressModel.find({ studentId }).lean()
        ]);

        const progressMap = {};
        progressDocs.forEach(p => {
            progressMap[String(p.subjectId)] = {
                completed: new Set((p.completedChapters || []).map(String)),
                scores: p.scores || {}
            };
        });

        // 2. For each system, get units and compute percentages
        const validSystems = systems.filter(s => s.systemName && s.systemName.trim().length > 0);
        
        const overview = await Promise.all(validSystems.map(async (sys) => {
            const subjects = sys.subjects || [];
            let systemTotalChapters = 0;
            let systemCompletedChapters = 0;
            let systemScoreSum = 0;

            const subjectStats = await Promise.all(subjects.map(async (sub) => {
                const subId = String(sub._id);
                const subProgress = progressMap[subId] || { completed: new Set(), scores: {} };

                const units = await unitModel.find({ subject: sub._id }).select('chapters').lean();
                let subTotalChapters = 0;
                let subCompletedCount = 0;

                let subScoreSum = 0;
                units.forEach(u => {
                    const chaps = u.chapters || [];
                    subTotalChapters += chaps.length;
                    chaps.forEach(cId => {
                        const score = Number(subProgress.scores?.[String(cId)]) || 0;
                        subScoreSum += score;
                        if (score >= 70 || subProgress.completed.has(String(cId))) {
                            subCompletedCount++;
                        }
                    });
                });

                systemTotalChapters += subTotalChapters;
                systemCompletedChapters += subCompletedCount;
                systemScoreSum += subScoreSum;

                const subPercentage = subTotalChapters > 0
                    ? Math.min(100, Math.round(subScoreSum / subTotalChapters))
                    : 0;

                return {
                    subjectId: sub._id,
                    subjectName: sub.subjectName,
                    totalChapters: subTotalChapters,
                    completedChapters: subCompletedCount,
                    completionPercentage: subPercentage
                };
            }));

            const systemPercentage = systemTotalChapters > 0
                ? Math.min(100, Math.round(systemScoreSum / systemTotalChapters))
                : 0;

            return {
                systemId: sys._id,
                systemName: sys.systemName.trim(),
                totalChapters: systemTotalChapters,
                completedChapters: systemCompletedChapters,
                completionPercentage: systemPercentage,
                subjects: subjectStats
            };
        }));

        res.status(200).json({
            message: 'success',
            overview
        });
    } catch (error) {
        console.error('getSystemOverview error:', error);
        res.status(500).json({ message: error.message });
    }
};

module.exports = {
    saveProgress,
    getProgress,
    getAllProgress,
    getSystemOverview
};
