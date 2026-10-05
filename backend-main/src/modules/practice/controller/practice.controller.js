const practiceAttemptModel = require('../../../../DB/models/practiceAttempt.model');
const subjectModel = require('../../../../DB/models/subject.model');
const chapterModel = require('../../../../DB/models/chapter.model');
const userModel = require('../../../../DB/models/user.model');

// Save a completed practice exam attempt
const recordAttempt = async (req, res) => {
    try {
        const studentId = req.userData?._id;
        if (!studentId) {
            return res.status(401).json({ message: 'User not authenticated' });
        }

        let { 
            questionTypeId, 
            subjectId, 
            chapterId, 
            score, 
            totalQuestions, 
            percentage, 
            timeSpent, 
            subjectName, 
            chapterName 
        } = req.body;

        // Auto-resolve subject name if not provided
        if (!subjectName && subjectId) {
            try {
                const subject = await subjectModel.findById(subjectId);
                if (subject) {
                    subjectName = subject.subjectName || subject.name || '';
                }
            } catch (err) {
                console.error('Error fetching subject name for attempt:', err);
            }
        }

        // Auto-resolve chapter name if not provided
        if (!chapterName && chapterId) {
            try {
                const chapter = await chapterModel.findById(chapterId);
                if (chapter) {
                    chapterName = chapter.chapterName || chapter.name || '';
                }
            } catch (err) {
                console.error('Error fetching chapter name for attempt:', err);
            }
        }

        const safeScore = Number(score) || 0;
        const safeTotal = Number(totalQuestions) || 0;
        const safePercentage = safeTotal > 0 
            ? (percentage !== undefined ? Number(percentage) : Math.round((safeScore / safeTotal) * 100))
            : 0;

        const attempt = await practiceAttemptModel.create({
            studentId,
            questionTypeId: questionTypeId || null,
            subjectId: subjectId || null,
            chapterId: chapterId || null,
            subjectName: subjectName || 'Real Exam Practice',
            chapterName: chapterName || 'Practice Test',
            score: safeScore,
            totalQuestions: safeTotal,
            percentage: safePercentage,
            timeSpent: timeSpent || '0:00',
            completedAt: new Date()
        });

        res.status(201).json({
            message: 'success',
            attempt
        });
    } catch (error) {
        console.error('recordAttempt error:', error);
        res.status(500).json({ message: error.message });
    }
};

// Retrieve all practice exam attempts for a specific student (for teacher view or student view)
const getStudentPracticeAttempts = async (req, res) => {
    try {
        const { studentId } = req.params;
        if (!studentId) {
            return res.status(400).json({ message: 'studentId is required' });
        }

        // Verify student exists
        const student = await userModel.findById(studentId).select('userName email role');
        if (!student) {
            return res.status(404).json({ message: 'Student not found' });
        }

        const attempts = await practiceAttemptModel.find({ studentId })
            .sort({ completedAt: -1 })
            .lean();

        // Calculate statistics
        const totalAttempts = attempts.length;
        const totalScore = attempts.reduce((sum, a) => sum + (a.score || 0), 0);
        const totalQuestions = attempts.reduce((sum, a) => sum + (a.totalQuestions || 0), 0);
        const averagePercentage = totalAttempts > 0
            ? Math.round(attempts.reduce((sum, a) => sum + (a.percentage || 0), 0) / totalAttempts)
            : 0;
        const highestPercentage = totalAttempts > 0
            ? Math.max(...attempts.map(a => a.percentage || 0))
            : 0;

        res.status(200).json({
            message: 'success',
            student: {
                _id: student._id,
                userName: student.userName,
                email: student.email
            },
            attempts,
            statistics: {
                totalAttempts,
                averagePercentage,
                highestPercentage,
                totalScore,
                totalQuestions
            }
        });
    } catch (error) {
        console.error('getStudentPracticeAttempts error:', error);
        res.status(500).json({ message: error.message });
    }
};

module.exports = {
    recordAttempt,
    getStudentPracticeAttempts
};
