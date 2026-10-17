const questionReportModel = require('../../../../DB/models/questionReport.model');
const questionModel = require('../../../../DB/models/question.model');
const chapterModel = require('../../../../DB/models/chapter.model');
const userModel = require('../../../../DB/models/user.model');
const jwt = require('jsonwebtoken');
const getJwtSecret = require('../../../services/jwtSecret');

// Helper to safely extract user from auth headers (without throwing)
const extractUserSafe = async (req) => {
    try {
        const rawAuthHeader = req.headers['authorization'] || req.headers['authrization'] || req.headers['auth-token'] || req.headers['token'];
        if (!rawAuthHeader) return null;

        const prefixes = ['pracYas09', process.env.AUTH_SECRET_KEY, 'Bearer ', 'Token '].filter(Boolean);
        let token = rawAuthHeader;
        for (const p of prefixes) {
            if (token.startsWith(p)) {
                token = token.slice(p.length).trim();
                break;
            }
        }

        const decoded = jwt.verify(token, getJwtSecret());
        if (decoded && decoded.id) {
            const user = await userModel.findById(decoded.id).select('userName email role');
            return user;
        }
    } catch (e) {
        // Silently ignore invalid tokens for reporting
    }
    return null;
};

// 1. Submit a Question Report (Students, Teachers, Guests)
const createReport = async (req, res) => {
    try {
        const { questionId, reason, comment, sectionInfo, chapterId } = req.body;

        if (!questionId) {
            return res.status(400).json({ message: 'questionId is required' });
        }

        const question = await questionModel.findById(questionId);
        if (!question) {
            return res.status(404).json({ message: 'Question not found' });
        }

        const currentUser = await extractUserSafe(req);

        const newReport = new questionReportModel({
            question: questionId,
            user: currentUser ? currentUser._id : null,
            reporterName: currentUser ? (currentUser.userName || 'Student') : (sectionInfo?.reporterName || 'Student (Guest)'),
            reporterEmail: currentUser ? (currentUser.email || '') : (sectionInfo?.reporterEmail || ''),
            reason: reason || 'other',
            comment: (comment || '').trim(),
            chapter: chapterId || question.chapter || null,
            sectionInfo: {
                questionTypeName: sectionInfo?.questionTypeName || '',
                subjectName: sectionInfo?.subjectName || '',
                unitName: sectionInfo?.unitName || '',
                chapterName: sectionInfo?.chapterName || '',
                questionNum: sectionInfo?.questionNum ? String(sectionInfo.questionNum) : ''
            },
            status: 'pending'
        });

        await newReport.save();

        res.status(201).json({
            message: 'success',
            report: newReport
        });
    } catch (error) {
        console.error('Error creating question report:', error);
        res.status(500).json({ message: error.message });
    }
};

// 2. Get All Question Reports (Dashboard Queue)
const getAllReports = async (req, res) => {
    try {
        const { status } = req.query;
        const filter = {};

        if (status && status !== 'all') {
            filter.status = status;
        }

        const reports = await questionReportModel.find(filter)
            .sort({ createdAt: -1 })
            .populate({
                path: 'question',
                select: 'question questionPic typeOfAnswer correctAnswer wrongAnswer chapter explanation questionPoints'
            })
            .populate({
                path: 'user',
                select: 'userName email role'
            })
            .populate({
                path: 'chapter',
                select: 'chapterName unit',
                populate: {
                    path: 'unit',
                    select: 'unitName questionType subject',
                    populate: [
                        { path: 'subject', select: 'subjectName' },
                        { path: 'questionType', select: 'questionType' }
                    ]
                }
            })
            .lean();

        // Enrich each report with unified hierarchy fields for easy 1-click navigation
        const enrichedReports = reports.map(r => {
            const chap = r.chapter;
            const unit = chap?.unit;
            const subj = unit?.subject;
            const qType = unit?.questionType;

            return {
                ...r,
                hierarchy: {
                    questionTypeName: qType?.questionType || r.sectionInfo?.questionTypeName || 'Topic Questions',
                    questionTypeID: qType?._id ? String(qType._id) : '',
                    subjectName: subj?.subjectName || r.sectionInfo?.subjectName || '',
                    subjectID: subj?._id ? String(subj._id) : '',
                    unitName: unit?.unitName || r.sectionInfo?.unitName || '',
                    unitID: unit?._id ? String(unit._id) : '',
                    chapterName: chap?.chapterName || r.sectionInfo?.chapterName || '',
                    chapterID: chap?._id ? String(chap._id) : (r.chapter ? String(r.chapter) : '')
                }
            };
        });

        const [totalPending, totalResolved, totalCount] = await Promise.all([
            questionReportModel.countDocuments({ status: 'pending' }),
            questionReportModel.countDocuments({ status: 'resolved' }),
            questionReportModel.countDocuments()
        ]);

        res.json({
            message: 'success',
            reports: enrichedReports,
            totalPending,
            totalResolved,
            totalCount
        });
    } catch (error) {
        console.error('Error fetching question reports:', error);
        res.status(500).json({ message: error.message });
    }
};

// 3. Quick Summary / Badge Count (for Dashboard Navbar)
const getReportSummary = async (req, res) => {
    try {
        const pendingCount = await questionReportModel.countDocuments({ status: 'pending' });
        res.json({
            message: 'success',
            pendingCount
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// 4. Get Reports For Specific Question
const getReportsForQuestion = async (req, res) => {
    try {
        const { questionID } = req.params;
        const reports = await questionReportModel.find({ question: questionID })
            .sort({ createdAt: -1 })
            .populate('user', 'userName email')
            .lean();

        const pendingCount = reports.filter(r => r.status === 'pending').length;

        res.json({
            message: 'success',
            reports,
            pendingCount
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// 5. Update Status (Resolved / Dismissed / Pending)
const updateReportStatus = async (req, res) => {
    try {
        const { reportID } = req.params;
        const { status, resolutionNote } = req.body;

        if (!['pending', 'resolved', 'dismissed'].includes(status)) {
            return res.status(400).json({ message: 'Invalid status' });
        }

        const updateData = {
            status,
            resolutionNote: resolutionNote || '',
            resolvedAt: status === 'resolved' ? new Date() : null
        };

        const updated = await questionReportModel.findByIdAndUpdate(reportID, updateData, { new: true });
        if (!updated) {
            return res.status(404).json({ message: 'Report not found' });
        }

        res.json({
            message: 'success',
            report: updated
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// 6. Bulk Resolve All Reports for a Question
const resolveAllForQuestion = async (req, res) => {
    try {
        const { questionID } = req.params;
        const { resolutionNote } = req.body;

        const result = await questionReportModel.updateMany(
            { question: questionID, status: 'pending' },
            {
                status: 'resolved',
                resolutionNote: resolutionNote || 'Question revised and updated by admin.',
                resolvedAt: new Date()
            }
        );

        res.json({
            message: 'success',
            resolvedCount: result.modifiedCount
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// 7. Delete Report
const deleteReport = async (req, res) => {
    try {
        const { reportID } = req.params;
        const deleted = await questionReportModel.findByIdAndDelete(reportID);
        if (!deleted) {
            return res.status(404).json({ message: 'Report not found' });
        }

        res.json({ message: 'success' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

module.exports = {
    createReport,
    getAllReports,
    getReportSummary,
    getReportsForQuestion,
    updateReportStatus,
    resolveAllForQuestion,
    deleteReport
};
