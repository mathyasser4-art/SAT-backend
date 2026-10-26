const questionReportRouter = require('express').Router();
const { adminAuth } = require('../../middleware/auth');
const {
    createReport,
    getAllReports,
    getReportSummary,
    getReportsForQuestion,
    updateReportStatus,
    resolveAllForQuestion,
    deleteReport
} = require('./controller/questionReport.controller');

// Public/student reporting endpoint
questionReportRouter.post('/report/create', createReport);

// Dashboard management endpoints: same guard as the dashboard's question/chapter/unit routes.
// Attached per route because every router is mounted at the app root, so a router-level
// use() would also run in front of unrelated routes mounted after this one.
questionReportRouter.get('/report/all', adminAuth, getAllReports);
questionReportRouter.get('/report/summary', adminAuth, getReportSummary);
questionReportRouter.get('/report/question/:questionID', adminAuth, getReportsForQuestion);
questionReportRouter.patch('/report/updateStatus/:reportID', adminAuth, updateReportStatus);
questionReportRouter.put('/report/resolveQuestion/:questionID', adminAuth, resolveAllForQuestion);
questionReportRouter.delete('/report/deleteReport/:reportID', adminAuth, deleteReport);

module.exports = questionReportRouter;
