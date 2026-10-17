const questionReportRouter = require('express').Router();
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

// Dashboard management endpoints
questionReportRouter.get('/report/all', getAllReports);
questionReportRouter.get('/report/summary', getReportSummary);
questionReportRouter.get('/report/question/:questionID', getReportsForQuestion);
questionReportRouter.patch('/report/updateStatus/:reportID', updateReportStatus);
questionReportRouter.put('/report/resolveQuestion/:questionID', resolveAllForQuestion);
questionReportRouter.delete('/report/deleteReport/:reportID', deleteReport);

module.exports = questionReportRouter;
