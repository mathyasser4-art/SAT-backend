const assignmentRouter = require('express').Router()
const { createAssignment, getAssignment, updateAssignment, deleteAssignment, getStudentResults, getQuestionStats, setCountedAttempt, setAttemptMark, duplicateAssignment } = require('./controller/assignment.controller')
const { teacherAuth } = require('../../middleware/auth')

assignmentRouter.post('/assignment/createAssignment', teacherAuth, createAssignment)
assignmentRouter.get('/assignment/getAssignment', teacherAuth, getAssignment)
assignmentRouter.put('/assignment/updateAssignment/:assignmentID', teacherAuth, updateAssignment)
assignmentRouter.delete('/assignment/deleteAssignment/:assignmentID', teacherAuth, deleteAssignment)
assignmentRouter.get('/assignment/:assignmentID/student-results', teacherAuth, getStudentResults);
assignmentRouter.get('/assignment/:assignmentID/question-stats', teacherAuth, getQuestionStats);
assignmentRouter.post('/assignment/duplicateAssignment/:assignmentID', teacherAuth, duplicateAssignment);
// Teacher corrections to one student's marks
assignmentRouter.put('/assignment/:assignmentID/students/:studentID/counted-attempt', teacherAuth, setCountedAttempt);
assignmentRouter.put('/assignment/:assignmentID/students/:studentID/attempts/:attemptNumber/mark', teacherAuth, setAttemptMark);

module.exports = assignmentRouter