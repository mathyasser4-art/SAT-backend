const answerRouter = require('express').Router()
const { checkAssinmentAnswer, getAssignmentAnswer, getResult, getStudentOwnReport, debugAnswerDocument, getAllAttempts } = require('./controller/answer.controller')
const { wrapMulter } = require('../../middleware/handleMulter')
const upload = require('../../middleware/handleMulter')
const { studentAuth, teacherAuth } = require('../../middleware/auth')

answerRouter.post('/answer/checkAnswer/:questionID/:assignmentID', studentAuth, wrapMulter(upload.any()), checkAssinmentAnswer)
answerRouter.get('/answer/getAnswer/:studentID/:assignmentID', teacherAuth, getAssignmentAnswer)
answerRouter.get('/answer/getMyReport/:assignmentID', studentAuth, getStudentOwnReport)
answerRouter.get('/answer/getResult/:assignmentID', studentAuth, getResult)
answerRouter.get('/answer/getAllAttempts/:assignmentID', studentAuth, getAllAttempts)


// Debug endpoint - can be accessed by both teacher and student
answerRouter.get('/answer/debug/:studentID/:assignmentID', debugAnswerDocument)

module.exports = answerRouter