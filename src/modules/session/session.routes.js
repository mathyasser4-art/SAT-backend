const sessionRouter = require('express').Router()
const { getMySessions, endMySession, logout, getStudentSessions, endStudentSession } = require('./controller/session.controller')
const { userAuth, teacherAuth } = require('../../middleware/auth')

sessionRouter.get('/sessions/me', userAuth, getMySessions)
sessionRouter.post('/sessions/logout', userAuth, logout)
sessionRouter.delete('/sessions/me/:sessionId', userAuth, endMySession)
sessionRouter.get('/sessions/student/:studentID', teacherAuth, getStudentSessions)
sessionRouter.delete('/sessions/student/:studentID/:sessionId', teacherAuth, endStudentSession)

module.exports = sessionRouter
