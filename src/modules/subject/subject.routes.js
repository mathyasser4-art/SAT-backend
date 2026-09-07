const subjectRouter = require('express').Router()
const { addSubject, updateSubject, deleteSubject } = require('./controller/subject.controller')
const { adminAuth } = require('../../middleware/auth')

subjectRouter.post('/subject/addSubject', adminAuth, addSubject)
subjectRouter.put('/subject/updateSubject/:subjectID', adminAuth, updateSubject)
subjectRouter.delete('/subject/deleteSubject/:subjectID', adminAuth, deleteSubject)

module.exports = subjectRouter