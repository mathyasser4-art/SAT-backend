const questionRouter = require('express').Router()
const { addQuestion, updateAnswerPic, updateQuestion, checkTheAnswer, getQuestionDetails, deleteQuestion, addGraphQuestion, updateAutoCorrect } = require('./controller/question.controller')
const upload = require('../../middleware/handleMulter')
const { publicAdminAuth } = require('../../middleware/auth')

questionRouter.post('/question/addQuestion', publicAdminAuth, upload.any(), addQuestion)
questionRouter.put('/question/updateAnswerPic/:questionID', publicAdminAuth, upload.any(), updateAnswerPic)
questionRouter.put('/question/updateQuestion/:questionID', publicAdminAuth, upload.any(), updateQuestion)
questionRouter.put('/question/addGraphQuestion/:questionID', publicAdminAuth, upload.array("image"), addGraphQuestion)
questionRouter.post('/question/checkTheAnswer/:questionID', checkTheAnswer)
questionRouter.get('/question/getQuestionDetails/:questionID', getQuestionDetails)
questionRouter.delete('/question/deleteQuestion/:questionID/:chapterID', publicAdminAuth, deleteQuestion)
questionRouter.put('/question/updateAutoCorrect/:questionID', publicAdminAuth, updateAutoCorrect)

module.exports = questionRouter
