const questionTypeRouter = require('express').Router()
const { addQuestionType, getQuestionType } = require('./controller/questionType.controller')
const { publicAdminAuth } = require('../../middleware/auth')

questionTypeRouter.post('/questionType/addQuestionType', publicAdminAuth, addQuestionType)
questionTypeRouter.get('/questionType/getQuestionType/:typeOfExamID', getQuestionType)

module.exports = questionTypeRouter