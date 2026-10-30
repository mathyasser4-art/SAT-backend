// Submits one trial: freezes its question set, re-checks answers not yet marked correct,
// marks it by the shared rules (services/grading.js) and saves it as submitted.
const questionModel = require('../../DB/models/question.model')
const answerModel = require('../../DB/models/answer.model')
const checkAnswer = require('./checkAnswer')
const { idOf, questionSetOf, gradeAttempt } = require('./grading')

// Fields needed to re-check an answer against its key
const CHECK_FIELDS = 'questionPoints correctAnswer typeOfAnswer answer correctPicAnswer'

// answer: mongoose answer document. assignment: needs `questions`. Returns the grade.
const submitAttempt = async (answer, assignment, time) => {
    // Freeze the question set on submit for trials started before it was saved
    const setIds = questionSetOf(answer, assignment.questions)
    if (!answer.questionSet || answer.questionSet.length === 0) answer.questionSet = setIds

    const questions = await questionModel.find({ _id: { $in: setIds } }).select(CHECK_FIELDS).lean()
    const questionsById = new Map(questions.map(q => [String(q._id), q]))

    // Re-check answers not yet marked correct (e.g. a graph answer sent as a picture)
    answer.questions.forEach(entry => {
        if (!entry || !entry.question || entry.isCorrect === true) return
        const question = questionsById.get(idOf(entry.question))
        if (!question) return
        const given = question.typeOfAnswer === 'Graph' && entry.stepPicture?.secure_url
            ? entry.stepPicture.secure_url
            : entry.firstAnswer
        entry.isCorrect = checkAnswer(question, given)
    })

    const grade = gradeAttempt(answer, setIds, questionsById)
    const earnedById = new Map(grade.questions.map(g => [g.questionId, g.earned]))
    answer.questions.forEach(entry => {
        if (entry && entry.question) entry.point = earnedById.get(idOf(entry.question)) || 0
    })

    answer.total = grade.score
    answer.totalPossible = grade.totalPoints
    answer.questionsNumber = grade.answeredCount
    // A second submit of the same trial keeps its first time and date
    if (!answer.completedAt) {
        answer.time = time || "0:00"
        answer.completedAt = new Date()
    }
    await answer.save()
    return grade
}

// Submits trials up to upToAttempt that were left open (only possible for records from before
// one-open-trial was enforced), so a new trial never opens while an older one is unfinished
const closeOpenTrials = async (studentID, assignment, upToAttempt) => {
    const open = await answerModel.find({ solveBy: studentID, assignment: assignment._id, completedAt: null, attemptNumber: { $lte: upToAttempt } })
    for (const answer of open) await submitAttempt(answer, assignment)
    return open.length
}

module.exports = { submitAttempt, closeOpenTrials }
