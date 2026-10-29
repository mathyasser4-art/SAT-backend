// One source of truth for homework/test marks.
// Every screen (submit popup, student report, teacher sheets, parent view, copilot) must
// read marks through these helpers so the same attempt always shows the same mark.
//
// Rules:
// - A question is worth its questionPoints (1 when unset).
// - An attempt is marked against the questions it was given (answer.questionSet, saved when
//   the attempt starts). Older attempts without a snapshot use the assignment's current
//   questions plus any question they answered that was later removed, so their saved
//   answers still count.
// - Score = points of the questions marked correct. Out of = points of the attempt's questions.
// - The attempt that counts for a student is the best submitted one (highest percentage,
//   ties go to the later attempt). With nothing submitted, the latest attempt is shown as
//   "In Progress".
const mongoose = require('mongoose')
const questionModel = require('../../DB/models/question.model')
const assignmentModel = require('../../DB/models/assignment.model')
const answerModel = require('../../DB/models/answer.model')

const idOf = (x) => String(x && x._id ? x._id : x)

const pointsOf = (q) => (q && typeof q.questionPoints === 'number' && q.questionPoints > 0) ? q.questionPoints : 1

const sumPoints = (questions) => (questions || []).filter(Boolean).reduce((sum, q) => sum + pointsOf(q), 0)

const isFilled = (v) => v !== undefined && v !== null && String(v).trim() !== ''

const isAnswered = (entry) => Boolean(entry) && (
    isFilled(entry.firstAnswer) || isFilled(entry.secondAnswer) || isFilled(entry.thirdAnswer) ||
    isFilled(entry.fourthAnswer) || Boolean(entry.stepPicture && entry.stepPicture.secure_url)
)

const percentOf = (score, totalPoints) => totalPoints > 0 ? Math.round((score / totalPoints) * 100) : 0

// Ordered question ids an attempt is marked against
const questionSetOf = (answer, assignmentQuestionIds) => {
    if (answer && Array.isArray(answer.questionSet) && answer.questionSet.length > 0) {
        return [...new Set(answer.questionSet.map(idOf))]
    }
    const ids = (assignmentQuestionIds || []).filter(Boolean).map(idOf)
    const seen = new Set(ids)
    ;(answer && answer.questions || []).forEach(entry => {
        if (!entry || !entry.question || !isAnswered(entry)) return
        const qId = idOf(entry.question)
        if (!seen.has(qId)) { seen.add(qId); ids.push(qId) }
    })
    return ids
}

// Marks one attempt. questionsById: Map of question id -> question doc (needs questionPoints).
// Ids missing from the map (question deleted from the bank) are left out of the mark.
const gradeAttempt = (answer, questionSetIds, questionsById) => {
    const entries = new Map()
    ;(answer && answer.questions || []).forEach(entry => {
        if (entry && entry.question) {
            const qId = idOf(entry.question)
            if (!entries.has(qId)) entries.set(qId, entry)
        }
    })

    let score = 0
    let totalPoints = 0
    let correctCount = 0
    let wrongCount = 0
    let unansweredCount = 0
    const questions = []
    questionSetIds.forEach(qId => {
        const question = questionsById.get(qId)
        if (!question) return
        const entry = entries.get(qId) || null
        const points = pointsOf(question)
        const answered = isAnswered(entry)
        const isCorrect = Boolean(entry && entry.isCorrect === true)
        const earned = isCorrect ? points : 0
        totalPoints += points
        score += earned
        if (isCorrect) correctCount += 1
        else if (answered) wrongCount += 1
        else unansweredCount += 1
        questions.push({ questionId: qId, question, entry, points, earned, isCorrect, answered })
    })

    return {
        score,
        totalPoints,
        percentage: percentOf(score, totalPoints),
        correctCount,
        wrongCount,
        unansweredCount,
        answeredCount: correctCount + wrongCount,
        questions
    }
}

const QUESTION_FIELDS = 'questionPoints'

// Marks many attempts with two queries. Returns Map of answer id -> grade.
// assignmentsById (optional): Map of assignment id -> assignment with `questions` ids/docs.
const gradeAttempts = async (answers, { assignmentsById, questionFields = QUESTION_FIELDS, sync = true } = {}) => {
    const list = (answers || []).filter(Boolean)
    const grades = new Map()
    if (list.length === 0) return grades

    const byId = new Map(assignmentsById ? [...assignmentsById].map(([k, v]) => [String(k), v]) : [])
    const missing = [...new Set(list.map(a => idOf(a.assignment)).filter(id => id && id !== 'null' && id !== 'undefined' && !byId.has(id)))]
    if (missing.length > 0) {
        const found = await assignmentModel.find({ _id: { $in: missing } }).select('questions').lean()
        found.forEach(a => byId.set(String(a._id), a))
    }

    const sets = new Map()
    const allIds = new Set()
    list.forEach(answer => {
        const assignment = byId.get(idOf(answer.assignment))
        const set = questionSetOf(answer, assignment ? assignment.questions : [])
        sets.set(idOf(answer._id), set)
        set.forEach(id => allIds.add(id))
    })

    const validIds = [...allIds].filter(id => mongoose.Types.ObjectId.isValid(id))
    const questions = validIds.length > 0
        ? await questionModel.find({ _id: { $in: validIds } }).select(questionFields).lean()
        : []
    const questionsById = new Map(questions.map(q => [String(q._id), q]))

    const updates = []
    list.forEach(answer => {
        const grade = gradeAttempt(answer, sets.get(idOf(answer._id)), questionsById)
        grades.set(idOf(answer._id), grade)
        if (sync && answer._id && (answer.total !== grade.score || answer.totalPossible !== grade.totalPoints)) {
            updates.push({ updateOne: { filter: { _id: answer._id }, update: { $set: { total: grade.score, totalPossible: grade.totalPoints } } } })
        }
    })
    // Keep the stored totals in line with what every screen shows
    if (updates.length > 0) answerModel.bulkWrite(updates, { ordered: false }).catch(() => {})
    return grades
}

const gradeOne = async (answer, opts) => {
    const grades = await gradeAttempts([answer], opts)
    return grades.get(idOf(answer._id))
}

// The attempt that counts. attempts: [{ answer, grade }]
const pickCountedAttempt = (attempts) => {
    const list = (attempts || []).filter(a => a && a.answer)
    if (list.length === 0) return null
    const attemptNo = (a) => a.answer.attemptNumber || 1
    const submitted = list.filter(a => a.answer.completedAt)
    if (submitted.length > 0) {
        return submitted.reduce((best, a) => {
            if (a.grade.percentage !== best.grade.percentage) return a.grade.percentage > best.grade.percentage ? a : best
            if (a.grade.score !== best.grade.score) return a.grade.score > best.grade.score ? a : best
            return attemptNo(a) > attemptNo(best) ? a : best
        })
    }
    return list.reduce((latest, a) => attemptNo(a) > attemptNo(latest) ? a : latest)
}

// Groups graded answers by key (e.g. student or student+assignment) and picks the counted attempt of each
const countedAttemptsBy = (answers, grades, keyOf) => {
    const groups = new Map()
    answers.forEach(answer => {
        const key = keyOf(answer)
        if (!key) return
        if (!groups.has(key)) groups.set(key, [])
        groups.get(key).push({ answer, grade: grades.get(idOf(answer._id)) })
    })
    const counted = new Map()
    groups.forEach((attempts, key) => counted.set(key, { counted: pickCountedAttempt(attempts), attempts }))
    return counted
}

module.exports = {
    idOf,
    pointsOf,
    sumPoints,
    isAnswered,
    percentOf,
    questionSetOf,
    gradeAttempt,
    gradeAttempts,
    gradeOne,
    pickCountedAttempt,
    countedAttemptsBy
}
