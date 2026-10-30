const mongoose = require('mongoose')

const assignmentSchema = new mongoose.Schema({
    questions: {
        type: [mongoose.Schema.Types.ObjectId],
        ref: "question"
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user"
    },
    classes: {
        type: [mongoose.Schema.Types.ObjectId],
        ref: "class"
    },
    students: [
        {
            attempts: Number,
            solveBy: { type: mongoose.Schema.Types.ObjectId, ref: "user" }
        }
    ],
    createdAt: String,
    title: String,
    timer: Number,
    startDate: String,
    endDate: String,
    attemptsNumber: {
        type: Number,
        default: 1
    },
    explanationMode: {
        type: String,
        enum: ['guided', 'independent'],
        default: 'independent'
    },
    totalPoints: Number,
    // Which submitted trial is the student's mark: 'first' or 'best' (see src/services/grading.js)
    countingRule: {
        type: String,
        enum: ['first', 'best'],
        default: 'first'
    },
    // Each student gets the questions, and MCQ choices, in their own order
    shuffle: {
        type: Boolean,
        default: false
    },
})

const assignmentModel = mongoose.model('assignment', assignmentSchema)
module.exports = assignmentModel