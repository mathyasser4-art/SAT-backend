const mongoose = require('mongoose')

const answerSchema = new mongoose.Schema({
    assignment: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "assignment"
    },
    solveBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user"
    },
    attemptNumber: {
        type: Number,
        required: true,
        default: 1
    },
    time: {
        type: String,
        default: "0:00"  // Add default value
    },
    completedAt: {
        type: Date,
        default: null
    },
    questions: [
        {
            question: { type: mongoose.Schema.Types.ObjectId, ref: "question" },
            attempts: Number,
            firstAnswer: String,
            secondAnswer: String,
            thirdAnswer: String,
            fourthAnswer: String,
            isCorrect: Boolean,
            point: Number,
            stepPicture: {
                secure_url: String,
                public_id: String
            },
        }
    ],
    // Questions this attempt was given, saved when it starts, so later edits to the
    // assignment do not change a mark already earned (see src/services/grading.js)
    questionSet: [{ type: mongoose.Schema.Types.ObjectId, ref: "question" }],
    total: Number,
    totalPossible: Number,
    // Mark typed in by the teacher; replaces the automatic mark of this trial while set
    manualScore: { type: Number, default: null },
    manualScoreBy: { type: mongoose.Schema.Types.ObjectId, ref: "user" },
    manualScoreAt: Date,
    // The teacher chose this trial as the student's mark, overriding the assignment's rule
    countedByTeacher: { type: Boolean, default: false },
    countedSetBy: { type: mongoose.Schema.Types.ObjectId, ref: "user" },
    countedSetAt: Date,
    questionsNumber: Number,
}, { 
    timestamps: true 
})

const answerModel = mongoose.model('answer', answerSchema)
module.exports = answerModel