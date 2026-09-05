const mongoose = require('mongoose');

const practiceAttemptSchema = new mongoose.Schema({
    studentId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user',
        required: true
    },
    questionTypeId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'questionType'
    },
    subjectId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'subject'
    },
    chapterId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'chapter'
    },
    subjectName: {
        type: String,
        default: ''
    },
    chapterName: {
        type: String,
        default: ''
    },
    score: {
        type: Number,
        required: true,
        default: 0
    },
    totalQuestions: {
        type: Number,
        required: true,
        default: 0
    },
    percentage: {
        type: Number,
        required: true,
        default: 0
    },
    timeSpent: {
        type: String,
        default: '0:00'
    },
    completedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Index for efficient querying by student
practiceAttemptSchema.index({ studentId: 1, completedAt: -1 });

const practiceAttemptModel = mongoose.model('practiceAttempt', practiceAttemptSchema);
module.exports = practiceAttemptModel;
