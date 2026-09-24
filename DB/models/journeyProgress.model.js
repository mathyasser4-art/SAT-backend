const mongoose = require('mongoose');

const journeyProgressSchema = new mongoose.Schema({
    studentId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user',
        required: true
    },
    subjectId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'subject',
        required: true
    },
    completedChapters: {
        type: [String],
        default: []
    },
    stars: {
        type: Map,
        of: Number,
        default: {}
    },
    scores: {
        type: Map,
        of: Number,
        default: {}
    },
    totalQuestionsSolved: {
        type: Number,
        default: 0
    },
    lastUpdated: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true });

journeyProgressSchema.index({ studentId: 1, subjectId: 1 }, { unique: true });

const journeyProgressModel = mongoose.model('journeyProgress', journeyProgressSchema);
module.exports = journeyProgressModel;
