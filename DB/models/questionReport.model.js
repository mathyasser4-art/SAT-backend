const mongoose = require('mongoose');

const questionReportSchema = new mongoose.Schema(
    {
        question: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'question',
            required: [true, 'question is required'],
            index: true
        },
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'user',
            default: null
        },
        reporterName: {
            type: String,
            default: 'Student'
        },
        reporterEmail: {
            type: String,
            default: ''
        },
        reason: {
            type: String,
            required: [true, 'reason is required'],
            enum: ['wrong_answer', 'typo', 'rendering', 'confusing', 'other'],
            default: 'other',
            index: true
        },
        comment: {
            type: String,
            default: '',
            trim: true
        },
        chapter: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'chapter',
            default: null
        },
        sectionInfo: {
            questionTypeName: { type: String, default: '' },
            subjectName: { type: String, default: '' },
            unitName: { type: String, default: '' },
            chapterName: { type: String, default: '' },
            questionNum: { type: String, default: '' }
        },
        status: {
            type: String,
            enum: ['pending', 'resolved', 'dismissed'],
            default: 'pending',
            index: true
        },
        resolutionNote: {
            type: String,
            default: ''
        },
        resolvedAt: {
            type: Date,
            default: null
        }
    },
    {
        timestamps: true
    }
);

const questionReportModel = mongoose.model('questionReport', questionReportSchema);
module.exports = questionReportModel;
