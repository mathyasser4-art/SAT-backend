const mongoose = require('mongoose')

const sessionSchema = new mongoose.Schema({
    title: { type: String, required: true },
    date: { type: Date },
    explanationVideoUrl: { type: String },
    recordingUrl: { type: String },
    pdfExercises: [{ type: String }],
    onlineHw: [{ type: mongoose.Schema.Types.ObjectId, ref: 'assignment' }],
    order: { type: Number, required: true }
})

const progressSchema = new mongoose.Schema({
    studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'user' },
    completedSessions: [{ type: mongoose.Schema.Types.ObjectId }] // session IDs
})

const courseSchema = new mongoose.Schema({
    name: { type: String, required: [true, 'Course name is required'] },
    description: { type: String },
    teacher: { type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true },
    students: [{ type: mongoose.Schema.Types.ObjectId, ref: 'user' }], 
    sessions: [sessionSchema],
    progress: [progressSchema],
    isActive: { type: Boolean, default: true }
}, { timestamps: true })

const courseModel = mongoose.model('course', courseSchema)
module.exports = courseModel
