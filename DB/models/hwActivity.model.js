const mongoose = require('mongoose')

// Which device opened, answered or submitted a homework trial (see src/services/sessions.js)
const hwActivitySchema = new mongoose.Schema({
    student: { type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true },
    assignment: { type: mongoose.Schema.Types.ObjectId, ref: 'assignment', required: true },
    attemptNumber: { type: Number, default: 1 },
    // 'open', 'answer' (first answer saved from this device in this trial) or 'submit'
    action: { type: String, required: true },
    session: { type: mongoose.Schema.Types.ObjectId, ref: 'session' },
    deviceId: String,
    deviceName: String,
    ip: String,
    at: { type: Date, default: Date.now },
})

hwActivitySchema.index({ assignment: 1, student: 1, at: 1 })

module.exports = mongoose.model('hwActivity', hwActivitySchema)
