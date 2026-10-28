const mongoose = require('mongoose')

// A cloud recording of a LiveClass. LiveKit Egress records the meeting layout to an MP4 and uploads it
// straight to the S3-compatible bucket (Cloudflare R2); this record is what the course page lists.
const liveRecordingSchema = new mongoose.Schema({
    course: { type: mongoose.Schema.Types.ObjectId, ref: 'course', required: true },
    session: { type: mongoose.Schema.Types.ObjectId, ref: 'liveSession' },
    teacher: { type: mongoose.Schema.Types.ObjectId, ref: 'user' },
    egressId: { type: String, required: true, unique: true },
    title: { type: String },
    fileKey: { type: String, required: true },
    // recording -> processing (stopped, file still uploading) -> ready | failed
    status: { type: String, enum: ['recording', 'processing', 'ready', 'failed'], default: 'recording' },
    startedAt: { type: Date, default: Date.now },
    endedAt: { type: Date },
    duration: { type: Number, default: 0 },
    size: { type: Number, default: 0 },
    error: { type: String }
}, { timestamps: true })

liveRecordingSchema.index({ course: 1, startedAt: -1 })

const liveRecordingModel = mongoose.model('liveRecording', liveRecordingSchema)
module.exports = liveRecordingModel
