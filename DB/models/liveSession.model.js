const mongoose = require('mongoose')

// One LiveClass meeting of a course. The video itself runs on LiveKit; this record is what the
// API checks before handing out a room token (who may join, waiting room, lock, removals).
const liveSessionSchema = new mongoose.Schema({
    course: { type: mongoose.Schema.Types.ObjectId, ref: 'course', required: true },
    teacher: { type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true },
    roomName: { type: String, required: true },
    status: { type: String, enum: ['live', 'ended'], default: 'live' },
    startedAt: { type: Date, default: Date.now },
    endedAt: { type: Date },
    locked: { type: Boolean, default: false },
    waitingRoom: { type: Boolean, default: true },
    allowShare: { type: Boolean, default: false },
    spotlight: { type: String, default: '' },
    waiting: [{
        user: { type: mongoose.Schema.Types.ObjectId, ref: 'user' },
        name: { type: String },
        requestedAt: { type: Date, default: Date.now }
    }],
    admitted: [{ type: mongoose.Schema.Types.ObjectId, ref: 'user' }],
    removed: [{ type: mongoose.Schema.Types.ObjectId, ref: 'user' }],
    // People who came in through the guest link. They have no account, so they are tracked here by
    // their LiveKit identity ("guest-…") and a secret only their browser knows (stored hashed).
    guests: [{
        identity: { type: String, required: true },
        name: { type: String, required: true },
        secretHash: { type: String, required: true },
        status: { type: String, enum: ['waiting', 'admitted', 'removed'], default: 'waiting' },
        requestedAt: { type: Date, default: Date.now }
    }]
}, { timestamps: true })

liveSessionSchema.index({ course: 1, status: 1 })

const liveSessionModel = mongoose.model('liveSession', liveSessionSchema)
module.exports = liveSessionModel
