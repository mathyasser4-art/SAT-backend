const mongoose = require('mongoose')

// One logged-in device of an account (see src/services/sessions.js)
const sessionSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true },
    // Random id the browser keeps in localStorage (x-device-id header); falls back to a hash of the browser
    deviceId: { type: String, required: true },
    deviceName: String,
    userAgent: String,
    ip: String,
    // Tokens issued before sessions existed are adopted on first use, matched by this hash
    legacyTokenHash: { type: String, index: { unique: true, sparse: true } },
    lastSeenAt: { type: Date, default: Date.now },
    endedAt: { type: Date, default: null },
    // 'logout', 'device-limit' (a newer device logged in), 'staff' (logged out by a teacher/admin)
    endedReason: String,
}, { timestamps: true })

sessionSchema.index({ user: 1, endedAt: 1, lastSeenAt: -1 })

module.exports = mongoose.model('session', sessionSchema)
