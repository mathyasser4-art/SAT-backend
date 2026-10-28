const mongoose = require('mongoose')

// The shareable guest link of a course's LiveClass (/live/join/<token>). One per course, so a
// teacher can send it before a trial lesson starts; turning it off or resetting it stops old links.
const liveGuestLinkSchema = new mongoose.Schema({
    course: { type: mongoose.Schema.Types.ObjectId, ref: 'course', required: true, unique: true },
    token: { type: String, required: true, unique: true },
    enabled: { type: Boolean, default: true }
}, { timestamps: true })

const liveGuestLinkModel = mongoose.model('liveGuestLink', liveGuestLinkSchema)
module.exports = liveGuestLinkModel
