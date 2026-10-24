const mongoose = require('mongoose')

// One video list per scope: "brand:<name>" for a branded academy site
// (e.g. brand:mrshahin) or "teacher:<userId>" for an individual teacher.
const featuredVideoSchema = new mongoose.Schema({
    scope: {
        type: String,
        required: true,
        unique: true
    },
    videos: [
        {
            id: String,
            title: String,
            youtubeUrl: String,
            tag: String,
            duration: String
        }
    ],
    updatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "user"
    }
}, {
    timestamps: true
})

const featuredVideoModel = mongoose.model('featuredVideo', featuredVideoSchema)
module.exports = featuredVideoModel
