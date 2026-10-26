const mongoose = require('mongoose')

// Every change the AI Copilot made (or tried to make) on a teacher's behalf.
const copilotAuditSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'user', index: true },
    conversation: { type: mongoose.Schema.Types.ObjectId, ref: 'copilotConversation' },
    tool: String,
    summary: String,
    payload: mongoose.Schema.Types.Mixed,
    ok: Boolean,
    result: String,
}, { timestamps: true })

const copilotAuditModel = mongoose.model('copilotAudit', copilotAuditSchema)
module.exports = copilotAuditModel
