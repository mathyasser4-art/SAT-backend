const mongoose = require('mongoose')

// One AI Copilot chat thread for one teacher.
// `messages` holds the exact Claude API messages, each JSON-encoded, and is only ever appended to:
// Claude rejects a history whose earlier turns were edited.
// `display` is the simplified copy the chat window shows.
// `actions` keeps every change Claude proposed; the ones still 'pending' wait for Confirm / Cancel.
const actionSchema = new mongoose.Schema({
    actionId: { type: String, required: true },
    toolUseId: { type: String, required: true },
    tool: { type: String, required: true },
    title: String,
    summary: String,
    details: [String],
    danger: Boolean,
    payload: mongoose.Schema.Types.Mixed,
    status: {
        type: String,
        enum: ['pending', 'executing', 'done', 'failed', 'cancelled', 'expired'],
        default: 'pending'
    },
    resultText: String,
}, { _id: false })

const copilotConversationSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true, index: true },
    title: { type: String, default: 'New chat' },
    brand: String,
    promptVersion: String,
    messages: { type: [String], default: [] },
    messagesSize: { type: Number, default: 0 },
    display: { type: [mongoose.Schema.Types.Mixed], default: [] },
    // Tool results that finished while write actions wait for the teacher's decision
    heldResults: { type: [String], default: [] },
    actions: { type: [actionSchema], default: [] },
    busyUntil: { type: Date, default: null },
}, { timestamps: true })

const copilotConversationModel = mongoose.model('copilotConversation', copilotConversationSchema)
module.exports = copilotConversationModel
