const crypto = require('crypto');
const mongoose = require('mongoose');
const conversationModel = require('../../../../DB/models/copilotConversation.model');
const auditModel = require('../../../../DB/models/copilotAudit.model');
const { runAgent, describeError } = require('./agent');
const { TOOLS_BY_NAME } = require('./tools');
const { TeacherScope } = require('./scope');
const { PROMPT_VERSION, resolveBrand } = require('./prompt');
const { ToolError, isId, toResultText } = require('./util');

// A conversation stops growing past this (images make it large); the next message starts a new one
const MAX_CONVERSATION_CHARS = 3000000;
const BUSY_MS = 3 * 60 * 1000;
const IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const MAX_IMAGE_CHARS = 5000000;

// Website pages the Copilot understands, so "this assignment" means the one on screen
const PAGE_PATTERNS = [
    [/^\/teacher\/student\/([a-f0-9]{24})\/history/i, (m) => `Student history page (studentId=${m[1]})`],
    [/^\/teacher\/assignmentReport\/([a-f0-9]{24})\/([a-f0-9]{24})/i, (m) => `One student's answers page (studentId=${m[1]}, assignmentId=${m[2]})`],
    [/^\/assignment\/([a-f0-9]{24})\/reports/i, (m) => `Assignment results page (assignmentId=${m[1]})`],
    [/^\/teacher\/assignment\/([a-f0-9]{24})\/view/i, (m) => `Homework projector view (assignmentId=${m[1]})`],
    [/^\/teacher\/course\/([a-f0-9]{24})\/hw-matrix/i, (m) => `Course homework report (courseId=${m[1]})`],
    [/^\/teacher\/course\/([a-f0-9]{24})\/test-matrix/i, (m) => `Course test report (courseId=${m[1]})`],
    [/^\/teacher\/course\/([a-f0-9]{24})/i, (m) => `Course page (courseId=${m[1]})`],
    [/^\/teacher\/courses/i, () => 'Courses list'],
    [/^\/question\/([a-f0-9]{24})\/([a-f0-9]{24})\/([a-f0-9]{24})/i, (m) => `Question bank chapter (chapterId=${m[1]}, questionTypeId=${m[2]}, subjectId=${m[3]})`],
    [/^\/Unit\/([a-f0-9]{24})\/([a-f0-9]{24})/i, (m) => `Question bank units (questionTypeId=${m[1]}, subjectId=${m[2]})`],
    [/^\/system\/([a-f0-9]{24})/i, (m) => `Question bank subjects (questionTypeId=${m[1]})`],
    [/^\/dashboard\/teacher/i, () => 'Teacher dashboard (classes and assignments)'],
    [/^\/dashboard-school/i, () => 'School dashboard'],
    [/^\/dashboard\/supervisor/i, () => 'Supervisor dashboard'],
];

const describePage = (page) => {
    const path = typeof page?.path === 'string' ? page.path.slice(0, 300) : '';
    if (!path) return 'unknown';
    const match = PAGE_PATTERNS.find(([re]) => re.test(path));
    const known = match ? match[1](path.match(match[0])) : 'another page';
    const title = typeof page.title === 'string' && page.title.trim() ? ` — "${page.title.trim().slice(0, 120)}"` : '';
    return `${known}${title} [${path}]`;
};

const contextBlock = (user, page) => {
    const now = new Date();
    const day = now.toLocaleDateString('en-US', { weekday: 'long', timeZone: 'UTC' });
    return `<context>\nToday: ${now.toISOString().slice(0, 10)} (${day})\nTeacher: ${user.userName || 'Teacher'} (${user.role})\nPage: ${describePage(page)}\n</context>`;
};

const imageBlock = (dataUrl) => {
    const match = typeof dataUrl === 'string' && dataUrl.match(/^data:([a-z/+]+);base64,([A-Za-z0-9+/=]+)$/);
    if (!match || !IMAGE_TYPES.includes(match[1])) throw new ToolError('Attach a JPG, PNG, GIF or WebP image.');
    if (match[2].length > MAX_IMAGE_CHARS) throw new ToolError('That image is too large. Try a smaller screenshot.');
    return { type: 'image', source: { type: 'base64', media_type: match[1], data: match[2] } };
};

// Server-sent events: the chat window shows progress and text while Claude works
const openStream = (res) => {
    res.status(200).set({
        'Content-Type': 'text/event-stream; charset=utf-8',
        // no-transform keeps the compression middleware from buffering the stream
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
    });
    res.flushHeaders();
    return (event, data) => {
        if (res.writableEnded) return;
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
        if (typeof res.flush === 'function') res.flush();
    };
};

const parseMessages = (conv) => conv.messages.map(m => JSON.parse(m));

// Locks the conversation so two requests can't run Claude on it at once
const lockConversation = async (conversationId, userId) => {
    const now = new Date();
    return conversationModel.findOneAndUpdate(
        { _id: conversationId, user: userId, $or: [{ busyUntil: null }, { busyUntil: { $lt: now } }] },
        { $set: { busyUntil: new Date(now.getTime() + BUSY_MS) } },
        { new: true }
    );
};

const unlock = (conversationId) => conversationModel.updateOne({ _id: conversationId }, { $set: { busyUntil: null } }).catch(() => {});

// Appends messages (and optionally pending actions) to the stored conversation
const makeSaver = (conv) => async (newMessages, extra = {}) => {
    newMessages.forEach(m => {
        const json = JSON.stringify(m);
        conv.messages.push(json);
        conv.messagesSize += json.length;
    });
    if (extra.actions) {
        conv.heldResults = extra.heldResults.map(r => JSON.stringify(r));
        extra.actions.forEach(a => conv.actions.push(a));
    }
    await conv.save();
};

const publicAction = (a) => ({
    actionId: a.actionId, tool: a.tool, title: a.title, summary: a.summary, details: a.details,
    danger: !!a.danger, status: a.status, resultText: a.status === 'pending' ? undefined : a.resultText,
});

const displayEntry = (role, fields) => ({ id: crypto.randomUUID(), role, at: new Date().toISOString(), ...fields });

// Runs Claude on a locked conversation and reports the outcome on the stream
const runAndReport = async ({ conv, firstUserMessage, user, brand, send, signal }) => {
    const ctx = { user, scope: new TeacherScope(user), brand, conversationId: conv._id };
    const result = await runAgent({
        brand,
        messages: parseMessages(conv),
        firstUserMessage,
        ctx,
        emit: send,
        save: makeSaver(conv),
        signal,
    });
    const entry = displayEntry('assistant', {
        text: result.reply,
        actionIds: result.actions.map(a => a.actionId),
        ui: result.ui,
    });
    conv.display.push(entry);
    conv.markModified('display');
    await conv.save();
    send('done', {
        conversationId: String(conv._id),
        message: { ...entry, actions: result.actions.map(publicAction) },
    });
};

const failStream = (send, err) => {
    if (!(err instanceof ToolError)) console.error('Copilot error:', err);
    send('error', { message: err instanceof ToolError ? err.message : describeError(err) });
};

// Starts a fresh conversation when there is none, it belongs to an older prompt, or it grew too big
const pickConversation = async ({ conversationId, user, brand }) => {
    if (isId(conversationId)) {
        const existing = await conversationModel.findOne({ _id: conversationId, user: user._id }).select('promptVersion brand messagesSize');
        if (existing && existing.promptVersion === PROMPT_VERSION && existing.brand === brand && existing.messagesSize < MAX_CONVERSATION_CHARS) {
            return { id: existing._id, isNew: false };
        }
    }
    const created = await conversationModel.create({ user: user._id, brand, promptVersion: PROMPT_VERSION });
    return { id: created._id, isNew: true };
};

const chat = async (req, res) => {
    const user = req.userData;
    const { message, image, page, conversationId } = req.body || {};
    const text = typeof message === 'string' ? message.trim().slice(0, 8000) : '';
    if (!text && !image) return res.status(400).json({ message: 'Write a message or attach an image.' });
    if (mongoose.connection.readyState !== 1) return res.status(503).json({ message: 'The database is not connected right now.' });

    const brand = resolveBrand(String(req.body?.brand || '').toLowerCase());
    let picked;
    let conv;
    try {
        picked = await pickConversation({ conversationId, user, brand });
        conv = await lockConversation(picked.id, user._id);
    } catch (err) {
        return res.status(500).json({ message: err.message });
    }
    if (!conv) return res.status(409).json({ message: 'I am still working on your previous message.' });

    const abort = new AbortController();
    res.on('close', () => { if (!res.writableEnded) abort.abort(); });
    const send = openStream(res);
    send('conversation', { conversationId: String(conv._id), isNew: picked.isNew });

    try {
        const content = [];
        // Changes the teacher never answered are dropped: Claude learns they were not done
        const waiting = conv.actions.filter(a => a.status === 'pending');
        if (waiting.length) {
            conv.heldResults.forEach(r => content.push(JSON.parse(r)));
            waiting.forEach(a => {
                a.status = 'expired';
                a.resultText = 'Not done: the teacher sent a new message instead of confirming.';
                content.push({ type: 'tool_result', tool_use_id: a.toolUseId, content: a.resultText, is_error: true });
                send('action_update', publicAction(a));
            });
            conv.heldResults = [];
        }
        content.push({ type: 'text', text: `${contextBlock(user, page)}\n\n${text || 'Please look at the attached image.'}` });
        if (image) content.push(imageBlock(image));

        if (conv.display.length === 0) conv.title = (text || 'Image question').slice(0, 60);
        conv.display.push(displayEntry('user', { text, hasImage: !!image }));
        conv.markModified('display');

        await runAndReport({ conv, firstUserMessage: { role: 'user', content }, user, brand, send, signal: abort.signal });
    } catch (err) {
        failStream(send, err);
    } finally {
        await unlock(conv._id);
        res.end();
    }
};

const decide = async (req, res) => {
    const user = req.userData;
    const { actionId } = req.params;
    const { conversationId, decision } = req.body || {};
    if (!isId(conversationId) || !['confirm', 'cancel'].includes(decision)) {
        return res.status(400).json({ message: 'Send the conversationId and a decision of confirm or cancel.' });
    }
    const conv = await lockConversation(conversationId, user._id);
    if (!conv) return res.status(409).json({ message: 'This chat is busy or does not exist.' });
    const action = conv.actions.find(a => a.actionId === actionId);
    if (!action || action.status !== 'pending') {
        await unlock(conv._id);
        return res.status(409).json({ message: 'This change was already handled.', action: action ? publicAction(action) : null });
    }

    const abort = new AbortController();
    res.on('close', () => { if (!res.writableEnded) abort.abort(); });
    const send = openStream(res);
    const brand = conv.brand || 'satarea';

    try {
        const ctx = { user, scope: new TeacherScope(user), brand, conversationId: conv._id };
        if (decision === 'cancel') {
            action.status = 'cancelled';
            action.resultText = 'The teacher cancelled this. Nothing was changed.';
        } else {
            action.status = 'executing';
            await conv.save();
            send('status', { text: 'Saving the change' });
            const tool = TOOLS_BY_NAME.get(action.tool);
            try {
                const outcome = await tool.execute(action.payload, ctx);
                action.status = 'done';
                action.resultText = toResultText(outcome);
            } catch (err) {
                if (!(err instanceof ToolError)) console.error(`Copilot action ${action.tool} failed:`, err);
                action.status = 'failed';
                action.resultText = `It failed: ${err.message}`;
            }
            auditModel.create({
                user: user._id, conversation: conv._id, tool: action.tool, summary: `${action.title}: ${action.summary}`,
                payload: action.payload, ok: action.status === 'done', result: action.resultText,
            }).catch(err => console.error('Copilot audit log failed:', err.message));
        }
        conv.markModified('actions');
        await conv.save();
        send('action_update', publicAction(action));

        // Claude continues only once every change from that step has an answer
        if (conv.actions.some(a => a.status === 'pending')) {
            send('done', { conversationId: String(conv._id), waiting: true });
            return;
        }
        const answered = new Set(conv.actions.filter(a => ['done', 'failed', 'cancelled'].includes(a.status)).map(a => a.toolUseId));
        const lastAssistant = JSON.parse(conv.messages[conv.messages.length - 1]);
        const pendingIds = lastAssistant.role === 'assistant'
            ? lastAssistant.content.filter(b => b.type === 'tool_use').map(b => b.id)
            : [];
        const results = conv.heldResults.map(r => JSON.parse(r));
        conv.actions.filter(a => pendingIds.includes(a.toolUseId) && answered.has(a.toolUseId)).forEach(a => {
            results.push({ type: 'tool_result', tool_use_id: a.toolUseId, content: a.resultText, ...(a.status === 'done' ? {} : { is_error: a.status === 'failed' }) });
        });
        conv.heldResults = [];
        // The outcome is stored before asking Claude, so a failure below can't lose what was done
        await makeSaver(conv)([{ role: 'user', content: results }]);
        await runAndReport({ conv, firstUserMessage: null, user, brand, send, signal: abort.signal });
    } catch (err) {
        failStream(send, err);
    } finally {
        await unlock(conv._id);
        res.end();
    }
};

const listConversations = async (req, res) => {
    try {
        const rows = await conversationModel.find({ user: req.userData._id })
            .select('title updatedAt promptVersion').sort({ updatedAt: -1 }).limit(30).lean();
        res.json({ message: 'success', conversations: rows.map(r => ({ conversationId: String(r._id), title: r.title, updatedAt: r.updatedAt, canContinue: r.promptVersion === PROMPT_VERSION })) });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

const getConversation = async (req, res) => {
    try {
        const { conversationId } = req.params;
        if (!isId(conversationId)) return res.status(400).json({ message: 'Invalid conversation id.' });
        const conv = await conversationModel.findOne({ _id: conversationId, user: req.userData._id }).select('title display actions promptVersion').lean();
        if (!conv) return res.status(404).json({ message: 'Conversation not found.' });
        const actionsById = new Map((conv.actions || []).map(a => [a.actionId, publicAction(a)]));
        res.json({
            message: 'success',
            conversation: {
                conversationId,
                title: conv.title,
                canContinue: conv.promptVersion === PROMPT_VERSION,
                messages: (conv.display || []).map(m => ({ ...m, actions: (m.actionIds || []).map(id => actionsById.get(id)).filter(Boolean) })),
            },
        });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

module.exports = { chat, decide, listConversations, getConversation };
