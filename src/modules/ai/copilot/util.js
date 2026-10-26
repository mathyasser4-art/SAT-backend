const mongoose = require('mongoose');

// Error a tool throws when the request can't be done as asked. Its message goes back to Claude.
class ToolError extends Error {}

const isId = (value) => typeof value === 'string' && mongoose.Types.ObjectId.isValid(value) && /^[a-f0-9]{24}$/i.test(value);

const escapeRegex = (text) => String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Case-insensitive "contains" match that is safe for any user text
const containsRegex = (text) => ({ $regex: escapeRegex(String(text).trim()), $options: 'i' });

// Strips HTML and turns Quill formulas into $...$ so question text reads cleanly
const cleanHtml = (html) => {
    if (!html) return '';
    return String(html)
        .replace(/<span[^>]*class="ql-formula"[^>]*data-value="([^"]+)"[^>]*>[\s\S]*?<\/span>/gi, '$$$1$$')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/gi, ' ')
        .replace(/&amp;/gi, '&')
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/&ge;/gi, '≥')
        .replace(/&le;/gi, '≤')
        .replace(/\s+/g, ' ')
        .trim();
};

const shorten = (text, max = 160) => {
    const clean = cleanHtml(text);
    return clean.length > max ? `${clean.slice(0, max)}…` : clean;
};

const MAX_RESULT_CHARS = 14000;

// Serializes a tool result for Claude, cutting long arrays so one call can't flood the context
const toResultText = (data) => {
    let text = JSON.stringify(data);
    if (text.length <= MAX_RESULT_CHARS) return text;

    const trimmed = JSON.parse(text);
    const cutArrays = (node, keep) => {
        if (Array.isArray(node)) {
            const kept = node.slice(0, keep).map(item => cutArrays(item, keep));
            if (node.length > keep) kept.push(`… ${node.length - keep} more not shown — narrow the request to see them`);
            return kept;
        }
        if (node && typeof node === 'object') {
            Object.keys(node).forEach(key => { node[key] = cutArrays(node[key], keep); });
        }
        return node;
    };
    for (const keep of [60, 30, 15, 8]) {
        text = JSON.stringify(cutArrays(JSON.parse(JSON.stringify(trimmed)), keep));
        if (text.length <= MAX_RESULT_CHARS) return text;
    }
    return `${text.slice(0, MAX_RESULT_CHARS)}… (cut off)`;
};

const today = () => new Date().toISOString().slice(0, 10);

const addDays = (isoDate, days) => {
    const d = new Date(`${isoDate}T00:00:00Z`);
    d.setUTCDate(d.getUTCDate() + days);
    return d.toISOString().slice(0, 10);
};

const isIsoDate = (value) => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && !isNaN(new Date(value));

const requireDb = () => {
    if (mongoose.connection.readyState !== 1) throw new ToolError('The database is not connected right now. Try again in a minute.');
};

module.exports = { ToolError, isId, escapeRegex, containsRegex, cleanHtml, shorten, toResultText, today, addDays, isIsoDate, requireDb };
