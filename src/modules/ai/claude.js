const Anthropic = require('@anthropic-ai/sdk');

// Same model setting as the teacher Copilot, so one Railway variable switches both
const MODEL = process.env.COPILOT_MODEL || 'claude-opus-5-5';
// A student is waiting: each call gives up after this long in total (its one retry and backoff included)
const CALL_DEADLINE_MS = 60 * 1000;

// Models that accept the server-side refusal fallback (keep in sync with copilot/agent.js)
const SUPPORTS_FALLBACKS = ['claude-opus-5-5', 'claude-opus-5', 'claude-sonnet-5-5', 'claude-fable-5-1'];

const isClaudeConfigured = () => Boolean(process.env.ANTHROPIC_API_KEY);

let client = null;
const getClient = () => {
    if (!client) client = new Anthropic();
    return client;
};

/**
 * One-shot Claude call for small server-side jobs (no tools, no history).
 * Returns the reply text, or the parsed object when `schema` (a JSON schema) is given.
 * Throws when Claude is not configured, declines, or the reply is cut off, so callers can fall back.
 */
const askClaude = async ({ system, prompt, schema, maxTokens = 8000 }) => {
    if (!isClaudeConfigured()) throw new Error('ANTHROPIC_API_KEY is missing on the server.');
    const params = {
        model: MODEL,
        // Thinking counts toward this limit, so it is sized above the reply itself
        max_tokens: maxTokens,
        messages: [{ role: 'user', content: prompt }],
        output_config: { effort: 'low' },
    };
    if (system) params.system = system;
    if (schema) params.output_config.format = { type: 'json_schema', schema };
    if (SUPPORTS_FALLBACKS.includes(MODEL)) {
        // If a safety classifier declines the request, the API retries it on a fallback model
        params.betas = ['server-side-fallback-2026-07-01'];
        params.fallbacks = 'default';
    }

    // One retry covers a brief overload. The signal also cuts a long Retry-After wait or a stalled
    // body, which the SDK's per-attempt timeout alone does not
    const deadline = AbortSignal.timeout(CALL_DEADLINE_MS);
    let message;
    try {
        message = await getClient().beta.messages.create(params, { timeout: CALL_DEADLINE_MS, maxRetries: 1, signal: deadline });
    } catch (e) {
        if (deadline.aborted) throw new Error(`Claude did not answer within ${CALL_DEADLINE_MS / 1000}s.`);
        throw e;
    }
    if (message.stop_reason === 'refusal') throw new Error('Claude declined the request.');
    if (message.stop_reason === 'max_tokens') throw new Error('Claude\'s reply was cut off.');

    const text = message.content.filter(b => b.type === 'text').map(b => b.text).join('').trim();
    if (!schema) return text;
    return JSON.parse(text);
};

module.exports = { askClaude, isClaudeConfigured };
