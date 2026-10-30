const claude = require('./claudeClient');

// A student is waiting: each call gives up after this long in total (its one retry and backoff included)
const CALL_DEADLINE_MS = 60 * 1000;
const MAX_RELAX_RETRIES = 3;

// Same Claude access and model setting as the teacher Copilot, so one set of Railway variables switches both
const isClaudeConfigured = () => claude.isConfigured();

/**
 * One-shot Claude call for small server-side jobs (no tools, no history).
 * Returns the reply text, or the parsed object when `schema` (a JSON schema) is given.
 * Throws when Claude is not configured, declines, or the reply is cut off, so callers can fall back.
 */
const askClaude = async ({ system, prompt, schema, maxTokens = 8000 }) => {
    if (!isClaudeConfigured()) throw new Error(claude.notConfiguredMessage());

    const buildParams = () => {
        const params = {
            model: claude.MODEL,
            // Thinking counts toward this limit, so it is sized above the reply itself
            max_tokens: maxTokens,
            messages: [{ role: 'user', content: prompt }],
        };
        if (claude.features.effort) params.output_config = { effort: 'low' };
        if (system) params.system = system;
        if (schema) params.output_config = { ...(params.output_config || {}), format: { type: 'json_schema', schema } };
        if (claude.features.serverFallbacks) {
            // If a safety classifier declines the request, the API retries it on a fallback model
            // (on Bedrock the client's refusal middleware does this instead)
            params.betas = ['server-side-fallback-2026-07-01'];
            params.fallbacks = 'default';
        }
        return params;
    };

    // One retry covers a brief overload. The signal also cuts a long Retry-After wait or a stalled
    // body, which the SDK's per-attempt timeout alone does not
    const deadline = AbortSignal.timeout(CALL_DEADLINE_MS);
    let message;
    for (let relaxed = 0; ; relaxed++) {
        const used = claude.featuresInUse();
        try {
            message = await claude.getClient().beta.messages.create(buildParams(), claude.requestOptions({ timeout: CALL_DEADLINE_MS, maxRetries: 1, signal: deadline }));
            break;
        } catch (e) {
            if (deadline.aborted) throw new Error(`Claude did not answer within ${CALL_DEADLINE_MS / 1000}s.`);
            // An optional feature this provider doesn't accept: send the request again without it
            if (relaxed < MAX_RELAX_RETRIES && claude.relaxFor(e, used)) continue;
            throw e;
        }
    }
    if (message.stop_reason === 'refusal') throw new Error('Claude declined the request.');
    if (message.stop_reason === 'max_tokens') throw new Error('Claude\'s reply was cut off.');

    const text = message.content.filter(b => b.type === 'text').map(b => b.text).join('').trim();
    if (!schema) return text;
    return JSON.parse(text);
};

module.exports = { askClaude, isClaudeConfigured };
