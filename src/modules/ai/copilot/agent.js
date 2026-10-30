const crypto = require('crypto');
const Anthropic = require('@anthropic-ai/sdk');
const { TOOLS_BY_NAME, TOOL_DEFINITIONS } = require('./tools');
const { validateInput } = require('./validate');
const { ToolError, toResultText } = require('./util');
const { buildSystemPrompt } = require('./prompt');
const claude = require('../claudeClient');

const { MODEL } = claude;
const EFFORT = process.env.COPILOT_EFFORT || 'medium';
const MAX_STEPS = 12;
const MAX_JSON_RETRIES = 2;
const MAX_RELAX_RETRIES = 3;

class CopilotError extends Error {}

const getClient = () => {
    if (!claude.isConfigured()) throw new CopilotError(`The AI Copilot is not set up yet: ${claude.notConfiguredMessage()}`);
    return claude.getClient();
};

// Same definitions every time for a given feature set, so the prompt cache prefix holds
const toolsForRequest = () => (claude.features.eagerInputStreaming
    ? TOOL_DEFINITIONS
    : TOOL_DEFINITIONS.map(({ eager_input_streaming, ...tool }) => tool));

const systemBlocks = new Map();
const systemFor = (brand) => {
    if (!systemBlocks.has(brand)) {
        systemBlocks.set(brand, [{ type: 'text', text: buildSystemPrompt(brand), cache_control: { type: 'ephemeral' } }]);
    }
    return systemBlocks.get(brand);
};

const requestParams = (brand, messages) => {
    const betas = [];
    const { features } = claude;
    const params = {
        model: MODEL,
        max_tokens: 16000,
        system: systemFor(brand),
        tools: toolsForRequest(),
        messages,
        thinking: { type: 'adaptive' },
    };
    if (features.effort) params.output_config = { effort: EFFORT };
    // Caches the conversation so far; the system block above caches the shared prefix
    if (features.autoCache) params.cache_control = { type: 'ephemeral' };
    if (features.serverFallbacks) {
        // If a safety classifier declines a request, the API retries it on a fallback model
        // (on Bedrock the client's refusal middleware does this instead)
        betas.push('server-side-fallback-2026-07-01');
        params.fallbacks = 'default';
    }
    if (features.blockBinding) {
        // A conversation whose prefix changed (e.g. after a deploy) drops old reasoning instead of failing
        betas.push('thinking-binding-controls-2026-08-01');
        params.thinking.block_binding = { prefix_mismatch_behavior: 'drop_block' };
    }
    if (betas.length) params.betas = betas;
    return params;
};

// One model call, streaming text to the browser as it arrives
const callClaude = async ({ brand, messages, emit, signal, textSoFar, conversationKey }) => {
    let relaxed = 0;
    for (let attempt = 0; ; attempt++) {
        const used = claude.featuresInUse();
        const stream = getClient().beta.messages.stream(requestParams(brand, messages), claude.requestOptions({ signal }, conversationKey));
        stream.on('text', (delta) => emit('text', { delta }));
        try {
            const message = await stream.finalMessage();
            if (message.stop_reason === 'refusal') claude.forgetFallbackState(conversationKey);
            return message;
        } catch (err) {
            // An optional feature this provider doesn't accept: send the request again without it
            if (relaxed < MAX_RELAX_RETRIES && claude.relaxFor(err, used)) {
                relaxed += 1;
                attempt -= 1;
                continue;
            }
            if (err instanceof Anthropic.APIError) claude.forgetFallbackState(conversationKey);
            // Streamed tool inputs can arrive as JSON the SDK can't parse; only that case is retried
            if (err instanceof Anthropic.APIError || err instanceof Anthropic.APIUserAbortError || attempt >= MAX_JSON_RETRIES) throw err;
            console.warn('Copilot: unreadable tool input, asking again:', err.message);
            emit('text_reset', { text: textSoFar() });
        }
    }
};

const errorResult = (toolUseId, message) => ({ type: 'tool_result', tool_use_id: toolUseId, content: message, is_error: true });

// Runs one turn's tool calls. Reads finish now; writes become actions waiting for the teacher.
const runTools = async (toolUses, ctx, emit) => {
    const results = new Array(toolUses.length);
    const actions = [];
    const ui = [];

    await Promise.all(toolUses.map(async (block, i) => {
        const tool = TOOLS_BY_NAME.get(block.name);
        if (!tool) {
            results[i] = errorResult(block.id, `There is no tool called ${block.name}.`);
            return;
        }
        const problems = validateInput(block.input, tool.input_schema);
        if (problems.length) {
            results[i] = errorResult(block.id, JSON.stringify({ INVALID_INPUT: problems, received: block.input }));
            return;
        }
        emit('status', { text: tool.status(block.input) });
        try {
            if (tool.kind === 'write') {
                const prepared = await tool.prepare(block.input, ctx);
                actions.push({
                    actionId: crypto.randomUUID(),
                    toolUseId: block.id,
                    tool: tool.name,
                    title: prepared.title,
                    summary: prepared.summary,
                    details: prepared.details || [],
                    danger: !!prepared.danger,
                    payload: prepared.payload,
                    status: 'pending',
                });
                results[i] = null; // filled in after the teacher decides
                return;
            }
            const data = await tool.run(block.input, ctx);
            if (data && data.ui) {
                ui.push(data.ui);
                delete data.ui;
            }
            results[i] = { type: 'tool_result', tool_use_id: block.id, content: toResultText(data) };
        } catch (err) {
            if (!(err instanceof ToolError)) console.error(`Copilot tool ${block.name} failed:`, err);
            results[i] = errorResult(block.id, err instanceof ToolError ? err.message : `This failed on the server: ${err.message}`);
        }
    }));

    return { results: results.filter(Boolean), actions, ui };
};

const joinText = (blocks) => blocks.filter(b => b.type === 'text').map(b => b.text).join('\n\n');
const opening = (text) => text.replace(/\s+/g, ' ').trim().toLowerCase().slice(0, 24);

/**
 * On Bedrock a refusal mid-reply is retried on another model by the client's fallback middleware,
 * which marks each switch with a `fallback` block. Only what follows the last switch stands: the
 * refused model's reasoning and tool calls are dropped (the docs say not to echo them back), and the
 * markers are never stored, since they 400 once the middleware is off. The refused model's text is
 * kept in the reply only when the new model continued it rather than starting over.
 */
const settleFallbackSeam = (content) => {
    const seam = content.map(b => b.type).lastIndexOf('fallback');
    if (seam === -1) return { content, text: joinText(content).trim() };
    const before = content.slice(0, seam).filter(b => b.type === 'text' && b.text);
    const after = content.slice(seam + 1).filter(b => b.type !== 'fallback');
    const partial = joinText(before);
    const answer = joinText(after);
    const restarted = !partial.trim() || (answer.trim() !== '' && opening(answer) === opening(partial));
    return { content: [...before, ...after], text: (restarted ? answer : partial + answer).trim() };
};

/**
 * Runs Claude until it answers, or until it proposes changes that need the teacher's decision.
 * `messages` is the conversation so far (not modified). `firstUserMessage` is appended before the
 * first call, or null when the history already ends with a user message (after a confirmation).
 * `save(newMessages, extra)` persists messages appended in this run; it is only called with
 * complete exchanges, so the stored history is always valid even if a later step fails.
 */
const runAgent = async ({ brand, messages, firstUserMessage, ctx, emit, save, signal }) => {
    const history = [...messages];
    let unsaved = [];
    if (firstUserMessage) {
        history.push(firstUserMessage);
        unsaved.push(firstUserMessage);
    }
    const replyParts = [];
    const ui = [];

    for (let step = 0; step < MAX_STEPS; step++) {
        const message = await callClaude({ brand, messages: history, emit, signal, textSoFar: () => replyParts.join('\n\n'), conversationKey: ctx && ctx.conversationId });

        if (message.stop_reason === 'refusal') {
            // The partial reply is discarded; the history still ends with the teacher's message
            if (unsaved.length) await save(unsaved);
            return { reply: 'Sorry, I can\'t help with that request.', ui, actions: [], refused: true };
        }

        const settled = settleFallbackSeam(message.content);
        const assistant = { role: 'assistant', content: settled.content };
        if (settled.text) replyParts.push(settled.text);
        const toolUses = settled.content.filter(b => b.type === 'tool_use');
        history.push(assistant);
        unsaved.push(assistant);

        if (message.stop_reason === 'pause_turn') continue;

        if (toolUses.length === 0) {
            await save(unsaved);
            return { reply: replyParts.join('\n\n'), ui, actions: [], truncated: message.stop_reason === 'max_tokens' };
        }

        if (message.stop_reason === 'max_tokens') {
            // A tool input cut off by the output limit may parse as valid but incomplete; never run it
            const results = toolUses.map(b => errorResult(b.id, 'Your tool call was cut off by the output limit. Try again with a shorter input.'));
            const user = { role: 'user', content: results };
            history.push(user);
            unsaved.push(user);
            continue;
        }

        const ran = await runTools(toolUses, ctx, emit);
        ui.push(...ran.ui);
        ran.ui.forEach(item => emit('ui', item));

        if (ran.actions.length > 0) {
            // Stop here: the history ends with Claude's tool calls until the teacher decides
            await save(unsaved, { heldResults: ran.results, actions: ran.actions });
            return { reply: replyParts.join('\n\n'), ui, actions: ran.actions };
        }

        const user = { role: 'user', content: ran.results };
        history.push(user);
        unsaved.push(user);
        await save(unsaved);
        unsaved = [];
    }

    if (unsaved.length) await save(unsaved);
    return { reply: [...replyParts, 'I stopped here because this took many steps. Tell me to continue if you want me to keep going.'].join('\n\n'), ui, actions: [] };
};

/**
 * Turns an API failure into a sentence for the teacher. Setup problems (missing or refused key, model
 * not enabled) get a short sentence with a code, and the full explanation goes to the server log;
 * `forOperator` returns the full explanation instead (npm run check-ai).
 */
const describeError = (err, { forOperator = false } = {}) => {
    const setup = err instanceof CopilotError ? err.message : claude.describeAccessError(err);
    if (setup) {
        if (forOperator) return setup;
        console.error(`Copilot setup problem (${claude.accessErrorCode(err)}): ${setup}`);
        return `The AI isn't set up correctly on the server yet (code ${claude.accessErrorCode(err)}). Please tell the site admin.`;
    }
    if (err instanceof Anthropic.RateLimitError) return 'The AI is getting too many requests right now. Try again in a minute.';
    if (err instanceof Anthropic.APIConnectionError) return 'The server could not reach the AI service. Try again in a moment.';
    if (err instanceof Anthropic.BadRequestError) return `The AI rejected the request: ${err.message}`;
    if (err instanceof Anthropic.APIError && (err.status === 529 || err.status >= 500)) return 'The AI service is busy. Try again in a minute.';
    return `Something went wrong: ${err.message}`;
};

module.exports = { runAgent, describeError, CopilotError, MODEL };
