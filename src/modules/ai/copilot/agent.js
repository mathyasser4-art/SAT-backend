const crypto = require('crypto');
const Anthropic = require('@anthropic-ai/sdk');
const { TOOLS_BY_NAME, TOOL_DEFINITIONS } = require('./tools');
const { validateInput } = require('./validate');
const { ToolError, toResultText } = require('./util');
const { buildSystemPrompt } = require('./prompt');

const MODEL = process.env.COPILOT_MODEL || 'claude-opus-5-5';
const EFFORT = process.env.COPILOT_EFFORT || 'medium';
const MAX_STEPS = 12;
const MAX_JSON_RETRIES = 2;

// Request features that only some models accept
const SUPPORTS_FALLBACKS = ['claude-opus-5-5', 'claude-opus-5', 'claude-sonnet-5-5', 'claude-fable-5-1'];
const SUPPORTS_BLOCK_BINDING = ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-fable-5-1'];

class CopilotError extends Error {}

let client = null;
const getClient = () => {
    if (!process.env.ANTHROPIC_API_KEY) {
        throw new CopilotError('The AI Copilot is not set up yet: ANTHROPIC_API_KEY is missing on the server.');
    }
    if (!client) client = new Anthropic();
    return client;
};

const systemBlocks = new Map();
const systemFor = (brand) => {
    if (!systemBlocks.has(brand)) {
        systemBlocks.set(brand, [{ type: 'text', text: buildSystemPrompt(brand), cache_control: { type: 'ephemeral' } }]);
    }
    return systemBlocks.get(brand);
};

const requestParams = (brand, messages) => {
    const betas = [];
    const params = {
        model: MODEL,
        max_tokens: 16000,
        system: systemFor(brand),
        tools: TOOL_DEFINITIONS,
        messages,
        output_config: { effort: EFFORT },
        // Caches the conversation so far; the system block above caches the shared prefix
        cache_control: { type: 'ephemeral' },
        thinking: { type: 'adaptive' },
    };
    if (SUPPORTS_FALLBACKS.includes(MODEL)) {
        // If a safety classifier declines a request, the API retries it on a fallback model
        betas.push('server-side-fallback-2026-07-01');
        params.fallbacks = 'default';
    }
    if (SUPPORTS_BLOCK_BINDING.includes(MODEL)) {
        // A conversation whose prefix changed (e.g. after a deploy) drops old reasoning instead of failing
        betas.push('thinking-binding-controls-2026-08-01');
        params.thinking.block_binding = { prefix_mismatch_behavior: 'drop_block' };
    }
    if (betas.length) params.betas = betas;
    return params;
};

// One model call, streaming text to the browser as it arrives
const callClaude = async ({ brand, messages, emit, signal, textSoFar }) => {
    for (let attempt = 0; ; attempt++) {
        const stream = getClient().beta.messages.stream(requestParams(brand, messages), { signal });
        stream.on('text', (delta) => emit('text', { delta }));
        try {
            return await stream.finalMessage();
        } catch (err) {
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

const textOf = (message) => message.content.filter(b => b.type === 'text').map(b => b.text).join('\n\n').trim();

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
        const message = await callClaude({ brand, messages: history, emit, signal, textSoFar: () => replyParts.join('\n\n') });
        const assistant = { role: 'assistant', content: message.content };

        if (message.stop_reason === 'refusal') {
            // The partial reply is discarded; the history still ends with the teacher's message
            if (unsaved.length) await save(unsaved);
            return { reply: 'Sorry, I can\'t help with that request.', ui, actions: [], refused: true };
        }

        const text = textOf(message);
        if (text) replyParts.push(text);
        const toolUses = message.content.filter(b => b.type === 'tool_use');
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

// Turns an API failure into a sentence for the teacher
const describeError = (err) => {
    if (err instanceof CopilotError) return err.message;
    if (err instanceof Anthropic.AuthenticationError) return 'The AI key on the server is wrong or was revoked.';
    if (err instanceof Anthropic.PermissionDeniedError) return 'The AI account does not allow this request. Check the API key\'s workspace and billing.';
    if (err instanceof Anthropic.RateLimitError) return 'The AI is getting too many requests right now. Try again in a minute.';
    if (err instanceof Anthropic.APIConnectionError) return 'The server could not reach the AI service. Try again in a moment.';
    if (err instanceof Anthropic.BadRequestError) return `The AI rejected the request: ${err.message}`;
    if (err instanceof Anthropic.APIError && (err.status === 529 || err.status >= 500)) return 'The AI service is busy. Try again in a minute.';
    return `Something went wrong: ${err.message}`;
};

module.exports = { runAgent, describeError, CopilotError, MODEL };
