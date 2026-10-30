const Anthropic = require('@anthropic-ai/sdk');

// Claude is reached either directly (ANTHROPIC_API_KEY) or through Amazon Bedrock
// (AWS_BEARER_TOKEN_BEDROCK, or AWS access keys, plus AWS_REGION). Bedrock serves the same Messages
// API at bedrock-mantle.<region>.api.aws/anthropic, with `anthropic.`-prefixed model ids and a few
// features missing, so callers ask this module which request options they may send.
// AI_PROVIDER=anthropic|bedrock picks one when both are configured (direct wins otherwise).

const hasBedrockCredentials = () => Boolean(process.env.AWS_BEARER_TOKEN_BEDROCK
    || (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY));
const bedrockRegion = () => process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || '';

const resolveProvider = () => {
    const forced = String(process.env.AI_PROVIDER || '').trim().toLowerCase();
    if (forced === 'anthropic' || forced === 'bedrock') return forced;
    if (process.env.ANTHROPIC_API_KEY) return 'anthropic';
    if (hasBedrockCredentials()) return 'bedrock';
    return null;
};

const PROVIDER = resolveProvider();
const PROVIDER_NAME = PROVIDER === 'bedrock' ? 'Amazon Bedrock' : 'the Claude API';

// COPILOT_MODEL may be written with or without a prefix ("claude-opus-5-5", "anthropic.claude-opus-5-5").
// Claude in Amazon Bedrock only takes `anthropic.<model>`, so other prefixes (the legacy integration's
// "global." / "eu." inference profiles) are rewritten. Feature checks use the plain name.
const CONFIGURED_MODEL = String(process.env.COPILOT_MODEL || 'claude-opus-5-5').trim();
const PLAIN_MODEL = CONFIGURED_MODEL.toLowerCase().replace(/^([a-z]+\.)?anthropic\./, '');
const MODEL = PROVIDER === 'bedrock' ? `anthropic.${PLAIN_MODEL}` : PLAIN_MODEL;
if (CONFIGURED_MODEL !== MODEL && CONFIGURED_MODEL !== PLAIN_MODEL) {
    console.warn(`Claude: COPILOT_MODEL "${CONFIGURED_MODEL}" is sent as "${MODEL}" on ${PROVIDER_NAME}.`);
}

// Models whose safety classifiers can decline a request, and the ones with block-binding controls
const REFUSAL_MODELS = ['claude-opus-5-5', 'claude-opus-5', 'claude-sonnet-5-5', 'claude-fable-5-1'];
const BLOCK_BINDING_MODELS = ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-fable-5-1'];
// Bedrock has no server-side `fallbacks`; the SDK middleware retries a refusal on this model instead
const BEDROCK_FALLBACK_MODEL = 'anthropic.claude-opus-4-8';

// Optional request features. Each one can be switched off for the rest of the process if the
// provider rejects it (see relaxFor), so one unsupported extra can't break every request.
const features = {
    serverFallbacks: PROVIDER === 'anthropic' && REFUSAL_MODELS.includes(PLAIN_MODEL),
    refusalMiddleware: PROVIDER === 'bedrock' && REFUSAL_MODELS.includes(PLAIN_MODEL),
    blockBinding: BLOCK_BINDING_MODELS.includes(PLAIN_MODEL),
    // Bedrock accepts this field only on part of its serving stack; tool inputs here are small anyway
    eagerInputStreaming: PROVIDER === 'anthropic',
    autoCache: true,
    effort: true,
};

const isConfigured = () => {
    if (PROVIDER === 'anthropic') return Boolean(process.env.ANTHROPIC_API_KEY);
    if (PROVIDER === 'bedrock') return hasBedrockCredentials() && Boolean(bedrockRegion());
    return false;
};

const notConfiguredMessage = () => {
    if (PROVIDER === 'bedrock' && !bedrockRegion()) return 'Amazon Bedrock is set up without a region: AWS_REGION is missing on the server.';
    if (PROVIDER === 'bedrock') return 'Amazon Bedrock is selected but AWS_BEARER_TOKEN_BEDROCK is missing on the server.';
    if (PROVIDER === 'anthropic') return 'ANTHROPIC_API_KEY is missing on the server.';
    return 'No Claude access is set up on the server: add ANTHROPIC_API_KEY, or AWS_BEARER_TOKEN_BEDROCK with AWS_REGION.';
};

let client = null;
const getClient = () => {
    if (!isConfigured()) throw new Error(notConfiguredMessage());
    if (!client) {
        if (PROVIDER === 'bedrock') {
            // Loaded only here: the package's main entry also pulls in the legacy Bedrock client and its AWS SDK
            const { AnthropicBedrockMantle } = require('@anthropic-ai/bedrock-sdk/mantle-client');
            // Region and credentials come from AWS_REGION and AWS_BEARER_TOKEN_BEDROCK (or AWS keys)
            const middleware = features.refusalMiddleware
                ? [Anthropic.betaRefusalFallbackMiddleware([{ model: BEDROCK_FALLBACK_MODEL }])]
                : [];
            client = new AnthropicBedrockMantle({ middleware });
        } else {
            client = new Anthropic();
        }
    }
    return client;
};

// After a refusal moves a conversation to the fallback model, its next requests should start there
// too. The middleware remembers that in a BetaFallbackState, kept here per conversation.
const MAX_FALLBACK_STATES = 500;
const fallbackStates = new Map();
const fallbackStateFor = (key) => {
    if (!features.refusalMiddleware) return undefined;
    if (!key) return new Anthropic.BetaFallbackState();
    const id = String(key);
    if (!fallbackStates.has(id)) {
        if (fallbackStates.size >= MAX_FALLBACK_STATES) fallbackStates.delete(fallbackStates.keys().next().value);
        fallbackStates.set(id, new Anthropic.BetaFallbackState());
    }
    return fallbackStates.get(id);
};

// Per-request options: the fallback state only when the middleware is in use
const requestOptions = (options = {}, conversationKey = null) => {
    const fallbackState = fallbackStateFor(conversationKey);
    return fallbackState ? { ...options, fallbackState } : options;
};

// The middleware pins a conversation to the fallback model before that model has answered. If the
// fallback then failed or the turn still ended in a refusal, unpin it so the next message starts over.
const forgetFallbackState = (conversationKey) => {
    if (conversationKey) fallbackStates.delete(String(conversationKey));
};

// The optional features a request is about to be built with, for relaxFor
const featuresInUse = () => ({ ...features });

// What a 400 has to mention for each optional feature to be the culprit, most specific first
const CULPRITS = [
    ['refusalMiddleware', ['fallback-credit', 'fallback_credit']],
    ['serverFallbacks', ['server-side-fallback', 'fallbacks']],
    ['blockBinding', ['block_binding', 'thinking-binding']],
    ['eagerInputStreaming', ['eager_input_streaming']],
    ['effort', ['effort']],
    ['autoCache', ['cache_control']],
];

/**
 * When the provider rejects a request because of one of the optional features it was sent with
 * (`used`, from featuresInUse() before the request was built), switches that feature off for good and
 * returns true so the caller can retry. Also true when a parallel request already switched it off.
 */
const relaxFor = (err, used = features) => {
    if (!(err instanceof Anthropic.BadRequestError)) return false;
    const text = String(err.message || '').toLowerCase();
    const found = CULPRITS.find(([key, words]) => used[key] && words.some(w => text.includes(w)));
    if (!found) return false;
    const [key] = found;
    if (features[key]) {
        features[key] = false;
        if (key === 'refusalMiddleware') client = null;
        console.warn(`Claude via ${PROVIDER_NAME}: turned off "${key}" after this rejection: ${err.message}`);
    }
    return true;
};

// Short code teachers can pass on to the admin, e.g. "bedrock-403"
const accessErrorCode = (err) => `${PROVIDER || 'ai'}-${(err && err.status) || 'setup'}`;

// Sentences for access problems, specific to how Claude is reached. Meant for the site admin
// (server log, npm run check-ai), not for teachers: they name variables, the region and the model.
const describeAccessError = (err) => {
    const bedrock = PROVIDER === 'bedrock';
    if (err instanceof Anthropic.AuthenticationError) {
        return bedrock
            ? 'Amazon Bedrock refused the key: AWS_BEARER_TOKEN_BEDROCK on the server is wrong or expired.'
            : 'The AI key on the server is wrong or was revoked.';
    }
    if (err instanceof Anthropic.PermissionDeniedError) {
        return bedrock
            ? `Amazon Bedrock does not allow this yet. In the AWS console (region ${bedrockRegion() || 'not set'}), open Bedrock → Model access and make sure ${MODEL} is enabled, and that the key's user may call Bedrock. Or set COPILOT_MODEL=claude-opus-4-8, which Amazon Bedrock opens to all customers.`
            : 'The AI account does not allow this request. Check the API key\'s workspace and billing.';
    }
    if (err instanceof Anthropic.NotFoundError && bedrock) {
        return `Amazon Bedrock can't find ${MODEL} in region ${bedrockRegion()}. Check COPILOT_MODEL and AWS_REGION.`;
    }
    return null;
};

module.exports = {
    PROVIDER, PROVIDER_NAME, MODEL, PLAIN_MODEL, features,
    isConfigured, notConfiguredMessage, getClient, requestOptions, forgetFallbackState, featuresInUse,
    relaxFor, describeAccessError, accessErrorCode, bedrockRegion,
};
