// Checks that this server can reach Claude with its current settings: `npm run check-ai`.
// Run it where the real variables are set (on Railway: inside the service). Prints no secrets.
// It sends the two kinds of request the site makes: the students' one-shot call and a Copilot turn
// (streamed, with every tool), and says if the provider made it switch any optional feature off.
require('dotenv').config();
const claude = require('../modules/ai/claudeClient');
const { askClaude } = require('../modules/ai/claude');
const { runAgent, describeError } = require('../modules/ai/copilot/agent');

const seconds = (since) => `${((Date.now() - since) / 1000).toFixed(1)}s`;

const step = async (label, run) => {
    const started = Date.now();
    try {
        const reply = await run();
        console.log(`${label}: WORKS in ${seconds(started)} — Claude replied "${String(reply).slice(0, 40)}"`);
        return true;
    } catch (err) {
        console.log(`${label}: FAILED — ${describeError(err, { forOperator: true })}${err.status ? ` (HTTP ${err.status})` : ''}`);
        return false;
    }
};

(async () => {
    console.log(`Provider: ${claude.PROVIDER ? claude.PROVIDER_NAME : 'none'}`);
    console.log(`Model:    ${claude.MODEL}`);
    if (claude.PROVIDER === 'bedrock') console.log(`Region:   ${claude.bedrockRegion() || '(missing)'}`);
    if (!claude.isConfigured()) {
        console.log(`NOT READY: ${claude.notConfiguredMessage()}`);
        process.exit(1);
    }

    const before = claude.featuresInUse();
    const tutor = await step('Students\' AI analysis', () => askClaude({ prompt: 'Reply with exactly: OK', maxTokens: 2000 }));
    const copilot = await step('Teacher Copilot', async () => {
        const result = await runAgent({
            brand: 'satarea',
            messages: [],
            firstUserMessage: { role: 'user', content: 'This is a connection test. Reply with exactly: OK. Do not use any tool.' },
            ctx: {},
            emit: () => {},
            save: async () => {},
        });
        return result.reply;
    });

    const switchedOff = Object.keys(before).filter(key => before[key] && !claude.features[key]);
    if (switchedOff.length) console.log(`Note: the provider rejected these optional features, so they are off until the next restart: ${switchedOff.join(', ')}`);
    process.exit(tutor && copilot ? 0 : 1);
})();
