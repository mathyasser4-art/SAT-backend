const { Router } = require('express');
const rateLimit = require('express-rate-limit');
const router = Router();
const aiController = require('./ai.controller');
const copilot = require('./copilot/copilot.controller');
const { userAuth, teacherAuth } = require('../../middleware/auth');

// The Copilot acts as the signed-in teacher, so it needs a real teacher account. teacherAuth can
// let token-less dashboard requests through without a user; those are refused here.
const copilotAuth = [
    teacherAuth,
    (req, res, next) => (req.userData && req.userData._id ? next() : res.status(401).json({ message: 'Sign in as a teacher to use the AI Copilot.' })),
];

// Each Copilot message can run many AI calls, so limit it per teacher on top of the global limit
const copilotLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    limit: 40,
    keyGenerator: (req) => String(req.userData._id),
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many Copilot messages. Wait a few minutes and try again.' },
});

router.post('/ai/mistakes-analysis', userAuth, aiController.analyzeMistakes);
router.post('/ai/generate-test', userAuth, aiController.generateTest);

router.post('/ai/copilot/chat', copilotAuth, copilotLimiter, copilot.chat);
router.post('/ai/copilot/actions/:actionId', copilotAuth, copilotLimiter, copilot.decide);
router.get('/ai/copilot/conversations', copilotAuth, copilot.listConversations);
router.get('/ai/copilot/conversations/:conversationId', copilotAuth, copilot.getConversation);

module.exports = router;
