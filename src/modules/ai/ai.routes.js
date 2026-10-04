const { Router } = require('express');
const router = Router();
const aiController = require('./ai.controller');
const { userAuth } = require('../../middleware/auth');

router.post('/ai/mistakes-analysis', userAuth, aiController.analyzeMistakes);
router.post('/ai/generate-test', userAuth, aiController.generateTest);

module.exports = router;
