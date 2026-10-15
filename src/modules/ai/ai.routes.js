const { Router } = require('express');
const router = Router();
const aiController = require('./ai.controller');
const { userAuth } = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const userModel = require('../../../DB/models/user.model');
const getJwtSecret = require('../../services/jwtSecret');

const optionalUserAuth = async (req, res, next) => {
    try {
        const rawAuthHeader = req.headers.authorization || req.headers.authrization || req.headers['auth-token'];
        if (!rawAuthHeader) {
            req.userData = null;
            return next();
        }
        let token = rawAuthHeader;
        if (token.startsWith('pracYas09')) {
            token = token.slice(9);
        } else if (process.env.AUTH_SECRET_KEY && token.startsWith(process.env.AUTH_SECRET_KEY)) {
            token = token.slice(process.env.AUTH_SECRET_KEY.length);
        } else if (token.startsWith('Bearer ')) {
            token = token.slice(7);
        }
        const { id } = jwt.verify(token, getJwtSecret());
        const user = await userModel.findById(id);
        if (user) {
            req.userData = user;
        }
    } catch (e) {
        req.userData = null;
    }
    next();
};

router.post('/ai/mistakes-analysis', userAuth, aiController.analyzeMistakes);
router.post('/ai/generate-test', userAuth, aiController.generateTest);
router.post('/ai/copilot/chat', optionalUserAuth, aiController.copilotChat);
router.get('/ai/copilot/audit/:assignmentId', optionalUserAuth, aiController.auditAssignmentDirect);

module.exports = router;
