const express = require('express');
const router = express.Router();
const { parentAuth } = require('../../middleware/auth');
const { getMyChildren, getChildAssignments, getChildMistakes } = require('./controller/parent.controller');

router.get('/parent/children', parentAuth, getMyChildren);
router.get('/parent/child/:childId/assignments', parentAuth, getChildAssignments);
router.get('/parent/child/:childId/mistakes', parentAuth, getChildMistakes);

module.exports = router;
