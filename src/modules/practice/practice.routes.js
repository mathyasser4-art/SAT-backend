const express = require('express');
const router = express.Router();
const practiceController = require('./controller/practice.controller');
const { userAuth } = require('../../middleware/auth');

// Auto-record practice attempt upon completing a test/exam
router.post('/practice/attempt', userAuth, practiceController.recordAttempt);

// Get all practice attempts for a student (for teacher inspection or student review)
router.get('/practice/student/:studentId', userAuth, practiceController.getStudentPracticeAttempts);

module.exports = router;
