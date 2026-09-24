const express = require('express');
const router = express.Router();
const journeyController = require('./controller/journey.controller');

// Save student journey progress
router.post('/journey/saveProgress', journeyController.saveProgress);

// Get progress for a specific student and subject
router.get('/journey/getProgress/:studentId/:subjectId', journeyController.getProgress);

// Get all progress for a student
router.get('/journey/getAllProgress/:studentId', journeyController.getAllProgress);

// Live system overview with completion percentages
router.get('/journey/systemOverview/:studentId', journeyController.getSystemOverview);

module.exports = router;
