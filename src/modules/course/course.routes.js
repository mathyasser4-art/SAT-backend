const express = require('express');
const router = express.Router();
const courseController = require('./course.controller');
const { auth } = require('../../middleware/auth'); // Assuming auth middleware exists here

// Teacher routes
router.post('/course', auth(), courseController.createCourse);
router.get('/course/teacher', auth(), courseController.getTeacherCourses);
router.post('/course/:id/session', auth(), courseController.addSession);

// Student routes
router.get('/course/student', auth(), courseController.getStudentCourses);
router.put('/course/:courseId/session/:sessionId/complete', auth(), courseController.markSessionCompleted);

// Shared routes
router.get('/course/:id', auth(), courseController.getCourseById);

module.exports = router;
