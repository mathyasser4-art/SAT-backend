const express = require('express');
const router = express.Router();
const courseController = require('./course.controller');
const { teacherAuth, studentAuth, userAuth } = require('../../middleware/auth'); 

// Teacher routes
router.post('/course', teacherAuth, courseController.createCourse);
router.get('/course/teacher', teacherAuth, courseController.getTeacherCourses);
router.post('/course/:id/session', teacherAuth, courseController.addSession);

// Student routes
router.get('/course/student', studentAuth, courseController.getStudentCourses);
router.put('/course/:courseId/session/:sessionId/complete', studentAuth, courseController.markSessionCompleted);

// Shared routes
router.get('/course/:id', userAuth, courseController.getCourseById);

module.exports = router;
