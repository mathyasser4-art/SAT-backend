const express = require('express');
const router = express.Router();
const courseController = require('./course.controller');
const { teacherAuth, studentAuth, userAuth } = require('../../middleware/auth'); 

// Teacher routes
router.post('/course', teacherAuth, courseController.createCourse);
router.get('/course/teacher', teacherAuth, courseController.getTeacherCourses);
router.put('/course/:id', teacherAuth, courseController.updateCourse);
router.post('/course/:id/session', teacherAuth, courseController.addSession);
router.put('/course/:id/session/:sessionId', teacherAuth, courseController.updateSession);
router.delete('/course/:id/session/:sessionId', teacherAuth, courseController.deleteSession);
router.put('/course/:id/students', teacherAuth, courseController.addStudents);
router.delete('/course/:id', teacherAuth, courseController.deleteCourse);

// Student routes
router.get('/course/student', studentAuth, courseController.getStudentCourses);
router.put('/course/:courseId/session/:sessionId/complete', studentAuth, courseController.markSessionCompleted);

// Shared routes
router.get('/course/:id', userAuth, courseController.getCourseById);

module.exports = router;
