const courseModel = require('../../../DB/models/course.model');
const userModel = require('../../../DB/models/user.model');

const createCourse = async (req, res) => {
    try {
        const { name, description, students, sessions } = req.body;
        const teacherId = req.userData._id;

        const course = new courseModel({
            name,
            description,
            teacher: teacherId,
            students,
            sessions: sessions || []
        });

        await course.save();
        res.status(201).json({ message: "Course created successfully", course });
    } catch (error) {
        res.status(500).json({ message: "Error creating course", error: error.message });
    }
};

const getTeacherCourses = async (req, res) => {
    try {
        const teacherId = req.userData._id;
        const courses = await courseModel.find({ teacher: teacherId }).populate('students', 'userName email');
        res.status(200).json({ courses });
    } catch (error) {
        res.status(500).json({ message: "Error fetching courses", error: error.message });
    }
};

const getStudentCourses = async (req, res) => {
    try {
        const studentId = req.userData._id;
        const courses = await courseModel.find({ students: studentId }).populate('teacher', 'userName');
        res.status(200).json({ courses });
    } catch (error) {
        res.status(500).json({ message: "Error fetching courses", error: error.message });
    }
};

const getCourseById = async (req, res) => {
    try {
        const course = await courseModel.findById(req.params.id)
            .populate('students', 'userName email')
            .populate('sessions.onlineHw');
        if (!course) {
            return res.status(404).json({ message: "Course not found" });
        }
        res.status(200).json({ course });
    } catch (error) {
        res.status(500).json({ message: "Error fetching course", error: error.message });
    }
};

const addSession = async (req, res) => {
    try {
        const { title, date, explanationVideoUrl, recordingUrl, pdfExercises, onlineHw, order } = req.body;
        const courseId = req.params.id;

        const course = await courseModel.findById(courseId);
        if (!course) return res.status(404).json({ message: "Course not found" });

        course.sessions.push({
            title, date, explanationVideoUrl, recordingUrl, pdfExercises, onlineHw, order
        });

        await course.save();
        res.status(200).json({ message: "Session added successfully", course });
    } catch (error) {
        res.status(500).json({ message: "Error adding session", error: error.message });
    }
};

const markSessionCompleted = async (req, res) => {
    try {
        const { courseId, sessionId } = req.params;
        const studentId = req.userData._id;

        const course = await courseModel.findById(courseId);
        if (!course) return res.status(404).json({ message: "Course not found" });

        let progressRecord = course.progress.find(p => p.studentId.toString() === studentId.toString());
        if (!progressRecord) {
            course.progress.push({ studentId, completedSessions: [sessionId] });
        } else {
            if (!progressRecord.completedSessions.includes(sessionId)) {
                progressRecord.completedSessions.push(sessionId);
            }
        }

        await course.save();
        res.status(200).json({ message: "Session marked as completed", progress: course.progress });
    } catch (error) {
        res.status(500).json({ message: "Error updating progress", error: error.message });
    }
};

module.exports = {
    createCourse,
    getTeacherCourses,
    getStudentCourses,
    getCourseById,
    addSession,
    markSessionCompleted
};
