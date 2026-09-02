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
        const courses = await courseModel.find({ teacher: teacherId })
            .populate('students', 'userName email')
            .populate('sessions.onlineHw')
            .populate('sessions.onlineClasswork');
        res.status(200).json({ courses });
    } catch (error) {
        res.status(500).json({ message: "Error fetching courses", error: error.message });
    }
};

const getStudentCourses = async (req, res) => {
    try {
        const studentId = req.userData._id;
        const courses = await courseModel.find({ students: studentId })
            .populate('teacher', 'userName')
            .populate('sessions.onlineHw')
            .populate('sessions.onlineClasswork');
        res.status(200).json({ courses });
    } catch (error) {
        res.status(500).json({ message: "Error fetching courses", error: error.message });
    }
};

const getCourseById = async (req, res) => {
    try {
        const course = await courseModel.findById(req.params.id)
            .populate('students', 'userName email')
            .populate('sessions.onlineHw')
            .populate('sessions.onlineClasswork');
        if (!course) {
            return res.status(404).json({ message: "Course not found" });
        }
        res.status(200).json({ course });
    } catch (error) {
        res.status(500).json({ message: "Error fetching course", error: error.message });
    }
};

const extractValidIds = (arr) => {
    if (!Array.isArray(arr)) return [];
    return arr.map(item => {
        if (!item) return null;
        if (typeof item === 'object' && item._id) return String(item._id);
        return String(item);
    }).filter(id => id && id.match(/^[0-9a-fA-F]{24}$/));
};

const addSession = async (req, res) => {
    try {
        const { title, date, explanationVideoUrl, recordingUrl, pdfExercises, hwPdfs, onlineHw, onlineClasswork, order } = req.body;
        const courseId = req.params.id;

        const course = await courseModel.findById(courseId);
        if (!course) return res.status(404).json({ message: "Course not found" });

        course.sessions.push({
            title,
            date: (date === "" || date === null) ? undefined : date,
            explanationVideoUrl,
            recordingUrl,
            pdfExercises: Array.isArray(pdfExercises) ? pdfExercises : [],
            hwPdfs: Array.isArray(hwPdfs) ? hwPdfs : [],
            onlineHw: extractValidIds(onlineHw),
            onlineClasswork: extractValidIds(onlineClasswork),
            order
        });

        await course.save();
        const populatedCourse = await courseModel.findById(courseId)
            .populate('students', 'userName email')
            .populate('sessions.onlineHw')
            .populate('sessions.onlineClasswork');
        res.status(200).json({ message: "Session added successfully", course: populatedCourse });
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

const addStudents = async (req, res) => {
    try {
        const { students } = req.body;
        const courseId = req.params.id;

        const course = await courseModel.findById(courseId);
        if (!course) return res.status(404).json({ message: "Course not found" });

        course.students = students;

        await course.save();
        const populatedCourse = await courseModel.findById(courseId)
            .populate('students', 'userName email')
            .populate('sessions.onlineHw')
            .populate('sessions.onlineClasswork');
        res.status(200).json({ message: "Students updated successfully", course: populatedCourse });
    } catch (error) {
        res.status(500).json({ message: "Error updating students", error: error.message });
    }
};

const updateCourse = async (req, res) => {
    try {
        const { name, description, students } = req.body;
        const courseId = req.params.id;

        const course = await courseModel.findById(courseId);
        if (!course) return res.status(404).json({ message: "Course not found" });

        if (name !== undefined) course.name = name;
        if (description !== undefined) course.description = description;
        if (students !== undefined) course.students = students;

        await course.save();
        const populatedCourse = await courseModel.findById(courseId)
            .populate('students', 'userName email')
            .populate('sessions.onlineHw')
            .populate('sessions.onlineClasswork');
        res.status(200).json({ message: "Course updated successfully", course: populatedCourse });
    } catch (error) {
        res.status(500).json({ message: "Error updating course", error: error.message });
    }
};

const updateSession = async (req, res) => {
    try {
        const { title, date, explanationVideoUrl, recordingUrl, pdfExercises, hwPdfs, onlineHw, onlineClasswork, order } = req.body;
        const { id, sessionId } = req.params;

        const course = await courseModel.findById(id);
        if (!course) return res.status(404).json({ message: "Course not found" });

        const session = course.sessions.id(sessionId);
        if (!session) return res.status(404).json({ message: "Session not found" });

        if (title !== undefined) session.title = title;
        if (date !== undefined) session.date = (date === "" || date === null) ? undefined : date;
        if (explanationVideoUrl !== undefined) session.explanationVideoUrl = explanationVideoUrl;
        if (recordingUrl !== undefined) session.recordingUrl = recordingUrl;
        if (pdfExercises !== undefined) session.pdfExercises = Array.isArray(pdfExercises) ? pdfExercises : [];
        if (hwPdfs !== undefined) session.hwPdfs = Array.isArray(hwPdfs) ? hwPdfs : [];
        if (onlineHw !== undefined) session.onlineHw = extractValidIds(onlineHw);
        if (onlineClasswork !== undefined) session.onlineClasswork = extractValidIds(onlineClasswork);
        if (order !== undefined) session.order = order;

        await course.save();
        const populatedCourse = await courseModel.findById(id)
            .populate('students', 'userName email')
            .populate('sessions.onlineHw')
            .populate('sessions.onlineClasswork');
        res.status(200).json({ message: "Session updated successfully", course: populatedCourse });
    } catch (error) {
        res.status(500).json({ message: "Error updating session", error: error.message });
    }
};

const deleteSession = async (req, res) => {
    try {
        const { id, sessionId } = req.params;

        const course = await courseModel.findById(id);
        if (!course) return res.status(404).json({ message: "Course not found" });

        course.sessions.pull({ _id: sessionId });

        // Clean up completedSessions progress
        course.progress.forEach(p => {
            p.completedSessions = p.completedSessions.filter(sid => sid.toString() !== sessionId.toString());
        });

        await course.save();
        const populatedCourse = await courseModel.findById(id)
            .populate('students', 'userName email')
            .populate('sessions.onlineHw')
            .populate('sessions.onlineClasswork');
        res.status(200).json({ message: "Session deleted successfully", course: populatedCourse });
    } catch (error) {
        res.status(500).json({ message: "Error deleting session", error: error.message });
    }
};

const deleteCourse = async (req, res) => {
    try {
        const { id } = req.params;
        const teacherId = req.userData._id;

        const course = await courseModel.findOneAndDelete({ _id: id, teacher: teacherId });
        if (!course) {
            return res.status(404).json({ message: "Course not found or unauthorized to delete this course" });
        }

        res.status(200).json({ message: "Course deleted successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error deleting course", error: error.message });
    }
};

module.exports = {
    createCourse,
    getTeacherCourses,
    getStudentCourses,
    getCourseById,
    addSession,
    markSessionCompleted,
    addStudents,
    updateCourse,
    updateSession,
    deleteSession,
    deleteCourse
};
