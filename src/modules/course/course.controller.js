const courseModel = require('../../../DB/models/course.model');
const userModel = require('../../../DB/models/user.model');

const extractValidIds = (arr) => {
    if (!Array.isArray(arr)) return [];
    const valid = arr.map(item => {
        if (!item) return null;
        if (typeof item === 'object' && item._id) return String(item._id);
        return String(item);
    }).filter(id => id && id.match(/^[0-9a-fA-F]{24}$/));
    return [...new Set(valid)];
};

const createCourse = async (req, res) => {
    try {
        const { name, description, students, sessions } = req.body;
        const teacherId = req.userData._id;

        const course = new courseModel({
            name,
            description,
            teacher: teacherId,
            students: extractValidIds(students),
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



const addSession = async (req, res) => {
    try {
        const { title, date, explanationVideoUrl, recordingUrl, pdfExercises, hwPdfs, onlineHw, onlineClasswork, order } = req.body;
        const courseId = req.params.id;
        const teacherId = req.userData._id;

        const course = await courseModel.findById(courseId);
        if (!course) return res.status(404).json({ message: "Course not found" });
        if (String(course.teacher) !== String(teacherId)) return res.status(403).json({ message: "Unauthorized: you do not own this course" });

        course.sessions.push({
            title,
            date: (date === "" || date === null) ? undefined : date,
            explanationVideoUrl,
            recordingUrl,
            pdfExercises: Array.isArray(pdfExercises) ? pdfExercises : [],
            hwPdfs: Array.isArray(hwPdfs) ? hwPdfs : [],
            onlineHw: extractValidIds(onlineHw),
            onlineClasswork: extractValidIds(onlineClasswork),
            order: order !== undefined ? order : (course.sessions.length + 1)
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
            const alreadyCompleted = progressRecord.completedSessions.some(id => id.toString() === sessionId.toString());
            if (!alreadyCompleted) {
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
        const { students, mode } = req.body;
        const courseId = req.params.id;
        const teacherId = req.userData._id;

        const course = await courseModel.findById(courseId);
        if (!course) return res.status(404).json({ message: "Course not found" });
        if (String(course.teacher) !== String(teacherId)) return res.status(403).json({ message: "Unauthorized: you do not own this course" });

        if (!Array.isArray(students)) {
            return res.status(400).json({ message: "students must be an array" });
        }

        const validStudents = extractValidIds(students);

        if (mode === 'append') {
            const existing = extractValidIds(course.students);
            course.students = [...new Set([...existing, ...validStudents])];
        } else {
            course.students = validStudents;
        }

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
        const teacherId = req.userData._id;

        const course = await courseModel.findById(courseId);
        if (!course) return res.status(404).json({ message: "Course not found" });
        if (String(course.teacher) !== String(teacherId)) return res.status(403).json({ message: "Unauthorized: you do not own this course" });

        if (name !== undefined) course.name = name;
        if (description !== undefined) course.description = description;
        if (students !== undefined) course.students = extractValidIds(students);

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
        const teacherId = req.userData._id;

        const course = await courseModel.findById(id);
        if (!course) return res.status(404).json({ message: "Course not found" });
        if (String(course.teacher) !== String(teacherId)) return res.status(403).json({ message: "Unauthorized: you do not own this course" });

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
        const teacherId = req.userData._id;

        const course = await courseModel.findById(id);
        if (!course) return res.status(404).json({ message: "Course not found" });
        if (String(course.teacher) !== String(teacherId)) return res.status(403).json({ message: "Unauthorized: you do not own this course" });

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

const submitStudentHw = async (req, res) => {
    try {
        const { id, sessionId } = req.params;
        const { hwPdfIndex, hwPdfName, fileUrl, fileName } = req.body;
        const studentId = req.userData._id;
        const studentName = req.userData.userName || req.userData.name || 'Student';
        const studentEmail = req.userData.email || '';

        if (!fileUrl) {
            return res.status(400).json({ message: "File upload is required" });
        }

        const course = await courseModel.findById(id);
        if (!course) return res.status(404).json({ message: "Course not found" });

        const session = course.sessions.id(sessionId);
        if (!session) return res.status(404).json({ message: "Session not found" });

        if (!session.studentHwSubmissions) {
            session.studentHwSubmissions = [];
        }

        const targetIndex = Number(hwPdfIndex) || 0;
        const existingIdx = session.studentHwSubmissions.findIndex(
            s => s.studentId && s.studentId.toString() === studentId.toString() && (s.hwPdfIndex || 0) === targetIndex
        );

        const newSubmission = {
            studentId,
            studentName,
            studentEmail,
            hwPdfIndex: targetIndex,
            hwPdfName: hwPdfName || `HW PDF #${targetIndex + 1}`,
            fileUrl,
            fileName: fileName || `homework_solution_${studentName}.pdf`,
            submittedAt: new Date()
        };

        if (existingIdx >= 0) {
            session.studentHwSubmissions[existingIdx] = newSubmission;
        } else {
            session.studentHwSubmissions.push(newSubmission);
        }

        await course.save();

        const populatedCourse = await courseModel.findById(id)
            .populate('students', 'userName email')
            .populate('sessions.onlineHw')
            .populate('sessions.onlineClasswork');

        res.status(200).json({ 
            message: "Homework solution submitted successfully", 
            submission: newSubmission, 
            course: populatedCourse 
        });
    } catch (error) {
        res.status(500).json({ message: "Error submitting homework", error: error.message });
    }
};

const getSessionHwSubmissions = async (req, res) => {
    try {
        const { id, sessionId } = req.params;
        const course = await courseModel.findById(id).populate('students', 'userName email');
        if (!course) return res.status(404).json({ message: "Course not found" });

        const session = course.sessions.id(sessionId);
        if (!session) return res.status(404).json({ message: "Session not found" });

        const submissions = session.studentHwSubmissions || [];
        const enrolledStudents = course.students || [];

        res.status(200).json({ 
            message: "Submissions retrieved successfully", 
            submissions,
            enrolledStudents,
            hwPdfs: session.hwPdfs || []
        });
    } catch (error) {
        res.status(500).json({ message: "Error fetching homework submissions", error: error.message });
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
    deleteCourse,
    submitStudentHw,
    getSessionHwSubmissions
};
