const assignmentModel = require('../../../../DB/models/assignment.model')
const answerModel = require('../../../../DB/models/answer.model')
const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require("cloudinary").v2;
cloudinaryConfig()
const mongoose = require('mongoose')
const userModel = require('../../../../DB/models/user.model')
const courseModel = require('../../../../DB/models/course.model')

const createAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id
        
        if (req.body.classes) {
            // FormData sends a string if only one item is appended, so we ensure it's an array
            const classesArray = Array.isArray(req.body.classes) ? req.body.classes : [req.body.classes];
            req.body.classes = classesArray; // Update req.body.classes to be an array for MongoDB

        }

        const today = new Date().toISOString().slice(0, 10)
        req.body.createdAt = today
        req.body.createdBy = teacherID
        const addAssignment = new assignmentModel(req.body)
        await addAssignment.save()
        res.json({ message: "success", assignment: addAssignment, addAssignment })
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const getAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id
        const allAssignment = await assignmentModel.find({ createdBy: teacherID }).populate({ path: 'questions', select: '-correctAnswer -questionPicID -wrongAnswerID -chapter' }).sort({ _id: -1 })
        if (allAssignment.length != 0) {
            res.json({ message: "success", allAssignment })
        } else {
            res.json({ message: "There is no any assignment yet." })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const updateAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id
        const { assignmentID } = req.params
        const findAssignment = await assignmentModel.findById(assignmentID)
        if (findAssignment) {
            const updateAssignment = await assignmentModel.findByIdAndUpdate(assignmentID, req.body)
            if (updateAssignment) {
                const getAssignment = await assignmentModel.find({ createdBy: teacherID }).select('-createdBy').populate([{ path: 'questions', select: '-chapter' }, { path: 'classes', select: 'class' }, { path: 'students.solveBy', select: 'userName' }]).sort({ _id: -1 })
                res.json({ message: "success", allAssignment: getAssignment })
            } else {
                res.json({ message: "an error is happend" })
            }
        } else {
            res.json({ message: "This assignment is not found" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const deleteAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id
        const { assignmentID } = req.params
        const removeAssignment = await assignmentModel.findByIdAndDelete(assignmentID)
        if (removeAssignment) {
            const getAssignment = await assignmentModel.find({ createdBy: teacherID }).select('-createdBy').populate([{ path: 'questions', select: '-chapter' }, { path: 'classes', select: 'class' }, { path: 'students.solveBy', select: 'userName' }]).sort({ _id: -1 })
            res.json({ message: "success", allAssignment: getAssignment })
        } else {
            res.json({ message: "This assignment is not found" })
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

// NEW: Duplicate/Re-assign an assignment
const duplicateAssignment = async (req, res) => {
    try {
        const teacherID = req.userData._id;
        const { assignmentID } = req.params;
        
        console.log('=== duplicateAssignment START ===');
        console.log('Teacher ID:', teacherID);
        console.log('Assignment ID to duplicate:', assignmentID);
        console.log('New assignment data:', req.body);

        // Find the original assignment
        const originalAssignment = await assignmentModel.findById(assignmentID);
        
        if (!originalAssignment) {
            console.log('ERROR: Original assignment not found');
            return res.status(404).json({ message: "Original assignment not found" });
        }

        // Verify teacher owns this assignment
        if (String(originalAssignment.createdBy) !== String(teacherID)) {
            console.log('ERROR: Teacher does not own this assignment');
            return res.status(403).json({ message: "You don't have permission to duplicate this assignment" });
        }

        console.log('Original assignment found:', originalAssignment.title);

        // Create new assignment based on original, but with new data from request
        const today = new Date().toISOString().slice(0, 10);
        
        const newAssignmentData = {
            // Copy from original assignment
            questions: originalAssignment.questions, // Same questions
            totalPoints: originalAssignment.totalPoints, // Same total points
            
            // Use new data from request body (title, dates, timer, attempts, classes)
            title: req.body.title,
            timer: req.body.timer,
            attemptsNumber: req.body.attemptsNumber || 1,
            startDate: req.body.startDate,
            endDate: req.body.endDate,
            classes: req.body.classes,
            
            // New metadata
            createdBy: teacherID,
            createdAt: today,
            students: [] // Start with no students (they haven't taken it yet)
        };

        console.log('Creating new assignment with data:', newAssignmentData);

        const newAssignment = new assignmentModel(newAssignmentData);
        await newAssignment.save();

        console.log('New assignment created with ID:', newAssignment._id);

        // Get all assignments to return to frontend
        const allAssignments = await assignmentModel
            .find({ createdBy: teacherID })
            .select('-createdBy')
            .populate([
                { path: 'questions', select: '-chapter' },
                { path: 'classes', select: 'class' },
                { path: 'students.solveBy', select: 'userName' }
            ])
            .sort({ _id: -1 });

        console.log('=== duplicateAssignment END ===');
        
        res.json({ 
            message: "success", 
            allAssignment: allAssignments,
            newAssignmentId: newAssignment._id
        });
        
    } catch (error) {
        console.error('=== duplicateAssignment ERROR ===');
        console.error('Error details:', error.message);
        console.error('Stack trace:', error.stack);
        res.status(502).json({ message: error.message });
    }
};

const getStudentResults = async (req, res) => {
    try {
        const { assignmentID } = req.params;
        const teacherID = req.userData._id;

        // Get assignment and populate questions and classes
        const assignment = await assignmentModel.findById(assignmentID)
            .populate('questions')
            .populate({ path: 'classes', select: 'class' });

        if (!assignment) {
            return res.status(404).json({ message: "Assignment not found" });
        }

        // Check permissions: Privileged roles (Admin, School, Supervisor, IT), creator, or course teacher
        const userRole = req.userData?.role;
        const isPrivileged = ['Admin', 'School', 'Supervisor', 'IT'].includes(userRole);

        if (!isPrivileged && assignment.createdBy && String(assignment.createdBy) !== String(teacherID)) {
            const courseWithAssignment = await courseModel.findOne({
                teacher: teacherID,
                $or: [
                    { 'sessions.onlineHw': assignmentID },
                    { 'sessions.onlineClasswork': assignmentID }
                ]
            });
            if (!courseWithAssignment) {
                return res.status(403).json({ message: "Access denied - You don't own this assignment" });
            }
        }

        // 1. Get all answers submitted for this assignment (sorted by latest attempt first)
        const answers = await answerModel.find({ 
            assignment: assignmentID
        })
            .sort({ attemptNumber: -1, createdAt: -1 })
            .populate('solveBy', 'userName email class')
            .select('total questionsNumber time createdAt completedAt questions solveBy attemptNumber');

        // 2. Get all students in assigned classes
        let assignedStudents = [];
        if (assignment.classes && assignment.classes.length > 0) {
            const classIds = assignment.classes.map(c => c._id || c);
            assignedStudents = await userModel.find({ 
                role: 'Student', 
                class: { $in: classIds } 
            }).select('userName email class');
        }

        // Fallback: If no assigned classes or no students found, use solveBy from answer documents
        if (assignedStudents.length === 0) {
            assignedStudents = answers
                .filter(a => a.solveBy)
                .map(a => a.solveBy);
        }

        // Deduplicate students by ID to prevent duplicate rows in reports
        const uniqueStudentMap = new Map();
        assignedStudents.forEach(st => {
            if (st && (st._id || st.id)) {
                const sKey = (st._id || st.id).toString();
                if (!uniqueStudentMap.has(sKey)) {
                    uniqueStudentMap.set(sKey, st);
                }
            }
        });
        assignedStudents = Array.from(uniqueStudentMap.values());

        // Calculate total possible points from questions
        let totalPoints = assignment.totalPoints || 0;
        if ((!totalPoints || totalPoints === 0) && assignment.questions && assignment.questions.length > 0) {
            totalPoints = assignment.questions.reduce((sum, q) => sum + ((typeof q.questionPoints === 'number' && q.questionPoints > 0) ? q.questionPoints : 1), 0);
        }
        if (!totalPoints || totalPoints <= 0) {
            totalPoints = assignment.questions ? assignment.questions.length : 1;
        }

        // Create lookup map of answer documents by student ID
        // Since answers is sorted by latest attempt (attemptNumber -1, createdAt -1),
        // the first entry we encounter is the latest attempt.
        const studentAnswerMap = {};
        answers.forEach(answer => {
            if (answer.solveBy && answer.solveBy._id) {
                const sId = answer.solveBy._id.toString();
                if (!studentAnswerMap[sId]) {
                    studentAnswerMap[sId] = answer;
                } else if (!studentAnswerMap[sId].completedAt && answer.completedAt) {
                    studentAnswerMap[sId] = answer;
                }
            }
        });

        // 3. Build comprehensive student results list with status
        const students = assignedStudents.map(student => {
            const sId = student._id.toString();
            const answer = studentAnswerMap[sId];

            if (answer) {
                let calculatedScore = 0;
                if (Array.isArray(answer.questions)) {
                    answer.questions.forEach(q => {
                        if (q && q.point && q.point > 0) {
                            calculatedScore += q.point;
                        } else if (q && q.isCorrect) {
                            calculatedScore += 1;
                        }
                    });
                }

                const score = (typeof answer.total === 'number' && answer.total > 0)
                    ? answer.total
                    : calculatedScore;

                // Self-heal answer.total in DB if it was 0 or unpopulated and we have calculatedScore > 0
                if ((!answer.total || answer.total === 0) && calculatedScore > 0) {
                    answerModel.findByIdAndUpdate(answer._id, { total: calculatedScore }).exec().catch(() => {});
                }

                const percentage = totalPoints > 0 ? Math.round((score / totalPoints) * 100) : 0;
                const isCompleted = !!answer.completedAt;

                return {
                    _id: answer._id,
                    studentId: student._id,
                    userName: student.userName || 'Student',
                    email: student.email || '',
                    status: isCompleted ? 'Completed' : 'In Progress',
                    answeredQuestions: answer.questionsNumber || (answer.questions ? answer.questions.length : 0),
                    score: score,
                    totalPossible: totalPoints,
                    timeSpent: answer.time || '0:00',
                    percentage: percentage,
                    completedAt: answer.completedAt || answer.createdAt,
                    totalQuestions: assignment.questions ? assignment.questions.length : totalPoints
                };
            } else {
                // Student has not started this assignment yet
                return {
                    _id: student._id,
                    studentId: student._id,
                    userName: student.userName || 'Student',
                    email: student.email || '',
                    status: 'Not Started',
                    answeredQuestions: 0,
                    score: 0,
                    totalPossible: totalPoints,
                    timeSpent: '0:00',
                    percentage: 0,
                    completedAt: null,
                    totalQuestions: assignment.questions ? assignment.questions.length : totalPoints
                };
            }
        });

        res.json({
            message: "success",
            students,
            assignment: {
                _id: assignment._id,
                title: assignment.title,
                totalPoints: totalPoints,
                totalQuestions: assignment.questions ? assignment.questions.length : 0,
                createdAt: assignment.createdAt
            }
        });
    } catch (error) {
        console.error('Error in getStudentResults:', error.message);
        res.status(502).json({ message: error.message });
    }
};

// FIXED: Add getStudentResults and duplicateAssignment to the exports
module.exports = { 
    createAssignment, 
    getAssignment, 
    updateAssignment, 
    deleteAssignment,
    getStudentResults,
    duplicateAssignment  // ADD THIS LINE
}
