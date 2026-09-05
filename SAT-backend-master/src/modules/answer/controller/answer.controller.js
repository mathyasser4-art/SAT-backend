const mongoose = require('mongoose')
const questionModel = require('../../../../DB/models/question.model')
const answerModel = require('../../../../DB/models/answer.model')
const assignmentModel = require('../../../../DB/models/assignment.model')
const checkAnswer = require('../../../services/checkAnswer')
const normalizeAnswer = require('../../../services/normalizeAnswer')
const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require("cloudinary").v2;
cloudinaryConfig()
const fs = require('fs');

const getResult = async (req, res) => {
    try {
        const { assignmentID } = req.params;
        const { time } = req.query;
        const studentID = req.userData._id;

        const studentObjId = mongoose.Types.ObjectId.isValid(studentID) ? new mongoose.Types.ObjectId(studentID) : studentID;
        const assignmentObjId = mongoose.Types.ObjectId.isValid(assignmentID) ? new mongoose.Types.ObjectId(assignmentID) : assignmentID;

        // Get current attempt number from assignment
        const assignmentDoc = await assignmentModel.findById(assignmentID);
        const studentRecord = assignmentDoc?.students?.find(s => String(s.solveBy) === String(studentID));
        const currentAttemptNumber = studentRecord?.attempts || 1;

        // Find answer for THIS specific attempt
        let findAnswer = await answerModel.findOne({ 
            $or: [
                { solveBy: studentID, assignment: assignmentID, attemptNumber: currentAttemptNumber },
                { solveBy: studentObjId, assignment: assignmentObjId, attemptNumber: currentAttemptNumber }
            ]
        });

        // Fallback: search for any existing attempt for this student/assignment
        if (!findAnswer) {
            findAnswer = await answerModel.findOne({
                $or: [
                    { solveBy: studentID, assignment: assignmentID },
                    { solveBy: studentObjId, assignment: assignmentObjId }
                ]
            }).sort({ createdAt: -1 });
        }

        // Last resort: create a new answer document
        if (!findAnswer) {
            findAnswer = await answerModel.create({
                solveBy: studentID,
                assignment: assignmentID,
                attemptNumber: currentAttemptNumber,
                questionsNumber: 0,
                questions: [],
                time: time || "0:00",
                completedAt: new Date()
            });
        }

        if (findAnswer) {
            findAnswer.time = time || "0:00";

            const assignment = await assignmentModel.findById(assignmentID)
                .populate({
                    path: 'questions',
                    select: 'questionPoints correctAnswer typeOfAnswer answer correctPicAnswer autoCorrect'
                });

            let totalSummation = 0;
            let studentTotalScore = 0;

            if (assignment && assignment.questions) {
                assignment.questions.forEach(question => {
                    if (!question) return;
                    totalSummation += (question.questionPoints || 0);

                    const studentAnswerForQuestion = findAnswer.questions.find(
                        (ans) => ans && ans.question && (ans.question._id || ans.question).toString() === question._id.toString()
                    );

                    if (studentAnswerForQuestion) {
                        let isCorrect = false;
                        if (question.typeOfAnswer === 'Graph' && studentAnswerForQuestion.stepPicture?.secure_url) {
                            isCorrect = checkAnswer(question, studentAnswerForQuestion.stepPicture.secure_url);
                        } else {
                            isCorrect = checkAnswer(question, studentAnswerForQuestion.firstAnswer);
                        }
                        
                        if (isCorrect) {
                            studentTotalScore += (question.questionPoints || 0);
                            studentAnswerForQuestion.point = question.questionPoints || 0;
                        } else {
                            studentAnswerForQuestion.point = 0;
                        }
                        studentAnswerForQuestion.isCorrect = isCorrect;
                    }
                });
            }

            findAnswer.total = studentTotalScore;
            findAnswer.questionsNumber = findAnswer.questions.length;

            if (!findAnswer.completedAt) {
                findAnswer.completedAt = new Date();
            }

            await findAnswer.save();

            return res.json({
                message: "success",
                result: {
                    total: findAnswer.total,
                    questionsNumber: findAnswer.questionsNumber,
                    time: findAnswer.time
                },
                totalSummation,
            });
        } else {
            return res.json({
                message: "success",
                result: { total: 0, questionsNumber: 0, time: time || "0:00" },
                totalSummation: 0
            });
        }
    } catch (error) {
        console.error('getResult error:', error.message);
        return res.json({
            message: "success",
            result: { total: 0, questionsNumber: 0, time: "0:00" },
            totalSummation: 0
        });
    }
};

const checkAssinmentAnswer = async (req, res) => {
    try {
        const { questionID, assignmentID } = req.params;
        const studentID = req.userData._id;
        
        const { firstAnswer, secondAnswer, thirdAnswer, fourthAnswer, questionAnswer } = req.body;

        const question = await questionModel.findById(questionID);
        if (!question) {
            return res.status(404).json({ message: "Question not found" });
        }

        const studentObjId = mongoose.Types.ObjectId.isValid(studentID) ? new mongoose.Types.ObjectId(studentID) : studentID;
        const assignmentObjId = mongoose.Types.ObjectId.isValid(assignmentID) ? new mongoose.Types.ObjectId(assignmentID) : assignmentID;
        const qObjId = mongoose.Types.ObjectId.isValid(questionID) ? new mongoose.Types.ObjectId(questionID) : questionID;

        // Cleanup any uploaded temp files if sent in request
        const uploadedFile = req.file || (req.files && req.files[0]);
        if (uploadedFile && uploadedFile.path && fs.existsSync(uploadedFile.path)) {
            try { fs.unlinkSync(uploadedFile.path); } catch (e) {}
        }

        // Get current attempt number from assignment
        const assignment = await assignmentModel.findById(assignmentID);
        const studentRecord = assignment?.students?.find(s => String(s.solveBy) === String(studentID));
        const currentAttemptNumber = studentRecord?.attempts || 1;

        // Find or create answer document for THIS attempt
        let findAnswer = await answerModel.findOne({ 
            $or: [
                { solveBy: studentID, assignment: assignmentID, attemptNumber: currentAttemptNumber },
                { solveBy: studentObjId, assignment: assignmentObjId, attemptNumber: currentAttemptNumber }
            ]
        });

        if (!findAnswer) {
            findAnswer = await answerModel.create({
                solveBy: studentObjId,
                assignment: assignmentObjId,
                attemptNumber: currentAttemptNumber,
                questionsNumber: 0,
                questions: [],
                time: "0:00"
            });
        }

        const answerToSave = (questionAnswer !== undefined && questionAnswer !== null) ? String(questionAnswer) : (firstAnswer !== undefined && firstAnswer !== null ? String(firstAnswer) : '');

        // Check if the answer is correct using practice-style checkAnswer service
        const isCorrect = checkAnswer(question, answerToSave);

        // Update or append question in questions array in JS memory
        const questionIndex = findAnswer.questions.findIndex(
            q => q && q.question && (q.question._id || q.question).toString() === questionID.toString()
        );

        if (questionIndex > -1) {
            findAnswer.questions[questionIndex].firstAnswer = answerToSave;
            findAnswer.questions[questionIndex].isCorrect = isCorrect;
            findAnswer.questions[questionIndex].point = isCorrect ? (question.questionPoints || 0) : 0;
            if (secondAnswer) findAnswer.questions[questionIndex].secondAnswer = String(secondAnswer);
            if (thirdAnswer) findAnswer.questions[questionIndex].thirdAnswer = String(thirdAnswer);
            if (fourthAnswer) findAnswer.questions[questionIndex].fourthAnswer = String(fourthAnswer);
        } else {
            const newQuestionAnswer = {
                question: qObjId,
                firstAnswer: answerToSave,
                secondAnswer: secondAnswer ? String(secondAnswer) : '',
                thirdAnswer: thirdAnswer ? String(thirdAnswer) : '',
                fourthAnswer: fourthAnswer ? String(fourthAnswer) : '',
                attempts: 1,
                isCorrect: isCorrect,
                point: isCorrect ? (question.questionPoints || 0) : 0
            };
            findAnswer.questions.push(newQuestionAnswer);
        }

        findAnswer.questionsNumber = findAnswer.questions.length;
        await findAnswer.save();

        const savedQuestion = findAnswer.questions.find(
            q => q && q.question && (q.question._id || q.question).toString() === questionID.toString()
        );

        return res.status(200).json({ 
            message: "success", 
            isCorrect: isCorrect,
            answer: savedQuestion || { question: questionID, firstAnswer: answerToSave, isCorrect }
        });

    } catch (error) {
        console.error('checkAssinmentAnswer error:', error.message);
        const uploadedFile = req.file || (req.files && req.files[0]);
        if (uploadedFile && uploadedFile.path && fs.existsSync(uploadedFile.path)) {
            try { fs.unlinkSync(uploadedFile.path); } catch (e) {}
        }
        return res.status(200).json({ 
            message: "success", 
            isCorrect: false,
            answer: { question: questionID, firstAnswer: '', isCorrect: false }
        });
    }
};

/**
 * Helper: Build correctAnswer string from question data
 */
function buildCorrectAnswerStr(question) {
    if (!question) return 'N/A';
    
    if (question.typeOfAnswer === 'Graph') {
        return question.correctPicAnswer || 'View Image';
    }
    
    // For MCQ: use correctAnswer field
    if (question.typeOfAnswer === 'MCQ' && question.correctAnswer && String(question.correctAnswer).trim() !== '') {
        return String(question.correctAnswer);
    }
    
    // For Essay: use answer[] array (list of acceptable answers)
    if (Array.isArray(question.answer) && question.answer.length > 0) {
        const filtered = question.answer.filter(Boolean);
        if (filtered.length > 0) return filtered.join(', ');
    }
    
    // Fallback: single string answer
    if (typeof question.answer === 'string' && question.answer.trim() !== '') {
        return question.answer;
    }
    
    // Final fallback for MCQ correctAnswer (even if it looked empty before)
    if (question.correctAnswer && String(question.correctAnswer).trim() !== '') {
        return String(question.correctAnswer);
    }
    
    return 'N/A';
}

const getAssignmentAnswer = async (req, res) => {
    try {
        const { studentID, assignmentID } = req.params;
        const studentObjId = mongoose.Types.ObjectId.isValid(studentID) ? new mongoose.Types.ObjectId(studentID) : studentID;
        const assignmentObjId = mongoose.Types.ObjectId.isValid(assignmentID) ? new mongoose.Types.ObjectId(assignmentID) : assignmentID;

        // Prefer completed answers (with completedAt set)
        let answers = await answerModel.findOne({ 
            $or: [
                { solveBy: studentID, assignment: assignmentID, completedAt: { $ne: null } },
                { solveBy: studentObjId, assignment: assignmentObjId, completedAt: { $ne: null } }
            ]
        })
        .sort({ attemptNumber: -1, createdAt: -1 })
        .populate({
            path: 'assignment',
            select: 'title totalPoints questions'
        });

        // Fallback: if no completed answer, get any answer
        if (!answers) {
            answers = await answerModel.findOne({ 
                $or: [
                    { solveBy: studentID, assignment: assignmentID },
                    { solveBy: studentObjId, assignment: assignmentObjId }
                ]
            })
            .sort({ attemptNumber: -1, createdAt: -1 })
            .populate({
                path: 'assignment',
                select: 'title totalPoints questions'
            });
        }

        // Always fetch full assignment with all questions for merging
        const assignment = await assignmentModel.findById(assignmentID).populate({
            path: 'questions',
            select: 'question questionPic questionPoints typeOfAnswer correctAnswer answer correctPicAnswer'
        });

        if (!answers) {
            // No answer document at all — return template report from assignment questions
            const questions = assignment?.questions || [];
            const report = {
                questions: questions.map(q => ({
                    _id: q._id,
                    questionId: q._id,
                    question: q.question || '',
                    questionPic: q.questionPic?.secure_url || null,
                    firstAnswer: '',
                    secondAnswer: '',
                    stepsPic: null,
                    isCorrect: false,
                    notAnswer: true,
                    questionPoints: q.questionPoints || 0,
                    correctAnswer: buildCorrectAnswerStr(q),
                    typeOfAnswer: q.typeOfAnswer || 'Essay'
                }))
            };

            return res.json({
                message: "success",
                answers: {
                    assignment: {
                        title: assignment?.title || 'Assignment Report',
                        totalPoints: assignment?.totalPoints || 0
                    },
                    time: "0:00",
                    total: 0,
                    questionsNumber: 0
                },
                report
            });
        }

        // Build report from ALL assignment questions, merging with student answers
        const allAssignmentQuestions = (assignment?.questions || []).filter(Boolean);
        
        // Create a lookup map of student answers by question ID
        // CRITICAL FIX: Safe extraction of question ID from populated or unpopulated field
        const studentAnswerMap = {};
        (answers.questions || []).forEach(sa => {
            if (sa && sa.question) {
                const qId = (sa.question._id ? sa.question._id : sa.question).toString();
                studentAnswerMap[qId] = sa;
            }
        });

        // Build report from ALL assignment questions
        const reportQuestions = allAssignmentQuestions.map(question => {
            const qId = question._id ? question._id.toString() : String(question);
            const studentAnswer = studentAnswerMap[qId];

            if (studentAnswer) {
                // Student answered this question
                const hasFirstAnswer = studentAnswer.firstAnswer !== undefined && studentAnswer.firstAnswer !== null && studentAnswer.firstAnswer !== '';
                const hasSecondAnswer = studentAnswer.secondAnswer !== undefined && studentAnswer.secondAnswer !== null && studentAnswer.secondAnswer !== '';

                return {
                    _id: studentAnswer._id || qId,
                    questionId: qId,
                    question: question.question || '',
                    questionPic: question.questionPic?.secure_url || null,
                    firstAnswer: studentAnswer.firstAnswer || '',
                    secondAnswer: studentAnswer.secondAnswer || '',
                    stepsPic: studentAnswer.stepPicture?.secure_url || null,
                    isCorrect: studentAnswer.isCorrect || false,
                    notAnswer: !hasFirstAnswer && !hasSecondAnswer,
                    questionPoints: question.questionPoints || 0,
                    point: studentAnswer.point || 0,
                    correctAnswer: buildCorrectAnswerStr(question),
                    typeOfAnswer: question.typeOfAnswer || 'Essay'
                };
            } else {
                // Student did NOT answer this question
                return {
                    _id: qId,
                    questionId: qId,
                    question: question.question || '',
                    questionPic: question.questionPic?.secure_url || null,
                    firstAnswer: '',
                    secondAnswer: '',
                    stepsPic: null,
                    isCorrect: false,
                    notAnswer: true,
                    questionPoints: question.questionPoints || 0,
                    point: 0,
                    correctAnswer: buildCorrectAnswerStr(question),
                    typeOfAnswer: question.typeOfAnswer || 'Essay'
                };
            }
        });

        const report = { questions: reportQuestions };
        const assignmentData = answers.assignment || assignment;

        return res.json({
            message: "success",
            answers: {
                assignment: assignmentData ? {
                    _id: assignmentData._id,
                    title: assignmentData.title,
                    totalPoints: assignmentData.totalPoints || 0
                } : { title: 'Assignment', totalPoints: 0 },
                time: answers.time || "0:00",
                total: answers.total || 0,
                questionsNumber: answers.questionsNumber || 0
            },
            report
        });

    } catch (error) {
        console.error('getAssignmentAnswer error:', error.message);
        return res.json({ 
            message: "success",
            answers: {
                assignment: { title: 'Assignment Report', totalPoints: 0 },
                time: "0:00",
                total: 0,
                questionsNumber: 0
            },
            report: { questions: [] }
        });
    }
};


const getStudentOwnReport = async (req, res) => {
    try {
        const { assignmentID } = req.params;
        const studentID = req.userData._id;

        const studentObjId = mongoose.Types.ObjectId.isValid(studentID) ? new mongoose.Types.ObjectId(studentID) : studentID;
        const assignmentObjId = mongoose.Types.ObjectId.isValid(assignmentID) ? new mongoose.Types.ObjectId(assignmentID) : assignmentID;

        // Prefer completed answers, sort by latest attempt
        let answers = await answerModel.findOne({ 
            $or: [
                { solveBy: studentID, assignment: assignmentID, completedAt: { $ne: null } },
                { solveBy: studentObjId, assignment: assignmentObjId, completedAt: { $ne: null } }
            ]
        })
        .sort({ attemptNumber: -1, createdAt: -1 })
        .populate({
            path: 'assignment',
            select: 'title totalPoints questions'
        });

        // Fallback: if no completed answer, get any answer
        if (!answers) {
            answers = await answerModel.findOne({ 
                $or: [
                    { solveBy: studentID, assignment: assignmentID },
                    { solveBy: studentObjId, assignment: assignmentObjId }
                ]
            })
            .sort({ attemptNumber: -1, createdAt: -1 })
            .populate({
                path: 'assignment',
                select: 'title totalPoints questions'
            });
        }

        // Always fetch full assignment with all questions for merging
        const assignment = await assignmentModel.findById(assignmentID).populate({
            path: 'questions',
            select: 'question questionPic questionPoints typeOfAnswer correctAnswer answer correctPicAnswer'
        });

        if (!answers) {
            // No answer document — return 200 success with all questions marked as unanswered
            const questions = assignment?.questions || [];
            const report = {
                questions: questions.map(q => ({
                    _id: q._id,
                    questionId: q._id,
                    question: q.question || '',
                    questionPic: q.questionPic?.secure_url || null,
                    firstAnswer: '',
                    secondAnswer: '',
                    stepsPic: null,
                    isCorrect: false,
                    notAnswer: true,
                    questionPoints: q.questionPoints || 0,
                    point: 0,
                    correctAnswer: buildCorrectAnswerStr(q),
                    typeOfAnswer: q.typeOfAnswer || 'Essay'
                }))
            };
            return res.json({
                message: "success",
                answers: {
                    assignment: { _id: assignment?._id || assignmentID, title: assignment?.title || 'Assignment Report', totalPoints: assignment?.totalPoints || 0 },
                    time: "0:00",
                    total: 0,
                    questionsNumber: 0
                },
                report
            });
        }

        // Build report from ALL assignment questions, merging with student answers
        const allAssignmentQuestions = (assignment?.questions || []).filter(Boolean);

        // Create a lookup map of student answers by question ID
        // CRITICAL FIX: Safe extraction of question ID from populated or unpopulated field
        const studentAnswerMap = {};
        (answers.questions || []).forEach(sa => {
            if (sa && sa.question) {
                const qId = (sa.question._id ? sa.question._id : sa.question).toString();
                studentAnswerMap[qId] = sa;
            }
        });

        // Build report from ALL assignment questions
        const reportQuestions = allAssignmentQuestions.map(question => {
            const qId = question._id ? question._id.toString() : String(question);
            const studentAnswer = studentAnswerMap[qId];

            if (studentAnswer) {
                const hasFirstAnswer = studentAnswer.firstAnswer !== undefined && studentAnswer.firstAnswer !== null && studentAnswer.firstAnswer !== '';
                const hasSecondAnswer = studentAnswer.secondAnswer !== undefined && studentAnswer.secondAnswer !== null && studentAnswer.secondAnswer !== '';

                return {
                    _id: studentAnswer._id || qId,
                    questionId: qId,
                    question: question.question || '',
                    questionPic: question.questionPic?.secure_url || null,
                    firstAnswer: studentAnswer.firstAnswer || '',
                    secondAnswer: studentAnswer.secondAnswer || '',
                    stepsPic: studentAnswer.stepPicture?.secure_url || null,
                    isCorrect: studentAnswer.isCorrect || false,
                    notAnswer: !hasFirstAnswer && !hasSecondAnswer,
                    questionPoints: question.questionPoints || 0,
                    point: studentAnswer.point || 0,
                    correctAnswer: buildCorrectAnswerStr(question),
                    typeOfAnswer: question.typeOfAnswer || 'Essay'
                };
            } else {
                // Student did NOT answer this question
                return {
                    _id: qId,
                    questionId: qId,
                    question: question.question || '',
                    questionPic: question.questionPic?.secure_url || null,
                    firstAnswer: '',
                    secondAnswer: '',
                    stepsPic: null,
                    isCorrect: false,
                    notAnswer: true,
                    questionPoints: question.questionPoints || 0,
                    point: 0,
                    correctAnswer: buildCorrectAnswerStr(question),
                    typeOfAnswer: question.typeOfAnswer || 'Essay'
                };
            }
        });

        const report = { questions: reportQuestions };
        const assignmentData = answers.assignment || assignment;

        return res.json({
            message: "success",
            answers: {
                assignment: assignmentData ? {
                    _id: assignmentData._id,
                    title: assignmentData.title,
                    totalPoints: assignmentData.totalPoints || 0
                } : { title: 'Assignment', totalPoints: 0 },
                time: answers.time || "0:00",
                total: answers.total || 0,
                questionsNumber: answers.questionsNumber || 0
            },
            report
        });

    } catch (error) {
        console.error('getStudentOwnReport error:', error.message);
        return res.json({ 
            message: "success",
            answers: {
                assignment: { title: 'Assignment Report', totalPoints: 0 },
                time: "0:00",
                total: 0,
                questionsNumber: 0
            },
            report: { questions: [] }
        });
    }
};

// Debug endpoint to inspect answer documents
const debugAnswerDocument = async (req, res) => {
    try {
        const { studentID, assignmentID } = req.params;
        
        const answer = await answerModel.findOne({ 
            solveBy: studentID, 
            assignment: assignmentID 
        }).populate('assignment').populate('questions.question');
        
        if (!answer) {
            return res.json({
                found: false,
                message: 'No answer document found for this student/assignment'
            });
        }
        
        const debugInfo = {
            found: true,
            documentId: answer._id,
            studentId: answer.solveBy,
            assignmentId: answer.assignment?._id,
            assignmentTitle: answer.assignment?.title,
            time: answer.time,
            total: answer.total,
            questionsNumber: answer.questionsNumber,
            questionsCount: answer.questions.length,
            questions: answer.questions.map((q, index) => ({
                index: index + 1,
                questionId: q.question?._id,
                questionText: q.question?.question?.substring(0, 50) + '...',
                questionType: q.question?.typeOfAnswer,
                firstAnswer: q.firstAnswer,
                secondAnswer: q.secondAnswer,
                isCorrect: q.isCorrect,
                point: q.point,
                attempts: q.attempts
            }))
        };
        
        res.json(debugInfo);
        
    } catch (error) {
        console.error('Debug endpoint error:', error);
        res.status(500).json({ error: error.message });
    }
};

// Get all attempts for a student on an assignment
const getAllAttempts = async (req, res) => {
    try {
        const { assignmentID } = req.params;
        const studentID = req.userData._id;

        // Find all answer documents for this student and assignment
        const allAttempts = await answerModel.find({
            solveBy: studentID,
            assignment: assignmentID
        }).sort({ attemptNumber: 1 }).select('attemptNumber total time completedAt createdAt');

        // Get assignment details for context
        const assignment = await assignmentModel.findById(assignmentID).select('title totalPoints attemptsNumber students');
        const studentRecord = assignment.students?.find(s => String(s.solveBy) === String(studentID));
        const currentAttemptNumber = studentRecord?.attempts || 0;

        // Calculate statistics
        const completedAttempts = allAttempts.filter(a => a.completedAt);
        const scores = completedAttempts.map(a => a.total || 0);
        const bestScore = scores.length > 0 ? Math.max(...scores) : 0;
        const averageScore = scores.length > 0 ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;

        res.json({
            message: "success",
            attempts: allAttempts,
            statistics: {
                totalAttempts: allAttempts.length,
                completedAttempts: completedAttempts.length,
                currentAttempt: currentAttemptNumber,
                remainingAttempts: Math.max(0, assignment.attemptsNumber - currentAttemptNumber),
                maxAttempts: assignment.attemptsNumber,
                bestScore: bestScore,
                averageScore: Math.round(averageScore * 100) / 100,
                totalPossiblePoints: assignment.totalPoints
            }
        });
    } catch (error) {
        console.error('getAllAttempts error:', error);
        res.status(500).json({ message: error.message });
    }
};

// Emergency submit - called via sendBeacon when browser/app closes mid-exam
const emergencySubmit = async (req, res) => {
    try {
        let body = req.body;
        // sendBeacon sends a Blob; express may not parse it automatically
        if (!body || !body.assignmentID) {
            const chunks = [];
            for await (const chunk of req) chunks.push(chunk);
            try { body = JSON.parse(Buffer.concat(chunks).toString()); } catch (e) { body = {}; }
        }

        const { assignmentID, time } = body;
        if (!assignmentID) return res.status(400).json({ message: 'assignmentID required' });

        // Find the most recent incomplete answer for this assignment
        // We can't trust req.userData here (sendBeacon may not send auth header reliably),
        // so we find any unfinished answer for this assignment and mark it complete.
        const assignmentObjId = mongoose.Types.ObjectId.isValid(assignmentID)
            ? new mongoose.Types.ObjectId(assignmentID)
            : null;

        if (!assignmentObjId) return res.status(400).json({ message: 'invalid assignmentID' });

        const incompleteAnswer = await answerModel.findOne({
            assignment: assignmentObjId,
            completedAt: null,
            questionsNumber: { $gt: 0 }
        }).sort({ createdAt: -1 });

        if (incompleteAnswer) {
            // Run scoring pass on existing answers
            const assignment = await assignmentModel.findById(assignmentID).populate({
                path: 'questions',
                select: 'questionPoints correctAnswer typeOfAnswer answer correctPicAnswer autoCorrect'
            });

            let studentTotalScore = 0;
            if (assignment && assignment.questions) {
                assignment.questions.forEach(question => {
                    if (!question) return;
                    const studentAnswerForQuestion = incompleteAnswer.questions.find(
                        ans => ans && ans.question && (ans.question._id || ans.question).toString() === question._id.toString()
                    );
                    if (studentAnswerForQuestion) {
                        const isCorrect = checkAnswer(question, studentAnswerForQuestion.firstAnswer);
                        if (isCorrect) {
                            studentTotalScore += (question.questionPoints || 0);
                            studentAnswerForQuestion.point = question.questionPoints || 0;
                        } else {
                            studentAnswerForQuestion.point = 0;
                        }
                        studentAnswerForQuestion.isCorrect = isCorrect;
                    }
                });
            }

            incompleteAnswer.total = studentTotalScore;
            incompleteAnswer.time = time || '0:00';
            incompleteAnswer.completedAt = new Date();
            await incompleteAnswer.save();
        }

        return res.status(200).json({ message: 'success' });
    } catch (error) {
        console.error('emergencySubmit error:', error.message);
        return res.status(200).json({ message: 'success' }); // Always 200 for sendBeacon
    }
};

module.exports = { checkAssinmentAnswer, getAssignmentAnswer, getResult, getStudentOwnReport, debugAnswerDocument, getAllAttempts, emergencySubmit }