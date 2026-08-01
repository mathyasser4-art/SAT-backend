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

        // Get current attempt number from assignment
        const assignmentDoc = await assignmentModel.findById(assignmentID);
        const studentRecord = assignmentDoc.students?.find(s => String(s.solveBy) === String(studentID));
        const currentAttemptNumber = studentRecord?.attempts || 1;

        // Find answer for THIS specific attempt
        let findAnswer = await answerModel.findOne({ 
            solveBy: studentID, 
            assignment: assignmentID,
            attemptNumber: currentAttemptNumber
        });

        // Fallback: search for any existing attempt for this student/assignment
        if (!findAnswer) {
            findAnswer = await answerModel.findOne({
                solveBy: studentID,
                assignment: assignmentID
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
                    totalSummation += question.questionPoints;

                    const studentAnswerForQuestion = findAnswer.questions.find(
                        (ans) => ans.question.toString() === question._id.toString()
                    );

                    if (studentAnswerForQuestion) {
                        let isCorrect = false;
                        
                        if (question.typeOfAnswer === 'MCQ') {
                            if (studentAnswerForQuestion.firstAnswer !== undefined && 
                                studentAnswerForQuestion.firstAnswer !== null) {
                                const normalizedStudentAnswer = normalizeAnswer(studentAnswerForQuestion.firstAnswer);
                                const normalizedCorrectAnswer = normalizeAnswer(question.correctAnswer);
                                isCorrect = normalizedCorrectAnswer === normalizedStudentAnswer;
                            }
                        } else if (question.typeOfAnswer === 'Essay') {
                            if (studentAnswerForQuestion.firstAnswer !== undefined && 
                                studentAnswerForQuestion.firstAnswer !== null && 
                                question.answer && question.answer.length > 0) {
                                const normalizedStudentAnswer = normalizeAnswer(studentAnswerForQuestion.firstAnswer, { toLowerCase: true });
                                isCorrect = question.answer.some(correctAns => {
                                    const normalizedCorrectAnswer = normalizeAnswer(correctAns, { toLowerCase: true });
                                    return normalizedCorrectAnswer === normalizedStudentAnswer;
                                });
                            }
                        } else if (question.typeOfAnswer === 'Graph') {
                            if (studentAnswerForQuestion.stepPicture && 
                                studentAnswerForQuestion.stepPicture.secure_url && 
                                question.correctPicAnswer) {
                                const normalizedStudentAnswer = normalizeAnswer(studentAnswerForQuestion.stepPicture.secure_url);
                                const normalizedCorrectAnswer = normalizeAnswer(question.correctPicAnswer);
                                isCorrect = normalizedCorrectAnswer === normalizedStudentAnswer;
                            }
                        }
                        
                        if (isCorrect) {
                            studentTotalScore += question.questionPoints;
                            studentAnswerForQuestion.point = question.questionPoints;
                        } else {
                            studentAnswerForQuestion.point = 0;
                        }
                        studentAnswerForQuestion.isCorrect = isCorrect;
                    }
                });
            }

            findAnswer.total = studentTotalScore;

            // FIX: Update questionsNumber so result popup shows correct count
            findAnswer.questionsNumber = findAnswer.questions.length;

            // FIX: Don't modify attempts when getting result
            // Attempts are incremented when student OPENS the assignment (in getAssignmentDetails)

            // Mark completion time for this attempt
            if (!findAnswer.completedAt) {
                findAnswer.completedAt = new Date();
            }

            await findAnswer.save();

            res.json({
                message: "success",
                result: {
                    total: findAnswer.total,
                    questionsNumber: findAnswer.questionsNumber,
                    time: findAnswer.time
                },
                totalSummation,
            });
        } else {
            res.status(404).json({ message: "Student answers not found" });
        }
    } catch (error) {
        console.error('getResult error:', error.message);
        res.status(500).json({ message: "An error occurred while calculating the result.", error: error.message });
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

        // Get current attempt number from assignment
        const assignment = await assignmentModel.findById(assignmentID);
        const studentRecord = assignment.students?.find(s => String(s.solveBy) === String(studentID));
        const currentAttemptNumber = studentRecord?.attempts || 1;

        // Find answer document for THIS specific attempt
        let findAnswer = await answerModel.findOne({ 
            solveBy: studentID, 
            assignment: assignmentID,
            attemptNumber: currentAttemptNumber
        });

        if (!findAnswer) {
            findAnswer = await answerModel.create({
                solveBy: studentID,
                assignment: assignmentID,
                attemptNumber: currentAttemptNumber,
                questionsNumber: 0,
                questions: []
            });
        }

        const questionIndex = findAnswer.questions.findIndex(q => q.question.toString() === questionID);

        // Determine the answer to save and check
        // FIX: Use proper null/undefined check to handle "0" answers
        const answerToSave = (questionAnswer !== undefined && questionAnswer !== null) ? questionAnswer : firstAnswer;
        
        let answerToCheck;
        let secure_url, public_id;
        
        if (question.typeOfAnswer === 'Graph' && req.file) {
            const uploadResult = await cloudinary.uploader.upload(req.file.path, { folder: `abacus-heroes/assignments/${assignmentID}/questions/${questionID}/answers` });
            secure_url = uploadResult.secure_url;
            public_id = uploadResult.public_id;
            answerToCheck = secure_url;
            
            if (questionIndex > -1) {
                findAnswer.questions[questionIndex].stepPicture = { secure_url, public_id };
            }
            fs.unlinkSync(req.file.path);
        } else {
            answerToCheck = answerToSave;
        }

        // Check if the answer is correct using the checkAnswer service
        const isCorrect = checkAnswer(question, answerToCheck);

        if (questionIndex > -1) {
            // Update existing answer
            if (question.typeOfAnswer !== 'Graph' || !req.file) {
                if (answerToSave !== undefined && answerToSave !== null) {
                    findAnswer.questions[questionIndex].firstAnswer = answerToSave;
                }
                if (secondAnswer !== undefined && secondAnswer !== null) {
                    findAnswer.questions[questionIndex].secondAnswer = secondAnswer;
                }
                if (thirdAnswer !== undefined && thirdAnswer !== null) {
                    findAnswer.questions[questionIndex].thirdAnswer = thirdAnswer;
                }
                if (fourthAnswer !== undefined && fourthAnswer !== null) {
                    findAnswer.questions[questionIndex].fourthAnswer = fourthAnswer;
                }
            }
            findAnswer.questions[questionIndex].isCorrect = isCorrect;
            findAnswer.questions[questionIndex].point = isCorrect ? question.questionPoints : 0;
        } else {
            // Add new question answer
            const newQuestionAnswer = {
                question: questionID,
                firstAnswer: (answerToSave !== undefined && answerToSave !== null && answerToSave !== '') ? answerToSave : undefined,
                secondAnswer: (secondAnswer !== undefined && secondAnswer !== null && secondAnswer !== '') ? secondAnswer : undefined,
                thirdAnswer: (thirdAnswer !== undefined && thirdAnswer !== null && thirdAnswer !== '') ? thirdAnswer : undefined,
                fourthAnswer: (fourthAnswer !== undefined && fourthAnswer !== null && fourthAnswer !== '') ? fourthAnswer : undefined,
                attempts: 1,
                isCorrect: isCorrect,
                point: isCorrect ? question.questionPoints : 0
            };

            if (question.typeOfAnswer === 'Graph' && req.file) {
                newQuestionAnswer.stepPicture = { secure_url, public_id };
            }
            findAnswer.questions.push(newQuestionAnswer);
            findAnswer.questionsNumber = findAnswer.questions.length;
        }

        await findAnswer.save();

        res.status(200).json({ 
            message: "success", 
            isCorrect: isCorrect,
            answer: findAnswer.questions[questionIndex > -1 ? questionIndex : findAnswer.questions.length - 1]
        });

    } catch (error) {
        console.error('checkAssinmentAnswer error:', error.message);
        if (req.file) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ message: "Error saving answer", error: error.message });
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

        // FIX: Prefer completed answers (with completedAt set)
        let answers = await answerModel.findOne({ 
            solveBy: studentID, 
            assignment: assignmentID,
            completedAt: { $ne: null }
        })
        .sort({ attemptNumber: -1, createdAt: -1 })
        .populate({
            path: 'assignment',
            select: 'title totalPoints questions'
        });

        // Fallback: if no completed answer, get any answer
        if (!answers) {
            answers = await answerModel.findOne({ 
                solveBy: studentID, 
                assignment: assignmentID
            })
            .sort({ attemptNumber: -1, createdAt: -1 })
            .populate({
                path: 'assignment',
                select: 'title totalPoints questions'
            });
        }

        // FIX: Always fetch the full assignment with all questions for merging
        const assignment = await assignmentModel.findById(assignmentID).populate({
            path: 'questions',
            select: 'question questionPic questionPoints typeOfAnswer correctAnswer answer correctPicAnswer'
        });

        if (!answers) {
            // No answer document at all — return template report from assignment questions
            if (!assignment) {
                return res.status(404).json({ message: "Assignment not found" });
            }

            const questions = assignment.questions || [];
            const report = {
                questions: questions.map(q => ({
                    _id: q._id,
                    questionId: q._id,
                    question: q.question || '',
                    questionPic: q.questionPic?.secure_url || null,
                    firstAnswer: 'Not answered',
                    secondAnswer: '',
                    stepsPic: null,
                    isCorrect: false,
                    notAnswer: true,
                    questionPoints: q.questionPoints || 0,
                    correctAnswer: buildCorrectAnswerStr(q),
                    typeOfAnswer: q.typeOfAnswer
                }))
            };

            return res.json({
                message: "success",
                answers: {
                    assignment: {
                        title: assignment.title,
                        totalPoints: assignment.totalPoints || 0
                    },
                    time: "0:00"
                },
                report
            });
        }

        // FIX: Build report from ALL assignment questions, merging with student answers
        // This ensures skipped/unanswered questions still appear as "Not Answered"
        const allAssignmentQuestions = assignment?.questions || [];
        
        // Also fetch question details for any answered questions not in the assignment (edge case)
        const answeredQuestionIds = answers.questions.map(q => q.question);
        const extraQuestions = await questionModel.find({
            _id: { $in: answeredQuestionIds }
        });

        // Create a lookup map of student answers by question ID
        const studentAnswerMap = {};
        (answers.questions || []).forEach(sa => {
            const qId = sa.question.toString();
            studentAnswerMap[qId] = sa;
        });

        // Build report from ALL assignment questions
        const reportQuestions = allAssignmentQuestions.map(question => {
            const qId = question._id.toString();
            const studentAnswer = studentAnswerMap[qId];

            if (studentAnswer) {
                // Student answered this question
                const hasFirstAnswer = studentAnswer.firstAnswer !== undefined && studentAnswer.firstAnswer !== null && studentAnswer.firstAnswer !== '';
                const hasSecondAnswer = studentAnswer.secondAnswer !== undefined && studentAnswer.secondAnswer !== null && studentAnswer.secondAnswer !== '';

                return {
                    _id: studentAnswer._id,
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

        // FIX: Null-safe assignment reference
        const assignmentData = answers.assignment || assignment;

        res.json({
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
        res.status(500).json({ 
            message: "An error occurred while fetching assignment answers.", 
            error: error.message 
        });
    }
};

const correctAnswer = async (req, res) => {
    try {
        const { studentID, assignmentID, questionID } = req.params;
        const { grade } = req.body;

        const findAnswer = await answerModel.findOne({ 
            solveBy: studentID, 
            assignment: assignmentID 
        });

        if (!findAnswer) {
            return res.status(404).json({ message: "Student answers not found" });
        }

        const questionIndex = findAnswer.questions.findIndex(
            q => q.question.toString() === questionID
        );

        if (questionIndex === -1) {
            return res.status(404).json({ message: "Question answer not found" });
        }

        // Update the grade and mark as correct
        findAnswer.questions[questionIndex].point = parseFloat(grade) || 0;
        findAnswer.questions[questionIndex].isCorrect = true;

        // Recalculate total
        let newTotal = 0;
        findAnswer.questions.forEach(q => {
            if (q.point !== undefined && q.point !== null) {
                newTotal += q.point;
            }
        });
        findAnswer.total = newTotal;

        await findAnswer.save();

        res.json({
            message: "success",
            updatedAnswer: findAnswer
        });

    } catch (error) {
        res.status(500).json({ 
            message: "An error occurred while correcting the answer.", 
            error: error.message 
        });
    }
};

const getStudentOwnReport = async (req, res) => {
    try {
        const { assignmentID } = req.params;
        const studentID = req.userData._id;

        // FIX: Prefer completed answers, sort by latest attempt
        let answers = await answerModel.findOne({ 
            solveBy: studentID, 
            assignment: assignmentID,
            completedAt: { $ne: null }
        })
        .sort({ attemptNumber: -1, createdAt: -1 })
        .populate({
            path: 'assignment',
            select: 'title totalPoints questions'
        });

        // Fallback: if no completed answer, get any answer
        if (!answers) {
            answers = await answerModel.findOne({ 
                solveBy: studentID, 
                assignment: assignmentID
            })
            .sort({ attemptNumber: -1, createdAt: -1 })
            .populate({
                path: 'assignment',
                select: 'title totalPoints questions'
            });
        }

        // FIX: Always fetch full assignment with all questions for merging
        const assignment = await assignmentModel.findById(assignmentID).populate({
            path: 'questions',
            select: 'question questionPic questionPoints typeOfAnswer correctAnswer answer correctPicAnswer'
        });

        if (!answers) {
            // No answer document — but if assignment exists, show all questions as unanswered
            if (assignment) {
                const questions = assignment.questions || [];
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
                        assignment: { _id: assignment._id, title: assignment.title, totalPoints: assignment.totalPoints || 0 },
                        time: "0:00",
                        total: 0,
                        questionsNumber: 0
                    },
                    report
                });
            }
            return res.status(404).json({ message: "the student closed the assignment before completing it" });
        }

        // FIX: Build report from ALL assignment questions, merging with student answers
        const allAssignmentQuestions = assignment?.questions || [];

        // Create a lookup map of student answers by question ID
        const studentAnswerMap = {};
        (answers.questions || []).forEach(sa => {
            if (sa && sa.question) {
                const qId = (sa.question._id || sa.question).toString();
                studentAnswerMap[qId] = sa;
            }
        });

        // Build report from ALL assignment questions
        const reportQuestions = allAssignmentQuestions.map(question => {
            const qId = question._id.toString();
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

        // FIX: Null-safe assignment reference
        const assignmentData = answers.assignment || assignment;

        res.json({
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
        res.status(500).json({ 
            message: "An error occurred while fetching your assignment report.", 
            error: error.message 
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

module.exports = { checkAssinmentAnswer, getAssignmentAnswer, getResult, getStudentOwnReport, debugAnswerDocument, getAllAttempts }