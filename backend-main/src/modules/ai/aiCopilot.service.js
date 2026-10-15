const assignmentModel = require('../../../DB/models/assignment.model');
const answerModel = require('../../../DB/models/answer.model');
const userModel = require('../../../DB/models/user.model');
const classModel = require('../../../DB/models/class.model');
const questionModel = require('../../../DB/models/question.model');
const courseModel = require('../../../DB/models/course.model');
const { GoogleGenAI } = require('@google/genai');
const mongoose = require('mongoose');

/**
 * Helper to strip markdown symbols for smooth, natural Text-to-Speech playback
 */
function cleanForVoice(text) {
    if (!text) return '';
    return text
        .replace(/[*#_`~>\[\]\(\)\\]/g, '') // remove markdown symbols
        .replace(/\n+/g, '. ')               // replace newlines with natural pauses
        .replace(/\s+/g, ' ')                // collapse whitespace
        .trim();
}

/**
 * Detect language: Arabic vs English
 */
function isArabic(text) {
    const arabicRegex = /[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]/;
    return arabicRegex.test(text || '');
}

/**
 * Tool: Get Homework / Assignment Audit (Who did it, who didn't, scores)
 */
async function auditHomework({ query, userData }) {
    if (mongoose.connection.readyState !== 1) {
        return { found: false, message: "Database is not connected" };
    }
    try {
        let filter = {};
        
        // If teacher, filter by teacher's created assignments or general
        if (userData && userData.role === 'Teacher') {
            filter.createdBy = userData._id;
        }

        // Search assignment by title if query provided
        let targetAssignment = null;
        if (query && query.trim().length > 1) {
            targetAssignment = await assignmentModel.findOne({
                ...filter,
                title: { $regex: query.trim(), $options: 'i' }
            }).sort({ _id: -1 }).populate('classes');
        }

        // If not found or no query, get the latest assignment
        if (!targetAssignment) {
            targetAssignment = await assignmentModel.findOne(filter)
                .sort({ _id: -1 })
                .populate('classes');
        }

        if (!targetAssignment) {
            return {
                found: false,
                message: "No assignments found in the system yet."
            };
        }

        const assignmentID = targetAssignment._id;

        // 1. Get all answers submitted
        const answers = await answerModel.find({ assignment: assignmentID })
            .populate('solveBy', 'userName email phone parentPhone class')
            .select('total questionsNumber time createdAt completedAt solveBy attemptNumber questions');

        // 2. Get all assigned students
        let assignedStudents = [];
        if (targetAssignment.classes && targetAssignment.classes.length > 0) {
            const classIds = targetAssignment.classes.map(c => c._id || c);
            assignedStudents = await userModel.find({
                role: 'Student',
                class: { $in: classIds },
                disable: { $ne: true }
            }).select('userName email phone parentPhone class');
        }

        // Fallback: If no class assigned or none found, use answer submissions
        if (assignedStudents.length === 0) {
            assignedStudents = answers.filter(a => a.solveBy).map(a => a.solveBy);
        }

        // Deduplicate students
        const studentMap = new Map();
        assignedStudents.forEach(st => {
            if (st && st._id) studentMap.set(st._id.toString(), st);
        });
        const allStudents = Array.from(studentMap.values());

        // Find submitted vs not submitted
        const submittedStudentIds = new Set();
        const submittedList = [];

        answers.forEach(ans => {
            if (ans.solveBy && ans.solveBy._id) {
                const sId = ans.solveBy._id.toString();
                if (!submittedStudentIds.has(sId)) {
                    submittedStudentIds.add(sId);
                    submittedList.push({
                        id: sId,
                        name: ans.solveBy.userName || 'Unknown',
                        score: ans.total || 0,
                        time: ans.time || 'N/A'
                    });
                }
            }
        });

        const notSubmittedList = allStudents
            .filter(st => !submittedStudentIds.has(st._id.toString()))
            .map(st => ({
                id: st._id,
                name: st.userName,
                phone: st.phone || 'N/A',
                parentPhone: st.parentPhone || 'N/A',
                email: st.email
            }));

        const totalEnrolled = allStudents.length;
        const totalSubmitted = submittedList.length;
        const totalPending = notSubmittedList.length;
        const completionRate = totalEnrolled > 0 ? Math.round((totalSubmitted / totalEnrolled) * 100) : 0;
        const avgScore = totalSubmitted > 0 ? Math.round(submittedList.reduce((acc, curr) => acc + (curr.score || 0), 0) / totalSubmitted) : 0;

        return {
            found: true,
            assignmentTitle: targetAssignment.title || 'Recent Assignment',
            assignmentId: targetAssignment._id,
            endDate: targetAssignment.endDate || 'No deadline',
            totalEnrolled,
            totalSubmitted,
            totalPending,
            completionRate,
            avgScore,
            submitted: submittedList,
            notSubmitted: notSubmittedList
        };
    } catch (err) {
        console.error("auditHomework Error:", err);
        return { found: false, error: err.message };
    }
}

/**
 * Tool: Lookup Student Progress
 */
async function lookupStudent({ studentName }) {
    if (mongoose.connection.readyState !== 1) {
        return { found: false, message: "Database is not connected" };
    }
    try {
        const student = await userModel.findOne({
            role: 'Student',
            userName: { $regex: studentName.trim(), $options: 'i' }
        }).select('userName email phone parentPhone class createdAt');

        if (!student) {
            return { found: false, message: `Student '${studentName}' was not found.` };
        }

        const answers = await answerModel.find({ solveBy: student._id })
            .populate('assignment', 'title totalPoints')
            .sort({ createdAt: -1 })
            .limit(10);

        const totalAttempts = answers.length;
        const avgScore = totalAttempts > 0
            ? Math.round(answers.reduce((sum, a) => sum + (a.total || 0), 0) / totalAttempts)
            : 0;

        return {
            found: true,
            student: {
                id: student._id,
                name: student.userName,
                email: student.email,
                phone: student.phone || 'N/A',
                parentPhone: student.parentPhone || 'N/A'
            },
            totalSubmissions: totalAttempts,
            averageScore: avgScore,
            recentAssignments: answers.map(a => ({
                title: a.assignment ? a.assignment.title : 'Assignment',
                score: a.total,
                date: a.createdAt
            }))
        };
    } catch (err) {
        console.error("lookupStudent Error:", err);
        return { found: false, error: err.message };
    }
}

/**
 * Tool: Platform Overview & Statistics
 */
async function getPlatformOverview() {
    if (mongoose.connection.readyState !== 1) {
        return null;
    }
    try {
        const [totalStudents, totalTeachers, totalClasses, totalAssignments, totalQuestions, totalCourses] = await Promise.all([
            userModel.countDocuments({ role: 'Student', disable: { $ne: true } }),
            userModel.countDocuments({ role: 'Teacher', disable: { $ne: true } }),
            classModel.countDocuments(),
            assignmentModel.countDocuments(),
            questionModel.countDocuments(),
            courseModel.countDocuments()
        ]);

        return {
            totalStudents,
            totalTeachers,
            totalClasses,
            totalAssignments,
            totalQuestions,
            totalCourses
        };
    } catch (err) {
        console.error("getPlatformOverview Error:", err);
        return null;
    }
}

/**
 * Tool: Solve SAT Question from Student Perspective
 */
async function solveQuestion({ questionText, questionId }) {
    if (mongoose.connection.readyState !== 1) {
        return { found: false, message: "Database is not connected" };
    }
    try {
        let questionData = null;
        if (questionId) {
            questionData = await questionModel.findById(questionId).populate('chapter');
        } else if (questionText) {
            questionData = await questionModel.findOne({
                question: { $regex: questionText.trim().slice(0, 30), $options: 'i' }
            }).populate('chapter');
        }

        return {
            found: !!questionData,
            question: questionData ? {
                text: questionData.question,
                pic: questionData.questionPic,
                type: questionData.typeOfAnswer,
                choices: questionData.wrongAnswer ? [questionData.correctAnswer, ...questionData.wrongAnswer] : [],
                correctAnswer: questionData.correctAnswer || (questionData.answer ? questionData.answer[0] : null),
                explanation: questionData.explanation
            } : null
        };
    } catch (err) {
        console.error("solveQuestion Error:", err);
        return { found: false, error: err.message };
    }
}

/**
 * Master Copilot Chat Function
 */
async function processCopilotChat({ message, userData, history = [] }) {
    const rawMessage = (message || '').trim();
    const inArabic = isArabic(rawMessage);
    const lowerMsg = rawMessage.toLowerCase();

    // 1. Detect Intent
    const isHwIntent = /hw|homework|assignment|who did|who didn't|who submitted|pending|واجب|الهووم وورك|مين عمل|مين معملش|تسليم/i.test(lowerMsg);
    const isStudentIntent = /student|score|grades|how is|performance|طالب|درجات|مستوى/i.test(lowerMsg) && !isHwIntent;
    const isStatsIntent = /how many|stats|statistics|platform|overview|كام طالب|احصائيات|عدد الطلاب|المنصة/i.test(lowerMsg);
    const isSolveIntent = /solve|explain|question|math|geometry|حل|اشرح|سؤال|المسألة/i.test(lowerMsg);

    let toolData = null;
    let toolType = 'general';

    if (isHwIntent) {
        toolType = 'homework_audit';
        // Extract assignment title query if mentioned
        toolData = await auditHomework({ query: rawMessage, userData });
    } else if (isStudentIntent) {
        toolType = 'student_lookup';
        // Simple name extractor
        const words = rawMessage.split(/\s+/).filter(w => w.length > 2);
        const candidateName = words[words.length - 1] || '';
        toolData = await lookupStudent({ studentName: candidateName });
    } else if (isStatsIntent) {
        toolType = 'platform_stats';
        toolData = await getPlatformOverview();
    } else if (isSolveIntent) {
        toolType = 'solve_question';
        toolData = await solveQuestion({ questionText: rawMessage });
    }

    // 2. Formulate Prompt for Gemini
    const systemInstruction = `You are the official intelligent AI Assistant & Copilot for "SAT Area / Mr. Shahin".
You are helpful, professional, encouraging, and clear.
You support both English and Arabic fluently. If the user writes or speaks in Arabic, reply in natural Arabic (professional yet friendly Egyptian/Modern Arabic). If English, reply in English.
Provide clear markdown formatting for the visual response.
Always provide factual answers based on the database data provided below.
If asked about who completed or did not complete homework, explicitly list the names of students who did not submit.`;

    const contextPayload = {
        user: {
            name: userData?.userName || 'Teacher / Admin',
            role: userData?.role || 'Teacher'
        },
        detectedIntent: toolType,
        databaseData: toolData
    };

    let reply = '';
    let voiceText = '';

    // 3. Try calling Gemini API
    const geminiKey = process.env.GEMINI_API_KEY;
    if (geminiKey) {
        try {
            const ai = new GoogleGenAI({ apiKey: geminiKey });
            const prompt = `System Instructions:
${systemInstruction}

Current Platform Database Context:
${JSON.stringify(contextPayload, null, 2)}

User Request:
"${rawMessage}"

Please provide your intelligent answer. Include markdown highlights and formatting.`;

            // Use configured model or latest gemini-3.8-flash
            const response = await ai.models.generateContent({
                model: process.env.AI_MODEL || 'gemini-3.8-flash',
                contents: prompt,
            });

            if (response && response.text) {
                reply = response.text;
                voiceText = cleanForVoice(reply);
            }
        } catch (apiErr) {
            console.warn("Gemini API call failed, using smart internal response engine:", apiErr.message);
        }
    }

    // 4. Fallback Engine: If Gemini is unavailable or not configured, generate smart native responses
    if (!reply) {
        if (toolType === 'homework_audit' && toolData) {
            if (toolData.found) {
                if (inArabic) {
                    const pendingNames = toolData.notSubmitted.map(s => `• **${s.name}** (${s.phone !== 'N/A' ? s.phone : 'بدون هاتف'})`).join('\n');
                    reply = `### 📋 تقرير الواجب: "${toolData.assignmentTitle}"\n\n` +
                        `* **إجمالي الطلاب:** ${toolData.totalEnrolled} طالب\n` +
                        `* ✅ **تم التسليم:** ${toolData.totalSubmitted} طالب (${toolData.completionRate}%)\n` +
                        `* ⏳ **لم يسلموا بعد:** ${toolData.totalPending} طالب\n` +
                        `* 📊 **متوسط الدرجات:** ${toolData.avgScore} نقطة\n\n` +
                        (toolData.totalPending > 0
                            ? `#### ⚠️ الطلاب الذين لم يسلموا الواجب بعد:\n${pendingNames}\n\n*هل ترغب في إرسال تنبيه أو رسالة تذكير لهم؟*`
                            : `🎉 **ممتاز! جميع الطلاب قاموا بتسليم الواجب.**`);

                    voiceText = `في واجب ${toolData.assignmentTitle}، سلم ${toolData.totalSubmitted} طالب من أصل ${toolData.totalEnrolled}. ` +
                        (toolData.totalPending > 0
                            ? `يوجد ${toolData.totalPending} طلاب لم يسلموا بعد، وهم: ${toolData.notSubmitted.slice(0, 5).map(s => s.name).join('، ')}.`
                            : `جميع الطلاب سلموا الواجب بنجاح.`);
                } else {
                    const pendingNames = toolData.notSubmitted.map(s => `• **${s.name}** (Phone: ${s.phone})`).join('\n');
                    reply = `### 📋 Homework Report: "${toolData.assignmentTitle}"\n\n` +
                        `* **Total Enrolled:** ${toolData.totalEnrolled} students\n` +
                        `* ✅ **Submitted:** ${toolData.totalSubmitted} (${toolData.completionRate}%)\n` +
                        `* ⏳ **Pending (Not Submitted):** ${toolData.totalPending}\n` +
                        `* 📊 **Average Score:** ${toolData.avgScore} pts\n\n` +
                        (toolData.totalPending > 0
                            ? `#### ⚠️ Students who have NOT submitted yet:\n${pendingNames}\n\n*Would you like to send them a reminder?*`
                            : `🎉 **Great job! All students have completed this assignment.**`);

                    voiceText = `For ${toolData.assignmentTitle}, ${toolData.totalSubmitted} out of ${toolData.totalEnrolled} students submitted. ` +
                        (toolData.totalPending > 0
                            ? `There are ${toolData.totalPending} students pending, including ${toolData.notSubmitted.slice(0, 5).map(s => s.name).join(', ')}.`
                            : `All students have submitted successfully.`);
                }
            } else {
                reply = inArabic
                    ? `لم أجد أي واجبات مطابقة في الوقت الحالي. يمكنك تحديد اسم الواجب أو إنشاء واجب جديد.`
                    : `I couldn't find any matching assignments at this moment. You can specify the assignment title or check your classes.`;
                voiceText = cleanForVoice(reply);
            }
        } else if (toolType === 'platform_stats' && toolData) {
            if (inArabic) {
                reply = `### 📊 نظرة عامة على منصة SAT Area / مستر شاهين:\n\n` +
                    `* 🎓 **الطلاب النشطون:** ${toolData.totalStudents}\n` +
                    `* 👨‍🏫 **المعلمون:** ${toolData.totalTeachers}\n` +
                    `* 🏫 **الفصول الدراسية:** ${toolData.totalClasses}\n` +
                    `* 📝 **الواجبات والامتحانات:** ${toolData.totalAssignments}\n` +
                    `* 📚 **بنك الأسئلة:** ${toolData.totalQuestions} سؤال\n` +
                    `* 🎓 **الدورات التدريبية:** ${toolData.totalCourses}`;
                voiceText = `المنصة تضم حالياً ${toolData.totalStudents} طالباً و ${toolData.totalClasses} فصول دراسية، مع ${toolData.totalQuestions} سؤال في بنك الأسئلة.`;
            } else {
                reply = `### 📊 Platform Overview (SAT Area / Mr. Shahin):\n\n` +
                    `* 🎓 **Active Students:** ${toolData.totalStudents}\n` +
                    `* 👨‍🏫 **Teachers:** ${toolData.totalTeachers}\n` +
                    `* 🏫 **Classes:** ${toolData.totalClasses}\n` +
                    `* 📝 **Assignments / Tests:** ${toolData.totalAssignments}\n` +
                    `* 📚 **Question Bank:** ${toolData.totalQuestions} questions\n` +
                    `* 🎓 **Courses:** ${toolData.totalCourses}`;
                voiceText = `The platform currently has ${toolData.totalStudents} students, ${toolData.totalClasses} classes, and ${toolData.totalQuestions} questions in the question bank.`;
            }
        } else {
            if (inArabic) {
                reply = `أهلاً بك! أنا المساعد الذكي لمنصة **SAT Area / مستر شاهين**. \n\n` +
                    `يمكنك سؤالي صوتياً 🎙️ أو كتابةً عن:\n` +
                    `* من سلم أو لم يسلم الواجبات والامتحانات.\n` +
                    `* مستوى ودرجات الطلاب.\n` +
                    `* حل أسئلة الـ SAT وشرحها خطوة بخطوة من منظور الطالب.\n` +
                    `* إحصائيات المنصة وإرشادات الاستخدام.`;
                voiceText = `أهلاً بك في منصة مستر شاهين. كيف يمكنني مساعدتك اليوم؟`;
            } else {
                reply = `Hello! I am your AI Copilot for **SAT Area / Mr. Shahin**.\n\n` +
                    `You can ask me via Voice 🎙️ or Text about:\n` +
                    `* Who did and who didn't submit homework or tests.\n` +
                    `* Student performance and score breakdowns.\n` +
                    `* Solving SAT questions step-by-step with student explanations.\n` +
                    `* Platform statistics and navigation help.`;
                voiceText = `Hello! I am your SAT Area AI Assistant. How can I help you today?`;
            }
        }
    }

    return {
        reply,
        voiceText: voiceText || cleanForVoice(reply),
        language: inArabic ? 'ar' : 'en',
        data: toolData,
        intent: toolType
    };
}

module.exports = {
    processCopilotChat,
    auditHomework,
    lookupStudent,
    getPlatformOverview,
    solveQuestion
};
