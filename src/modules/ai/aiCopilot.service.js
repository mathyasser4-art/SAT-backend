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
 * Action Tool: Assign Homework / Practice to Student or Class
 */
async function assignHomework({ studentName, className, topic, questionCount = 5, title, timer = 0, userData }) {
    if (mongoose.connection.readyState !== 1) {
        return { success: false, message: "Database is not connected" };
    }
    try {
        let targetStudents = [];
        let targetClasses = [];
        let resolvedStudent = null;
        let resolvedClass = null;

        // 1. Resolve Target Student
        if (studentName && studentName.trim().length > 0) {
            const cleanName = studentName.trim();
            const matchingStudents = await userModel.find({
                role: 'Student',
                userName: { $regex: cleanName, $options: 'i' }
            }).select('_id userName email class role').populate('class');

            let candidates = matchingStudents;
            if (candidates.length === 0) {
                candidates = await userModel.find({
                    userName: { $regex: cleanName, $options: 'i' }
                }).select('_id userName email class role').populate('class');
            }

            if (candidates.length === 0) {
                return {
                    success: false,
                    notFound: true,
                    studentName: cleanName,
                    message: `No student named "${cleanName}" exists in the database.`
                };
            }

            if (candidates.length > 1) {
                return {
                    success: false,
                    ambiguous: true,
                    studentName: cleanName,
                    candidates: candidates.map(s => ({
                        id: s._id,
                        name: s.userName,
                        email: s.email,
                        className: s.class ? s.class.class : 'No Class'
                    }))
                };
            }

            // Exactly 1 student resolved
            resolvedStudent = candidates[0];
            targetStudents.push({ solveBy: resolvedStudent._id, attempts: 0 });
            if (resolvedStudent.class && resolvedStudent.class._id) {
                targetClasses.push(resolvedStudent.class._id);
            }
        }

        // 2. Resolve Target Class
        if (className && className.trim().length > 0) {
            resolvedClass = await classModel.findOne({
                class: { $regex: className.trim(), $options: 'i' }
            });
            if (resolvedClass) {
                targetClasses.push(resolvedClass._id);
                const classStudents = await userModel.find({
                    role: 'Student',
                    class: resolvedClass._id,
                    disable: { $ne: true }
                }).select('_id userName');
                classStudents.forEach(st => {
                    if (!targetStudents.some(s => s.solveBy.toString() === st._id.toString())) {
                        targetStudents.push({ solveBy: st._id, attempts: 0 });
                    }
                });
            }
        }

        // Fallback: If neither student nor class resolved, assign to first available class or default
        if (targetStudents.length === 0 && targetClasses.length === 0) {
            const defaultClass = await classModel.findOne();
            if (defaultClass) {
                targetClasses.push(defaultClass._id);
                resolvedClass = defaultClass;
            }
        }

        // 3. Find matching questions from question bank
        const limitCount = Math.max(1, Math.min(questionCount || 5, 25));
        let selectedQuestions = [];

        if (topic && topic.trim().length > 1 && !/general|sat|any/i.test(topic.trim())) {
            const cleanTopic = topic.trim();
            selectedQuestions = await questionModel.find({
                $or: [
                    { topic: { $regex: cleanTopic, $options: 'i' } },
                    { question: { $regex: cleanTopic, $options: 'i' } }
                ]
            }).limit(limitCount);
        }

        if (selectedQuestions.length === 0) {
            selectedQuestions = await questionModel.find().sort({ _id: -1 }).limit(limitCount);
        }

        if (selectedQuestions.length === 0) {
            return {
                success: false,
                message: "No questions found in the question bank to assign."
            };
        }

        const questionIds = selectedQuestions.map(q => q._id);
        const totalPoints = selectedQuestions.reduce((acc, q) => acc + (q.questionPoints || 1), 0);

        // 4. Generate title and dates
        const topicName = topic && !/general/i.test(topic) ? topic.trim() : 'SAT Practice';
        const targetName = resolvedStudent ? resolvedStudent.userName : (resolvedClass ? resolvedClass.class : (studentName || 'Students'));
        const finalTitle = title || `${topicName} - ${targetName}`;

        const today = new Date().toISOString().slice(0, 10);
        const nextWeek = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

        const newAssignment = new assignmentModel({
            title: finalTitle,
            questions: questionIds,
            classes: targetClasses,
            students: targetStudents,
            createdBy: userData?._id,
            createdAt: today,
            startDate: today,
            endDate: nextWeek,
            timer: timer || 0,
            attemptsNumber: 1,
            explanationMode: 'independent',
            totalPoints: totalPoints
        });

        await newAssignment.save();

        return {
            success: true,
            assignment: {
                id: newAssignment._id,
                title: newAssignment.title,
                studentName: resolvedStudent ? resolvedStudent.userName : null,
                studentEmail: resolvedStudent ? resolvedStudent.email : null,
                studentClass: resolvedStudent && resolvedStudent.class ? resolvedStudent.class.class : null,
                className: resolvedClass ? resolvedClass.class : null,
                questionsCount: questionIds.length,
                totalPoints: totalPoints,
                startDate: today,
                endDate: nextWeek
            }
        };
    } catch (err) {
        console.error("assignHomework Error:", err);
        return { success: false, error: err.message };
    }
}

/**
 * Master Copilot Chat Function
 */
async function processCopilotChat({ message, userData, history = [] }) {
    const rawMessage = (message || '').trim();
    const inArabic = isArabic(rawMessage);

    const systemInstruction = `You are the official intelligent AI Assistant & Copilot for "SAT Area / Mr. Shahin".
You are helpful, professional, encouraging, and clear.
You support both English and Arabic fluently (when Arabic is used, reply in natural, friendly Modern/Egyptian Arabic).
Provide clear markdown formatting for visual responses.

Available Actions & Tools:
1. assign_homework: Call this whenever the user asks to assign, create, or give homework, practice, quiz, or test to a student (e.g. "can you assign hw to adam?") or a class. Always invoke this tool directly with default questionCount: 5 if not specified.
2. audit_homework: Call this ONLY when the user asks who submitted or who did not submit homework, or asks for a homework status report. DO NOT call this for general homework questions or requests to create/assign homework!
3. lookup_student: Call this when the user asks about a student's grades, scores, or performance.
4. get_platform_stats: Call this when the user asks for platform statistics, number of students, teachers, or courses.
5. Educational & Math Questions: If the user asks how to solve a question, SAT math problem, grammar rule, or general advice, answer directly with clear step-by-step explanations, formulas, and encouraging tone without calling audit tools.`;

    const tools = [{
        functionDeclarations: [
            {
                name: 'assign_homework',
                description: 'Creates and assigns homework or practice questions to a student or class in the SAT platform. Always invoke this when the user asks to assign, create, or give homework/test.',
                parameters: {
                    type: 'OBJECT',
                    properties: {
                        studentName: { type: 'STRING', description: 'Name of the student to assign to (e.g. Adam)' },
                        className: { type: 'STRING', description: 'Name of the class or group' },
                        topic: { type: 'STRING', description: 'Topic or chapter e.g. Circles, Linear Equations, Algebra' },
                        questionCount: { type: 'INTEGER', description: 'Number of questions (default: 5)' },
                        timer: { type: 'INTEGER', description: 'Time limit in minutes if requested' }
                    }
                }
            },
            {
                name: 'audit_homework',
                description: 'Checks who completed or did not complete an existing assignment and provides submission stats. Use ONLY when asked who did/did not submit homework or for assignment reports.',
                parameters: {
                    type: 'OBJECT',
                    properties: {
                        assignmentTitle: { type: 'STRING', description: 'Title or query of the assignment to check. Leave empty to check the latest.' }
                    }
                }
            },
            {
                name: 'lookup_student',
                description: 'Looks up a student progress, submissions, and average scores.',
                parameters: {
                    type: 'OBJECT',
                    properties: {
                        studentName: { type: 'STRING', description: 'Name of the student to look up' }
                    },
                    required: ['studentName']
                }
            },
            {
                name: 'get_platform_stats',
                description: 'Gets platform overview metrics (students, teachers, questions, classes).',
                parameters: {
                    type: 'OBJECT',
                    properties: {}
                }
            }
        ]
    }];

    let reply = '';
    let voiceText = '';
    let toolData = null;
    let detectedIntent = 'general';

    // 1. Try calling Gemini API
    const geminiKey = process.env.GEMINI_API_KEY;
    let apiErrorMsg = null;

    if (!geminiKey) {
        reply = inArabic
            ? `⚠️ مفتاح الذكاء الاصطناعي (GEMINI_API_KEY) غير متاح في إعدادات الخادم (Railway). يرجى التأكد من الضغط على Deploy للمتغيرات المحفوظة.`
            : `⚠️ GEMINI_API_KEY is not set on the server environment. If you staged it in Railway, please click "Deploy Changes" in your Railway dashboard to make it live.`;
        voiceText = cleanForVoice(reply);
    } else {
        try {
            const ai = new GoogleGenAI({ apiKey: geminiKey });
            const candidateModels = [
                'gemini-3.5-flash',
                'gemini-3.7-flash',
                process.env.AI_MODEL,
                'gemini-flash-latest',
                'gemini-3.8-flash'
            ].filter(Boolean);

            let response = null;
            let lastErr = null;

            for (const model of candidateModels) {
                try {
                    response = await ai.models.generateContent({
                        model,
                        contents: rawMessage,
                        config: {
                            systemInstruction,
                            tools
                        }
                    });
                    if (response) break;
                } catch (mErr) {
                    lastErr = mErr;
                    console.warn(`Gemini model ${model} error (${mErr.message.slice(0, 80)}), trying next fallback model...`);
                }
            }

            if (!response) {
                throw lastErr || new Error("All candidate Gemini models failed.");
            }

            if (response && response.functionCalls && response.functionCalls.length > 0) {
                const call = response.functionCalls[0];
                const fnName = call.name;
                const args = call.args || {};

                if (fnName === 'assign_homework') {
                    detectedIntent = 'assign_homework';
                    toolData = await assignHomework({ ...args, userData });
                    if (toolData.ambiguous) {
                        const list = toolData.candidates.map(c => `• **${c.name}** (${c.className} • ${c.email})`).join('\n');
                        reply = inArabic
                            ? `### ⚠️ وجدت أكثر من طالب باسم "${toolData.studentName}":\n\n${list}\n\n*يرجى تحديد اسم الطالب بالكامل أو فصله لتكليفه بالواجب.*`
                            : `### ⚠️ I found multiple students matching "${toolData.studentName}":\n\n${list}\n\n*Please specify the full student name or their class to assign the homework.*`;
                        voiceText = inArabic
                            ? `وجدت أكثر من طالب باسم ${toolData.studentName}. يرجى تحديد الطالب المطلوب.`
                            : `I found multiple students named ${toolData.studentName}. Please specify which one you mean.`;
                    } else if (toolData.notFound) {
                        reply = inArabic
                            ? `### ⚠️ لم يتم العثور على طالب باسم "${toolData.studentName}"\n\n* لا يوجد طالب بهذا الاسم مسجل في النظام حالياً.\n* يمكنك التحقق من قائمة الطلاب أو تعيين الواجب لفصل دراسي كامل.`
                            : `### ⚠️ No student found with the name "${toolData.studentName}"\n\n* No user with this name is registered in your student database.\n* Please check the student's name or assign the homework to a class instead.`;
                        voiceText = inArabic
                            ? `لم يتم العثور على طالب مسجل باسم ${toolData.studentName}.`
                            : `No student named ${toolData.studentName} was found in the database.`;
                    } else if (toolData.success) {
                        const asgn = toolData.assignment;
                        const studentDetails = asgn.studentName
                            ? `**${asgn.studentName}** ${asgn.studentClass ? `(${asgn.studentClass} • ${asgn.studentEmail})` : `(${asgn.studentEmail})`}`
                            : (asgn.className ? `فصل: **${asgn.className}**` : 'الطلاب');
                        const studentDetailsEn = asgn.studentName
                            ? `Student: **${asgn.studentName}** ${asgn.studentClass ? `(${asgn.studentClass} • ${asgn.studentEmail})` : `(${asgn.studentEmail})`}`
                            : (asgn.className ? `Class: **${asgn.className}**` : 'Students');

                        if (inArabic) {
                            reply = `### ✅ تم تكليف الواجب بنجاح!\n\n` +
                                `* 📝 **عنوان الواجب:** ${asgn.title}\n` +
                                `* 👤 **المُعيّن له:** ${studentDetails}\n` +
                                `* ❓ **عدد الأسئلة:** ${asgn.questionsCount} أسئلة\n` +
                                `* 🎯 **إجمالي الدرجات:** ${asgn.totalPoints} نقطة\n` +
                                `* 📅 **تاريخ البدء:** ${asgn.startDate}\n` +
                                `* ⏳ **آخر موعد للتسليم:** ${asgn.endDate}\n\n` +
                                `*تم حفظ الواجب في قاعدة البيانات وهو متاح الآن للطالب.*`;
                            voiceText = `تم تعيين الواجب بنجاح لـ ${asgn.studentName || 'الطلاب'} بعدد ${asgn.questionsCount} أسئلة، وآخر موعد للتسليم هو ${asgn.endDate}.`;
                        } else {
                            reply = `### ✅ Homework Assigned Successfully!\n\n` +
                                `* 📝 **Title:** ${asgn.title}\n` +
                                `* 👤 **Assigned To:** ${studentDetailsEn}\n` +
                                `* ❓ **Questions Count:** ${asgn.questionsCount} questions\n` +
                                `* 🎯 **Total Points:** ${asgn.totalPoints} pts\n` +
                                `* 📅 **Start Date:** ${asgn.startDate}\n` +
                                `* ⏳ **Due Date:** ${asgn.endDate}\n\n` +
                                `*The assignment is created in the database and is now live on the student dashboard.*`;
                            voiceText = `I have successfully assigned ${asgn.title} with ${asgn.questionsCount} questions to ${asgn.studentName || 'the student'}, due on ${asgn.endDate}.`;
                        }
                    } else {
                        reply = inArabic
                            ? `⚠️ لم أتمكن من إتمام التكليف: ${toolData.message || toolData.error}`
                            : `⚠️ Unable to assign homework: ${toolData.message || toolData.error}`;
                        voiceText = cleanForVoice(reply);
                    }

                } else if (fnName === 'audit_homework') {
                    detectedIntent = 'homework_audit';
                    toolData = await auditHomework({ query: args.assignmentTitle, userData });
                    if (toolData && toolData.found) {
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
                            voiceText = `في واجب ${toolData.assignmentTitle}، سلم ${toolData.totalSubmitted} طالب من أصل ${toolData.totalEnrolled}.`;
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
                            voiceText = `For ${toolData.assignmentTitle}, ${toolData.totalSubmitted} out of ${toolData.totalEnrolled} students submitted.`;
                        }
                    } else {
                        reply = inArabic ? `لم أجد أي واجبات مطابقة حالياً.` : `I couldn't find matching assignments.`;
                        voiceText = cleanForVoice(reply);
                    }
                } else if (fnName === 'lookup_student') {
                    detectedIntent = 'student_lookup';
                    toolData = await lookupStudent({ studentName: args.studentName });
                    if (toolData && toolData.found) {
                        const st = toolData.student;
                        reply = inArabic
                            ? `### 👤 تقرير الطالب: **${st.name}**\n\n* 📧 **البريد:** ${st.email}\n* 📝 **إجمالي التسليمات:** ${toolData.totalSubmissions}\n* 📊 **متوسط الدرجات:** ${toolData.averageScore} نقطة`
                            : `### 👤 Student Profile: **${st.name}**\n\n* 📧 **Email:** ${st.email}\n* 📝 **Total Submissions:** ${toolData.totalSubmissions}\n* 📊 **Average Score:** ${toolData.averageScore} pts`;
                        voiceText = `Student ${st.name} has submitted ${toolData.totalSubmissions} assignments with an average score of ${toolData.averageScore} points.`;
                    } else {
                        reply = inArabic ? `لم يتم العثور على طالب باسم "${args.studentName}".` : `Student "${args.studentName}" was not found.`;
                        voiceText = cleanForVoice(reply);
                    }
                } else if (fnName === 'get_platform_stats') {
                    detectedIntent = 'platform_stats';
                    toolData = await getPlatformOverview();
                    if (toolData) {
                        reply = inArabic
                            ? `### 📊 نظرة عامة على منصة SAT Area:\n\n* 🎓 **الطلاب النشطون:** ${toolData.totalStudents}\n* 👨‍🏫 **المعلمون:** ${toolData.totalTeachers}\n* 🏫 **الفصول:** ${toolData.totalClasses}\n* 📝 **الواجبات:** ${toolData.totalAssignments}\n* 📚 **بنك الأسئلة:** ${toolData.totalQuestions} سؤال`
                            : `### 📊 SAT Area Platform Overview:\n\n* 🎓 **Active Students:** ${toolData.totalStudents}\n* 👨‍🏫 **Teachers:** ${toolData.totalTeachers}\n* 🏫 **Classes:** ${toolData.totalClasses}\n* 📝 **Assignments / Tests:** ${toolData.totalAssignments}\n* 📚 **Question Bank:** ${toolData.totalQuestions} questions`;
                        voiceText = `The platform has ${toolData.totalStudents} students, ${toolData.totalClasses} classes, and ${toolData.totalQuestions} questions.`;
                    }
                }
            } else if (response && response.text) {
                reply = response.text;
                voiceText = cleanForVoice(reply);
            }
        } catch (apiErr) {
            console.error("Gemini Copilot Error:", apiErr);
            apiErrorMsg = apiErr.message;
            reply = `⚠️ AI Error: ${apiErr.message}`;
            voiceText = cleanForVoice(reply);
        }
    }


    // 2. Fallback Engine: Only if API is down or unavailable
    if (!reply) {
        const lowerMsg = rawMessage.toLowerCase();
        const isAuditQuestion = /who didn't|who submitted|pending|مين عمل|مين معملش|تسليم/i.test(lowerMsg);
        const isAssignRequest = /assign|create hw|create assignment|اعمل واجب|نزل واجب/i.test(lowerMsg);

        if (isAssignRequest) {
            reply = inArabic
                ? `لتعيين واجب، يرجى تزويدي باسم الطالب أو الفصل وموضوع الأسئلة، أو التأكد من إدخال مفتاح الذكاء الاصطناعي بشكل سليم.`
                : `To assign homework, please specify the student or class name and the topic, or ensure your AI key is configured.`;
            voiceText = cleanForVoice(reply);
        } else if (isAuditQuestion) {
            const auditData = await auditHomework({ query: rawMessage, userData });
            if (auditData && auditData.found) {
                reply = `### 📋 Homework Report: "${auditData.assignmentTitle}"\n\n* Total: ${auditData.totalEnrolled} | Submitted: ${auditData.totalSubmitted} | Pending: ${auditData.totalPending}`;
                voiceText = `For ${auditData.assignmentTitle}, ${auditData.totalSubmitted} out of ${auditData.totalEnrolled} submitted.`;
            } else {
                reply = inArabic ? `لم أجد واجبات مطابقة حالياً.` : `I couldn't find matching assignments.`;
                voiceText = cleanForVoice(reply);
            }
        } else {
            reply = inArabic
                ? `أهلاً بك! أنا المساعد الذكي لمنصة **SAT Area / مستر شاهين**.\n\nيمكنك أن تطلب مني تعيين واجب لطالب، حل أسئلة SAT، أو فحص تسليمات الطلاب.`
                : `Hello! I am your AI Copilot for **SAT Area / Mr. Shahin**.\n\nYou can ask me to assign homework to students, solve SAT questions, or audit homework submissions.`;
            voiceText = cleanForVoice(reply);
        }
    }

    return {
        reply,
        voiceText: voiceText || cleanForVoice(reply),
        language: inArabic ? 'ar' : 'en',
        data: toolData,
        intent: detectedIntent
    };
}

module.exports = {
    processCopilotChat,
    auditHomework,
    lookupStudent,
    getPlatformOverview,
    solveQuestion,
    assignHomework
};

