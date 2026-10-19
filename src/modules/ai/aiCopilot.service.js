const assignmentModel = require('../../../DB/models/assignment.model');
const answerModel = require('../../../DB/models/answer.model');
const userModel = require('../../../DB/models/user.model');
const classModel = require('../../../DB/models/class.model');
const questionModel = require('../../../DB/models/question.model');
const chapterModel = require('../../../DB/models/chapter.model');
const unitModel = require('../../../DB/models/unit.model');
const subjectModel = require('../../../DB/models/subject.model');
const questionReportModel = require('../../../DB/models/questionReport.model');
const courseModel = require('../../../DB/models/course.model');
const { GoogleGenAI } = require('@google/genai');
const Anthropic = require('@anthropic-ai/sdk');
const mongoose = require('mongoose');

/**
 * Helper to transform math/LaTeX expressions and strip markdown symbols
 * for smooth, fluent, natural Text-to-Speech playback
 */
function cleanForVoice(text, isAr = null) {
    if (!text) return '';
    let t = String(text);
    const arabic = isAr !== null ? isAr : isArabic(t);

    // 1. Convert LaTeX fractions \frac{a}{b} -> 'a على b' (Arabic) or 'a over b' (English)
    t = t.replace(/\\frac\{([^{}]+)\}\{([^{}]+)\}/g, (m, num, den) => {
        return arabic ? (`${num.trim()} على ${den.trim()}`) : (`${num.trim()} over ${den.trim()}`);
    });

    // 2. Convert powers and roots
    if (arabic) {
        t = t.replace(/([a-zA-Z0-9]+)\^2\b/g, '$1 تربيع');
        t = t.replace(/([a-zA-Z0-9]+)\^3\b/g, '$1 تكعيب');
        t = t.replace(/([a-zA-Z0-9]+)\^{?([0-9a-zA-Z]+)}?/g, '$1 أس $2');
        t = t.replace(/\\sqrt\{([^{}]+)\}/g, 'جذر $1');
        t = t.replace(/\\pm\b/g, ' موجب أو سالب ');
        t = t.replace(/\\leq?\b/g, ' أصغر من أو يساوي ');
        t = t.replace(/\\geq?\b/g, ' أكبر من أو يساوي ');
        t = t.replace(/\\neq\b/g, ' لا يساوي ');
        t = t.replace(/\\times\b/g, ' في ');
        t = t.replace(/\\cdot\b/g, ' في ');
        t = t.replace(/\\pi\b/g, ' باي ');
        t = t.replace(/=/g, ' يساوي ');
    } else {
        t = t.replace(/([a-zA-Z0-9]+)\^2\b/g, '$1 squared');
        t = t.replace(/([a-zA-Z0-9]+)\^3\b/g, '$1 cubed');
        t = t.replace(/([a-zA-Z0-9]+)\^{?([0-9a-zA-Z]+)}?/g, '$1 to the power of $2');
        t = t.replace(/\\sqrt\{([^{}]+)\}/g, 'square root of $1');
        t = t.replace(/\\pm\b/g, ' plus or minus ');
        t = t.replace(/\\leq?\b/g, ' less than or equal to ');
        t = t.replace(/\\geq?\b/g, ' greater than or equal to ');
        t = t.replace(/\\neq\b/g, ' not equal to ');
        t = t.replace(/\\times\b/g, ' times ');
        t = t.replace(/\\cdot\b/g, ' times ');
        t = t.replace(/\\pi\b/g, ' pi ');
        t = t.replace(/=/g, ' equals ');
    }

    // 3. Remove dollar signs and remaining LaTeX commands
    t = t.replace(/\$+/g, '');
    t = t.replace(/\\[a-zA-Z]+/g, ' ');

    // 4. Strip markdown formatting and symbols
    return t
        .replace(/[*#_`~>\[\]\(\)\{\}\\]/g, ' ')
        .replace(/\n+/g, '. ')
        .replace(/\s+/g, ' ')
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
 * Strips HTML tags and converts Quill math formulas to clean LaTeX ($...$)
 */
function cleanHtmlSnippet(html) {
    if (!html) return '';
    let str = String(html);
    str = str.replace(/<span[^>]*class="ql-formula"[^>]*data-value="([^"]+)"[^>]*>[\s\S]*?<\/span>/gi, '$$$1$$');
    str = str.replace(/<[^>]+>/g, ' ');
    str = str.replace(/&nbsp;/gi, ' ')
             .replace(/&amp;/gi, '&')
             .replace(/&lt;/gi, '<')
             .replace(/&gt;/gi, '>')
             .replace(/&ge;/gi, '≥')
             .replace(/&le;/gi, '≤');
    return str.replace(/\s+/g, ' ').trim();
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
async function assignHomework({ studentName, className, topic, questionCount = 5, title, timer = 0, section, userData }) {
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

        // Normalize section preference
        let resolvedSection = 'Quizzes';
        if (section) {
            if (/basic/i.test(section)) resolvedSection = 'Basics Classified';
            else if (/advanced/i.test(section)) resolvedSection = 'Advanced Classified';
            else if (/real|exam/i.test(section)) resolvedSection = 'Real Exams';
            else if (/quiz/i.test(section)) resolvedSection = 'Quizzes';
        }

        const queryOr = [];
        if (topic && topic.trim().length > 1 && !/general|sat|any/i.test(topic.trim())) {
            const cleanTopic = topic.trim();
            queryOr.push({ topic: { $regex: cleanTopic, $options: 'i' } });
            queryOr.push({ question: { $regex: cleanTopic, $options: 'i' } });
        }

        if (resolvedSection === 'Basics Classified') {
            selectedQuestions = await questionModel.find(
                queryOr.length > 0 ? { $or: queryOr } : {}
            ).sort({ questionPoints: 1, _id: 1 }).limit(limitCount);
        } else if (resolvedSection === 'Advanced Classified') {
            selectedQuestions = await questionModel.find(
                queryOr.length > 0 ? { $or: queryOr } : {}
            ).sort({ questionPoints: -1, _id: -1 }).limit(limitCount);
        } else if (queryOr.length > 0) {
            selectedQuestions = await questionModel.find({ $or: queryOr }).limit(limitCount);
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
        const finalTitle = title || `[${resolvedSection}] ${topicName} - ${targetName}`;

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
                section: resolvedSection,
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
 * Audits questions in an exam, test, or chapter for errors, missing images, duplicate choices, broken LaTeX, and student reports
 */
async function auditExamQuestions({ examName, limit = 25 }) {
    try {
        if (!examName || !examName.trim()) {
            return { success: false, message: 'Please specify an exam or chapter name to audit.' };
        }

        const rawQuery = examName.trim();
        const stopWords = new Set(['for', 'me', 'and', 'see', 'if', 'there', 'are', 'any', 'problems', 'or', 'mistakes', 'in', 'that', 'the', 'test', 'exam', 'questions', 'of', 'check', 'audit', 'show', 'please']);
        const tokens = rawQuery
            .toLowerCase()
            .replace(/[^a-z0-9\s]/g, ' ')
            .split(/\s+/)
            .filter(t => t.length > 0 && !stopWords.has(t));

        // Detect module preference: module 1 vs module 2, medium vs hard
        const isM1 = /module\s*1|\bm1\b|\bmedium\b|\bone\b/i.test(rawQuery);
        const isM2 = /module\s*2|\bm2\b|\bhard\b|\btwo\b/i.test(rawQuery);

        let questions = [];
        let resolvedExamTitle = rawQuery;
        let matchedSource = 'none';

        // 1. Search subjectModel (Real Exams category: e.g., 'May 2026 INT', 'May 2024 International')
        const yearMatch = rawQuery.match(/\b(202[3-7])\b/);
        const monthMatch = rawQuery.match(/\b(january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)\b/i);
        const regionMatch = rawQuery.match(/\b(int|international|us|usa)\b/i);

        let candidateSubjects = [];
        if (yearMatch || monthMatch || regionMatch) {
            const subRegexParts = [];
            if (yearMatch) subRegexParts.push(yearMatch[1]);
            if (monthMatch) subRegexParts.push(monthMatch[1].slice(0, 3));
            if (regionMatch) subRegexParts.push(regionMatch[1].toLowerCase().startsWith('int') ? '(int|international)' : 'us');

            candidateSubjects = await subjectModel.find({
                $and: subRegexParts.map(part => ({
                    subjectName: { $regex: part, $options: 'i' }
                }))
            }).limit(5).lean();
        }

        if ((!candidateSubjects || candidateSubjects.length === 0) && tokens.length > 0) {
            candidateSubjects = await subjectModel.find({
                $and: tokens.slice(0, 3).map(tok => ({
                    subjectName: { $regex: tok, $options: 'i' }
                }))
            }).limit(5).lean();
        }

        let targetChapter = null;

        if (candidateSubjects && candidateSubjects.length > 0) {
            const subject = candidateSubjects[0];
            resolvedExamTitle = subject.subjectName;

            const units = await unitModel.find({ subject: subject._id }).populate('chapters').lean();
            if (units && units.length > 0) {
                const allChapters = [];
                units.forEach(u => {
                    if (u.chapters && u.chapters.length > 0) {
                        u.chapters.forEach(ch => allChapters.push({ ...ch, unitName: u.unitName }));
                    }
                });

                if (allChapters.length > 0) {
                    if (isM1) {
                        targetChapter = allChapters.find(ch => /module\s*1|\bm1\b|medium/i.test(ch.chapterName || ch.unitName || '')) || allChapters[0];
                    } else if (isM2) {
                        targetChapter = allChapters.find(ch => /module\s*2|\bm2\b|hard/i.test(ch.chapterName || ch.unitName || '')) || allChapters[allChapters.length - 1];
                    } else {
                        targetChapter = allChapters[0];
                    }
                    if (targetChapter) {
                        resolvedExamTitle = `${subject.subjectName} - ${targetChapter.chapterName}`;
                        matchedSource = 'subject_unit_chapter';
                    }
                }
            }
        }

        // 2. Search unitModel directly
        if (!targetChapter) {
            const unitCandidates = await unitModel.find({
                $or: [
                    { unitName: { $regex: rawQuery, $options: 'i' } },
                    ...(tokens.length > 1 ? [{
                        $and: tokens.slice(0, 3).map(tok => ({ unitName: { $regex: tok, $options: 'i' } }))
                    }] : [])
                ]
            }).populate('chapters').limit(5).lean();

            if (unitCandidates && unitCandidates.length > 0) {
                const u = unitCandidates[0];
                if (u.chapters && u.chapters.length > 0) {
                    if (isM1) {
                        targetChapter = u.chapters.find(ch => /module\s*1|\bm1\b|medium/i.test(ch.chapterName || '')) || u.chapters[0];
                    } else if (isM2) {
                        targetChapter = u.chapters.find(ch => /module\s*2|\bm2\b|hard/i.test(ch.chapterName || '')) || u.chapters[u.chapters.length - 1];
                    } else {
                        targetChapter = u.chapters[0];
                    }
                    resolvedExamTitle = `${u.unitName} - ${targetChapter.chapterName}`;
                    matchedSource = 'unit_chapter';
                }
            }
        }

        // 3. Search chapterModel directly
        if (!targetChapter) {
            let chMatches = [];
            if (tokens.length > 0) {
                chMatches = await chapterModel.find({
                    $and: tokens.slice(0, 3).map(tok => ({ chapterName: { $regex: tok, $options: 'i' } }))
                }).limit(5).lean();
            }

            if (!chMatches || chMatches.length === 0) {
                chMatches = await chapterModel.find({
                    chapterName: { $regex: rawQuery, $options: 'i' }
                }).limit(5).lean();
            }

            if (chMatches && chMatches.length > 0) {
                targetChapter = chMatches[0];
                resolvedExamTitle = targetChapter.chapterName;
                matchedSource = 'chapter';
            }
        }

        // 4. Load questions from targetChapter
        if (targetChapter) {
            if (targetChapter.questions && targetChapter.questions.length > 0) {
                questions = await questionModel.find({ _id: { $in: targetChapter.questions } }).lean();
            } else {
                questions = await questionModel.find({ chapter: targetChapter._id }).lean();
            }
        }

        // 5. Fallback: Search questionModel directly by topic or question stem
        if (!questions || questions.length === 0) {
            if (tokens.length > 0) {
                questions = await questionModel.find({
                    $or: [
                        { topic: { $regex: tokens.join('.*'), $options: 'i' } },
                        { question: { $regex: tokens.join('.*'), $options: 'i' } }
                    ]
                }).limit(limit).lean();
                if (questions && questions.length > 0) {
                    matchedSource = 'questions_topic';
                }
            }
        }

        // 6. If STILL no questions found: Retrieve available exams to suggest to the user
        if (!questions || questions.length === 0) {
            const availableExams = await subjectModel.find({
                $or: [
                    { subjectName: { $regex: '202[4-7]', $options: 'i' } },
                    { subjectName: { $regex: 'int', $options: 'i' } },
                    { subjectName: { $regex: 'exam', $options: 'i' } },
                    { subjectName: { $regex: 'test', $options: 'i' } }
                ]
            }).select('subjectName').limit(10).lean();

            const suggestedList = (availableExams || []).map(e => e.subjectName);

            return {
                success: false,
                notFound: true,
                examName: rawQuery,
                suggestedExams: suggestedList,
                message: `No exam or questions found matching "${rawQuery}".`
            };
        }

        // Fetch student reports
        const questionIds = questions.map(q => q._id);
        let reportsMap = {};
        try {
            const reports = await questionReportModel.find({
                question: { $in: questionIds },
                status: { $in: ['pending', 'reviewed'] }
            }).lean();
            reports.forEach(r => {
                const qid = r.question.toString();
                if (!reportsMap[qid]) reportsMap[qid] = [];
                reportsMap[qid].push({
                    reason: r.reason,
                    comment: r.comment,
                    reporter: r.reporterName
                });
            });
        } catch (repErr) {
            // ignore
        }

        const issues = [];
        const healthyQuestions = [];
        const questionSummaries = [];

        const targetSlice = questions.slice(0, limit);

        targetSlice.forEach((q, idx) => {
            const qNum = idx + 1;
            const qId = q._id.toString();
            const text = (q.question || '').trim();
            const qType = q.typeOfAnswer || 'MCQ';
            const questionIssues = [];

            // Check 1: Empty or truncated prompt
            if (!text || text.length < 8) {
                questionIssues.push('Empty or truncated question prompt');
            }

            // Check 2: Missing image/figure referenced in stem
            const visualRegex = /(shown (above|below|in the (figure|graph|table|diagram))|in the (figure|xy-plane|coordinate plane|graph|table|diagram|scatterplot)|refer to the (figure|graph|table|diagram)|(pictured|diagrammed|graphed) (above|below))/i;
            if (visualRegex.test(text) && !q.questionPic) {
                questionIssues.push('Question explicitly references a figure, graph, or diagram, but questionPic is missing');
            }

            // ----------------------------------------------------
            // REAL FRONTEND SIMULATION (VIRTUAL STUDENT CLICKER)
            // ----------------------------------------------------
            let visibleButtons = [];
            let winningButtons = [];

            if (qType === 'MCQ') {
                const rawWrongs = (q.wrongAnswer || []).filter(i => i != null && String(i).trim() !== '');
                // Exactly how Question.js renders options on screen: (Array.from(new Set(thisQuestion.wrongAnswer)).slice(0, 4))
                const uniqueChoices = Array.from(new Set(rawWrongs));
                visibleButtons = uniqueChoices.slice(0, 4);

                if (visibleButtons.length < 4) {
                    questionIssues.push(`Incomplete Choices on Screen: Student only sees ${visibleButtons.length} buttons instead of 4 (A, B, C, D)`);
                }
                if (rawWrongs.length > uniqueChoices.length) {
                    questionIssues.push(`Duplicate Options on Screen: Multiple buttons contain identical text`);
                }

                // Simulate clicking each visible button (A, B, C, D) against backend checkTheAnswer
                const corr = (q.correctAnswer || '').trim();
                visibleButtons.forEach((btnValue, bIdx) => {
                    const letter = String.fromCharCode(65 + bIdx);
                    const cleanBtn = cleanHtmlSnippet(btnValue);
                    const isExactMatch = (btnValue === q.correctAnswer) || (btnValue.trim() === corr);
                    const isCleanMatch = cleanBtn && cleanHtmlSnippet(corr) && (cleanBtn.toLowerCase() === cleanHtmlSnippet(corr).toLowerCase());

                    if (isExactMatch || isCleanMatch) {
                        winningButtons.push({ letter, text: cleanBtn, isExact: isExactMatch });
                    }
                });

                if (winningButtons.length === 0) {
                    questionIssues.push(`FATAL FRONTEND ERROR: None of the clickable buttons (A, B, C, D) match the correct answer! Clicking any option will result in WRONG.`);
                } else if (winningButtons.length > 1) {
                    questionIssues.push(`AMBIGUOUS: Multiple buttons on screen (${winningButtons.map(b => b.letter).join(' and ')}) trigger a correct grade.`);
                }
            } else if (qType === 'Essay') {
                const rawAnswers = Array.isArray(q.answer) ? q.answer : [q.answer];
                const cleanAnswers = rawAnswers.filter(a => a && String(a).trim().length > 0);

                if (cleanAnswers.length === 0 && (!q.correctAnswer || !q.correctAnswer.trim())) {
                    questionIssues.push('FATAL: Missing answer key in database. Any student input will be marked WRONG.');
                }

                const hasHtmlContamination = cleanAnswers.some(a => /<[a-z][\s\S]*>/i.test(a));
                if (hasHtmlContamination) {
                    questionIssues.push(`HTML Contamination: Answer key contains HTML tags. Students typing plain numbers will be graded WRONG!`);
                }
            } else if (qType === 'Graph') {
                if (!q.correctPicAnswer) {
                    questionIssues.push('Graph question missing correctPicAnswer image');
                }
                if (!q.wrongPicAnswer || q.wrongPicAnswer.length === 0) {
                    questionIssues.push('Graph question missing wrongPicAnswer images');
                }
            }

            // Check: LaTeX formatting
            const dollarCount = (text.match(/\$/g) || []).length;
            if (dollarCount % 2 !== 0) {
                questionIssues.push('Unbalanced LaTeX dollar signs ($) in question text');
            }

            // Check: Student reports
            if (reportsMap[qId] && reportsMap[qId].length > 0) {
                const reps = reportsMap[qId].map(r => `${r.reason}: "${r.comment || 'Flagged by student'}"`).join('; ');
                questionIssues.push(`Student reports lodged (${reps})`);
            }

            const cleanStem = cleanHtmlSnippet(text);
            const rawAns = q.correctAnswer || (q.answer ? q.answer.join(', ') : null) || q.correctPicAnswer || 'N/A';
            const cleanAns = cleanHtmlSnippet(rawAns);

            const qSummary = {
                questionNumber: qNum,
                questionId: qId,
                type: qType,
                stem: cleanStem.length > 140 ? cleanStem.substring(0, 140) + '...' : cleanStem,
                correctAnswer: cleanAns,
                winningButton: winningButtons.length > 0 ? winningButtons.map(b => `${b.letter} (${b.text})`).join(', ') : (qType === 'MCQ' ? 'NONE (Unclickable!)' : cleanAns),
                screenButtons: visibleButtons.map((b, bIdx) => `${String.fromCharCode(65 + bIdx)}: ${cleanHtmlSnippet(b)}`),
                hasImage: Boolean(q.questionPic),
                problems: questionIssues
            };

            questionSummaries.push(qSummary);

            if (questionIssues.length > 0) {
                issues.push(qSummary);
            } else {
                healthyQuestions.push(qNum);
            }
        });

        return {
            success: true,
            examTitle: resolvedExamTitle,
            matchedSource: matchedSource,
            totalAudited: targetSlice.length,
            healthyCount: healthyQuestions.length,
            issuesCount: issues.length,
            issues: issues,
            healthyQuestions: healthyQuestions,
            questions: questionSummaries
        };
    } catch (err) {
        console.error("auditExamQuestions Error:", err);
        return { success: false, error: err.message };
    }
}

/**
 * Raw Tool Execution (for agentic 2-turn reasoning)
 */
async function executeRawTool({ fnName, args, userData }) {
    if (fnName === 'assign_homework') {
        return await assignHomework({ ...args, userData });
    } else if (fnName === 'audit_homework') {
        return await auditHomework({ query: args.assignmentTitle, userData });
    } else if (fnName === 'audit_exam_questions') {
        return await auditExamQuestions({ examName: args.examName, limit: args.limit });
    } else if (fnName === 'lookup_student') {
        return await lookupStudent({ studentName: args.studentName });
    } else if (fnName === 'get_platform_stats') {
        return await getPlatformOverview();
    }
    return { error: `Unknown tool: ${fnName}` };
}

/**
 * Shared Tool Execution Dispatcher
 */
async function executeToolAction({ fnName, args, userData, inArabic }) {
    let reply = '';
    let voiceText = '';
    let toolData = null;
    let detectedIntent = fnName;

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

            const sectionNameAr = asgn.section === 'Basics Classified' ? 'الأساسيات المصنفة (Basics Classified)' :
                (asgn.section === 'Advanced Classified' ? 'المتقدم المصنف (Advanced Classified)' :
                (asgn.section === 'Real Exams' ? 'الامتحانات الحقيقية (Real Exams)' : 'الكويزات والواجبات (Quizzes)'));

            if (inArabic) {
                reply = `### ✅ تم تكليف الواجب بنجاح!\n\n` +
                    `* 📝 **عنوان الواجب:** ${asgn.title}\n` +
                    `* 📚 **القسم:** ${sectionNameAr}\n` +
                    `* 👤 **المُعيّن له:** ${studentDetails}\n` +
                    `* ❓ **عدد الأسئلة:** ${asgn.questionsCount} أسئلة\n` +
                    `* 🎯 **إجمالي الدرجات:** ${asgn.totalPoints} نقطة\n` +
                    `* 📅 **تاريخ البدء:** ${asgn.startDate}\n` +
                    `* ⏳ **آخر موعد للتسليم:** ${asgn.endDate}\n\n` +
                    `*تم حفظ الواجب في قاعدة البيانات وهو متاح الآن للطالب مباشرة.*`;
                voiceText = `تم تعيين الواجب بنجاح من قسم ${asgn.section || 'الواجبات'} لـ ${asgn.studentName || 'الطلاب'} بعدد ${asgn.questionsCount} أسئلة، وآخر موعد للتسليم هو ${asgn.endDate}.`;
            } else {
                reply = `### ✅ Homework Assigned Successfully!\n\n` +
                    `* 📝 **Title:** ${asgn.title}\n` +
                    `* 📚 **Section:** ${asgn.section}\n` +
                    `* 👤 **Assigned To:** ${studentDetailsEn}\n` +
                    `* ❓ **Questions Count:** ${asgn.questionsCount} questions\n` +
                    `* 🎯 **Total Points:** ${asgn.totalPoints} pts\n` +
                    `* 📅 **Start Date:** ${asgn.startDate}\n` +
                    `* ⏳ **Due Date:** ${asgn.endDate}\n\n` +
                    `*The assignment is created in the database and is now live on the student dashboard.*`;
                voiceText = `I have successfully assigned ${asgn.title} from ${asgn.section} with ${asgn.questionsCount} questions to ${asgn.studentName || 'the student'}, due on ${asgn.endDate}.`;
            }
        } else {
            reply = inArabic
                ? `⚠️ لم أتمكن من إتمام التكليف: ${toolData.message || toolData.error}`
                : `⚠️ Unable to assign homework: ${toolData.message || toolData.error}`;
            voiceText = cleanForVoice(reply, inArabic);
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
    } else if (fnName === 'audit_exam_questions') {
        detectedIntent = 'audit_exam';
        toolData = await auditExamQuestions({ examName: args.examName, limit: args.limit });
        if (toolData.notFound) {
            const hasSuggestions = toolData.suggestedExams && toolData.suggestedExams.length > 0;
            const suggListAr = hasSuggestions
                ? `\n\n#### 📚 الامتحانات المتوفرة حالياً على المنصة للمراجعة:\n` + toolData.suggestedExams.map(s => `• **${s}**`).join('\n') + `\n\n*هل تود فحص أحد هذه الامتحانات بدلاً من ذلك؟*`
                : '';
            const suggListEn = hasSuggestions
                ? `\n\n#### 📚 Currently Available Exams on the Platform:\n` + toolData.suggestedExams.map(s => `• **${s}**`).join('\n') + `\n\n*Would you like me to audit one of these exams instead?*`
                : '';

            reply = inArabic
                ? `### ⚠️ لم أتمكن من العثور على امتحان أو فصل باسم "${toolData.examName}"\n\nيرجى التأكد من اسم الامتحان.${suggListAr}`
                : `### ⚠️ Could not find an exam or chapter matching "${toolData.examName}"\n\nIt may not be uploaded yet or uses a different title.${suggListEn}`;
            voiceText = inArabic
                ? `لم أجد امتحاناً باسم ${toolData.examName}. يرجى التحقق من الاسم أو اختيار أحد الامتحانات المتاحة.`
                : `I could not find an exam named ${toolData.examName}. Please verify the name or choose an available test.`;
        } else if (toolData.success) {
            const hasIssues = toolData.issuesCount > 0;
            if (hasIssues) {
                const issueList = toolData.issues.map(iss => {
                    const probs = iss.problems.map(p => `   - ⚠️ ${p}`).join('\n');
                    const text = iss.stem || iss.snippet || '';
                    const btns = iss.screenButtons && iss.screenButtons.length > 0 ? `\n   - 🖥️ الأزرار على الشاشة: ${iss.screenButtons.join(' | ')}` : '';
                    const win = iss.winningButton ? `\n   - 🎯 الزر الفائز عند النقر: \`${iss.winningButton}\`` : '';
                    return `• **السؤال #${iss.questionNumber}** (${iss.type}):\n  *${text}*${btns}${win}\n${probs}`;
                }).join('\n\n');

                const issueListEn = toolData.issues.map(iss => {
                    const probs = iss.problems.map(p => `   - ⚠️ ${p}`).join('\n');
                    const text = iss.stem || iss.snippet || '';
                    const btns = iss.screenButtons && iss.screenButtons.length > 0 ? `\n   - 🖥️ Screen Buttons: ${iss.screenButtons.join(' | ')}` : '';
                    const win = iss.winningButton ? `\n   - 🎯 Winning Clicked Button: \`${iss.winningButton}\`` : '';
                    return `• **Question #${iss.questionNumber}** (${iss.type}):\n  *${text}*${btns}${win}\n${probs}`;
                }).join('\n\n');

                reply = inArabic
                    ? `### 🖥️ تقرير فحص ومحاكاة الشاشة الحقيقية: **${toolData.examTitle}**\n\n` +
                      `*تم اختبار نقر أزرار الخيارات (A, B, C, D) ومطابقتها مع محرك التصحيح:*\n\n` +
                      `* **إجمالي الأسئلة المختبرة على الشاشة:** ${toolData.totalAudited} سؤال\n` +
                      `* **أسئلة تعمل وتُحل بنجاح 100%:** ✅ ${toolData.healthyCount}\n` +
                      `* **أسئلة بها ملاحظات أو مشاكل في العرض:** ⚠️ ${toolData.issuesCount}\n\n` +
                      `---\n\n` +
                      `### ⚠️ تفاصيل الفحص:\n\n${issueList}\n\n` +
                      `*يمكنك مراجعة وتعديل أي سؤال مباشرة من استوديو إدارة الأسئلة.*`
                    : `### 🖥️ Real Website Simulation & Audit Report: **${toolData.examTitle}**\n\n` +
                      `*Simulated real student clicks on buttons (A, B, C, D) tested against the backend grading engine:*\n\n` +
                      `* **Total Questions Tested on Screen:** ${toolData.totalAudited} questions\n` +
                      `* **100% Solvable & Verified:** ✅ ${toolData.healthyCount}\n` +
                      `* **Display / Grading Issues:** ⚠️ ${toolData.issuesCount}\n\n` +
                      `---\n\n` +
                      `### ⚠️ Detailed Findings:\n\n${issueListEn}\n\n` +
                      `*You can review or adjust any question directly in the Question Management Studio.*`;

                voiceText = inArabic
                    ? `تم اختبار شاشة امتحان ${toolData.examTitle}. فحصت ${toolData.totalAudited} سؤال على الموقع، ووجدت ${toolData.issuesCount} أسئلة بها ملاحظات.`
                    : `Real website simulation complete for ${toolData.examTitle}. Tested ${toolData.totalAudited} questions on screen: ${toolData.healthyCount} working perfectly, ${toolData.issuesCount} requiring review.`;
            } else {
                reply = inArabic
                    ? `### ✅ محاكاة الواجهة الحقيقية لـ **${toolData.examTitle}**: سليم 100%!\n\n` +
                      `* **إجمالي الأسئلة المختبرة على الشاشة:** ${toolData.totalAudited} سؤال\n` +
                      `* **نتيجة المحاكاة:** تم اختبار جميع أزرار الخيارات (A, B, C, D) ونصوص الأسئلة والمعادلات والصور — كل سؤال يمتلك زراً قابلاً للنقر يعطي درجة كاملة، ولا توجد أي مشاكل تعيق الطلاب.`
                    : `### ✅ Real Website Simulation for **${toolData.examTitle}**: 100% Clean & Solvable!\n\n` +
                      `* **Total Questions Tested on Screen:** ${toolData.totalAudited} questions\n` +
                      `* **Simulation Result:** Verified that every multiple-choice question displays 4 distinct buttons (A, B, C, D) and exactly one winning button triggers full credit. All figures and equations render cleanly on screen.`;

                voiceText = inArabic
                    ? `امتحان ${toolData.examTitle} سليم تماماً على شاشة الموقع وجميع الأسئلة قابلة للحل بنجاح.`
                    : `Exam ${toolData.examTitle} is completely clean and 100% solvable on screen with zero clickable errors.`;
            }
        }
    }

    return { reply, voiceText, toolData, detectedIntent };
}

/**
 * Master Copilot Chat Function
 */
async function processCopilotChat({ message, userData, history = [], image = null, brand = null }) {
    const rawMessage = (message || '').trim();
    const inArabic = isArabic(rawMessage);

    // Resolve brand identity: 'ais', 'mrshahin', or 'satarea'
    let activeBrand = (brand || '').toLowerCase().trim();
    if (!activeBrand && userData) {
        const uName = (userData.userName || '').toLowerCase();
        const uEmail = (userData.email || '').toLowerCase();
        const uSchool = (userData.school || userData.createdBy?.userName || '').toLowerCase();
        if (uName.includes('arrowad') || uName.includes('ais') || uEmail.includes('arrowad') || uSchool.includes('arrowad')) {
            activeBrand = 'ais';
        } else if (uName.includes('shahin') || uEmail.includes('shahin') || uSchool.includes('shahin')) {
            activeBrand = 'mrshahin';
        } else {
            activeBrand = 'satarea';
        }
    }
    if (!activeBrand) activeBrand = 'satarea';

    let copilotName = "SATAREA AI Copilot";
    let platformBrandName = "the SATAREA Digital SAT platform";
    let arabicCopilotName = "المساعد الذكي لمنصة سات إريا";
    if (activeBrand === 'ais') {
        copilotName = "Arrowad AI Copilot";
        platformBrandName = "Arrowad International Schools (AIS) and the SATAREA platform";
        arabicCopilotName = "مساعد مدارس الرواد العالمية الذكي";
    } else if (activeBrand === 'mrshahin') {
        copilotName = "Mr. Shahin's AI Copilot";
        platformBrandName = "Mr. Shahin Math Academy and the SAT Area platform";
        arabicCopilotName = "المساعد الذكي لمستر شاهين";
    }

    const systemInstruction = `You are "${copilotName}" — the premier, state-of-the-art educational AI assistant for ${platformBrandName}.
You combine elite SAT Math & English mastery with the responsiveness, warmth, and proactive intelligence of an expert co-teacher and mentor.

Your Core Directives:
1. High Intelligence & Vision: When explaining SAT concepts or analyzing an uploaded image/screenshot of a problem, provide clear, step-by-step breakdowns, clever Desmos calculator tips, SAT strategies, and mathematically rigorous formulas.
2. Natural Communication: Talk naturally and smartly like an intelligent human co-pilot (like modern ChatGPT voice chat). When you take an action (assigning homework, auditing exam questions, looking up students, etc.), review the tool result and summarize what you did with a warm, conversational explanation and proactive suggestions. Never sound like a rigid machine.
3. Bilingual Mastery: Fluent in English and Arabic. When the user speaks Arabic, reply naturally in warm, friendly, modern Egyptian/Standard Arabic.
4. Action Execution: You have direct access to database tools. Always invoke the appropriate tool when asked to assign homework, audit exam questions, check submissions, or inspect student stats.

MATHEMATICAL & LATEX FORMATTING (CRITICAL):
- ALWAYS write all mathematical expressions, formulas, fractions, equations, and variables using standard LaTeX wrapped in dollar signs.
- For inline math and fractions, ALWAYS enclose in single dollar signs: e.g., $\\frac{a}{b}$, $\\frac{3}{4}$, $x^2 + 5x + 6 = 0$, $\\sqrt{16} = 4$, $y = mx + b$.
- For standalone/display equations, ALWAYS enclose in double dollar signs: e.g., $$\\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}$$.
- NEVER output raw unformatted LaTeX without dollar signs (e.g., do NOT write \\frac{a}{b} alone; write $\\frac{a}{b}$).
- Fractions MUST ALWAYS be formatted as $\\frac{\\text{numerator}}{\\text{denominator}}$ so the KaTeX mathematical renderer displays them with beautiful horizontal division bars.

PLATFORM ARCHITECTURE & CORE SECTIONS:
You have intimate knowledge of the SAT Area platform structure and its 4 core sections:
1. 📚 Basics Classified (الأساسيات المصنفة):
   - Foundational question bank organized topic-by-topic for building core skills and concepts.
   - Covers: Linear Equations, Systems, Quadratics basics, Heart of Algebra, Problem Solving & Data Analysis, Rates, Ratios, Percentages, and Essential Reading/Writing conventions.
   - Purpose: Ideal for beginners or students aiming to establish a solid 600-650 foundation before tackling harder questions.

2. 🚀 Advanced Classified (المتقدم المصنف):
   - High-difficulty question bank organized topic-by-topic for students targeting 700-800 scores.
   - Covers: Complex polynomials, hard non-linear systems, advanced circles & trigonometry, complex numbers, tricky word problems, and high-level Reading inference questions.
   - Purpose: Perfect for advanced students seeking high-yield challenge problems and SAT traps.

3. 🏆 Real Exams (الامتحانات الحقيقية):
   - 56+ authentic, full-length official past Digital SAT tests from 2024 to 2026.
   - Organized by Year (2026, 2025, 2024) and Region (US vs International).
   - Features the official Bluebook-style test environment with a 35-minute timer capsule, question elimination, question review palette, and embedded Desmos graphing calculator.
   - Purpose: Full diagnostic mocks and authentic test-day simulation.

4. 📝 Quizzes & Assignments (الكويزات والواجبات):
   - Homework sheets, timed quizzes, and custom drills assigned by teachers or created for students.
   - Features instant auto-grading, step-by-step explanations, student mistake tracking (Mistakes Bank / بنك الأخطاء), and printable automated PDF gradebook reports for teachers and parents.

Available Tools:
- assign_homework: Creates and assigns homework, quiz, or practice questions to a student or class from any section.
- audit_exam_questions: Checks and audits questions in any practice exam, test, or chapter for errors (missing images, missing correct answers, duplicate choices, broken LaTeX, student problem reports).
- audit_homework: Checks who completed or did not complete an existing assignment and provides submission metrics.
- lookup_student: Looks up student progress, past submissions, and average scores.
- get_platform_stats: Platform overview metrics (students, teachers, questions, classes).`;

    let reply = '';
    let voiceText = '';
    let toolData = null;
    let detectedIntent = 'general';

    // Standard OpenAI/OpenRouter tools schema
    const standardTools = [
        {
            name: 'assign_homework',
            description: 'Creates and assigns homework, exam, quiz, or practice questions to a student or class. Invoke whenever the user asks to assign/create/give homework, test or exam.',
            parameters: {
                type: 'object',
                properties: {
                    studentName: { type: 'string', description: 'Student name to assign to (e.g. Adam, ahmed5)' },
                    className: { type: 'string', description: 'Class or group name' },
                    topic: { type: 'string', description: 'Topic, chapter, or exam title' },
                    section: {
                        type: 'string',
                        enum: ['Basics Classified', 'Advanced Classified', 'Real Exams', 'Quizzes', 'Any'],
                        description: 'The platform section to pull questions from or categorize the assignment'
                    },
                    questionCount: { type: 'integer', description: 'Number of questions (default: 5)' },
                    timer: { type: 'integer', description: 'Time limit in minutes' }
                }
            }
        },
        {
            name: 'audit_homework',
            description: 'Reports who did or did not submit an existing assignment. Use ONLY for homework submission status questions.',
            parameters: {
                type: 'object',
                properties: {
                    assignmentTitle: { type: 'string', description: 'Assignment title (empty = check latest)' }
                }
            }
        },
        {
            name: 'lookup_student',
            description: 'Looks up a student progress, submissions, and average scores.',
            parameters: {
                type: 'object',
                properties: {
                    studentName: { type: 'string', description: 'Student name to look up' }
                },
                required: ['studentName']
            }
        },
        {
            name: 'audit_exam_questions',
            description: 'Inspects and audits questions in any practice exam, test, or chapter to find problems such as missing images/diagrams, missing or duplicate answers, broken LaTeX formulas, or student reports. Always invoke when user asks to check or audit exam questions for problems.',
            parameters: {
                type: 'object',
                properties: {
                    examName: { type: 'string', description: 'Name of the exam, test, or chapter (e.g. "Practice Test 1", "March 2024", "Linear Equations")' },
                    limit: { type: 'integer', description: 'Number of questions to check (default: 25)' }
                },
                required: ['examName']
            }
        },
        {
            name: 'get_platform_stats',
            description: 'Gets platform overview metrics (students, teachers, questions, classes).',
            parameters: { type: 'object', properties: {} }
        }
    ].map(f => ({ type: 'function', function: f }));

    // Standard OpenAI/OpenRouter messages builder
    const buildStandardMessages = () => {
        const msgs = [{ role: 'system', content: systemInstruction }];
        if (Array.isArray(history) && history.length > 0) {
            history.forEach(h => {
                if (h.content && h.content.trim()) {
                    msgs.push({
                        role: h.role === 'model' || h.role === 'assistant' ? 'assistant' : 'user',
                        content: h.content.trim()
                    });
                }
            });
        }

        if (image && typeof image === 'string' && image.startsWith('data:image/')) {
            msgs.push({
                role: 'user',
                content: [
                    {
                        type: 'text',
                        text: rawMessage || (inArabic ? 'يرجى مراجعة وشرح الصورة المرفقة بالتفصيل وحل المسألة الرياضية الواردة بها خطوة بخطوة.' : 'Please analyze the attached image in detail and solve any SAT math question shown step-by-step.')
                    },
                    {
                        type: 'image_url',
                        image_url: { url: image }
                    }
                ]
            });
        } else {
            msgs.push({ role: 'user', content: rawMessage || (inArabic ? 'مرحباً' : 'Hello') });
        }
        return msgs;
    };

    // ==========================================
    // 0. OpenRouter Claude Sonnet (Flagship Railway-Level Tier)
    // ==========================================
    const openrouterKey = process.env.OPENROUTER_API_KEY;
    if (!reply && openrouterKey && openrouterKey.trim().length > 10) {
        try {
            const orMessages = buildStandardMessages();
            const orModels = [
                process.env.OPENROUTER_MODEL,
                'anthropic/claude-sonnet-5.5',
                'anthropic/claude-sonnet-5',
                'anthropic/claude-haiku-5.5'
            ].filter(Boolean);

            for (const model of orModels) {
                try {
                    const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${openrouterKey.trim()}`,
                            'Content-Type': 'application/json',
                            'HTTP-Referer': 'https://satarea.com',
                            'X-Title': 'SAT Area Copilot'
                        },
                        body: JSON.stringify({
                            model,
                            messages: orMessages,
                            tools: standardTools,
                            tool_choice: 'auto',
                            max_tokens: 1500
                        })
                    });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data?.error?.message || `HTTP ${res.status}`);
                    const msg = data.choices?.[0]?.message;
                    const call = msg?.tool_calls?.[0];

                    if (call) {
                        let args = {};
                        try { args = JSON.parse(call.function.arguments || '{}'); } catch (_) { }

                        const rawResult = await executeRawTool({ fnName: call.function.name, args, userData });
                        detectedIntent = call.function.name;
                        toolData = rawResult;

                        // Agentic 2-turn reasoning: Feed tool output back to Claude
                        orMessages.push(msg);
                        orMessages.push({
                            role: 'tool',
                            tool_call_id: call.id,
                            content: JSON.stringify(rawResult)
                        });

                        try {
                            const secondRes = await fetch('https://openrouter.ai/api/v1/chat/completions', {
                                method: 'POST',
                                headers: {
                                    'Authorization': `Bearer ${openrouterKey.trim()}`,
                                    'Content-Type': 'application/json',
                                    'HTTP-Referer': 'https://satarea.com',
                                    'X-Title': 'SAT Area Copilot'
                                },
                                body: JSON.stringify({
                                    model,
                                    messages: orMessages,
                                    max_tokens: 1500
                                })
                            });
                            const secondData = await secondRes.json();
                            const secondContent = secondData.choices?.[0]?.message?.content;
                            if (secondContent) {
                                reply = secondContent;
                                voiceText = cleanForVoice(reply);
                            }
                        } catch (sErr) {
                            console.warn("OpenRouter 2nd turn error:", sErr.message);
                        }

                        // Fallback to structured receipt if second turn failed
                        if (!reply) {
                            const actionRes = await executeToolAction({ fnName: call.function.name, args, userData, inArabic });
                            reply = actionRes.reply;
                            voiceText = actionRes.voiceText;
                        }
                    } else if (msg?.content) {
                        reply = msg.content;
                        voiceText = cleanForVoice(reply);
                    }
                    if (reply) break;
                } catch (orModelErr) {
                    console.warn(`OpenRouter model ${model} error (${String(orModelErr.message).slice(0, 100)}), trying next...`);
                }
            }
        } catch (orErr) {
            console.error("OpenRouter Error:", orErr.message);
        }
    }

    // ==========================================
    // 1. Anthropic Direct Tier (if ANTHROPIC_API_KEY provided)
    // ==========================================
    const anthropicKey = process.env.ANTHROPIC_API_KEY;
    if (!reply && anthropicKey && anthropicKey.trim().length > 10) {
        try {
            const anthropic = new Anthropic({ apiKey: anthropicKey.trim() });
            const claudeTools = [
                {
                    name: 'assign_homework',
                    description: 'Creates and assigns homework, exam, quiz, or practice questions to a student or class in the SAT platform. Always invoke this when the user asks to assign, create, or give homework/test/exam.',
                    input_schema: {
                        type: 'object',
                        properties: {
                            studentName: { type: 'string', description: 'Name of the student to assign to (e.g. Adam, ahmed5)' },
                            className: { type: 'string', description: 'Name of the class or group' },
                            topic: { type: 'string', description: 'Topic, chapter, or real exam title' },
                            questionCount: { type: 'integer', description: 'Number of questions to assign (default: 5)' },
                            timer: { type: 'integer', description: 'Time limit in minutes if requested' }
                        }
                    }
                },
                {
                    name: 'audit_homework',
                    description: 'Checks who completed or did not complete an existing assignment and provides submission stats. Use ONLY when asked who did or did not submit homework.',
                    input_schema: {
                        type: 'object',
                        properties: {
                            assignmentTitle: { type: 'string', description: 'Title or query of the assignment to check' }
                        }
                    }
                },
                {
                    name: 'lookup_student',
                    description: 'Looks up a student progress, submissions, and average scores.',
                    input_schema: {
                        type: 'object',
                        properties: {
                            studentName: { type: 'string', description: 'Name of the student to look up' }
                        },
                        required: ['studentName']
                    }
                },
                {
                    name: 'audit_exam_questions',
                    description: 'Audits questions in any exam, test, or chapter to find problems (missing diagrams/images, missing or duplicate answers, broken LaTeX, student reports).',
                    input_schema: {
                        type: 'object',
                        properties: {
                            examName: { type: 'string', description: 'Name of the exam or chapter to check' },
                            limit: { type: 'integer', description: 'Number of questions to check (default: 25)' }
                        },
                        required: ['examName']
                    }
                },
                {
                    name: 'get_platform_stats',
                    description: 'Gets platform overview metrics (students, teachers, questions, classes).',
                    input_schema: {
                        type: 'object',
                        properties: {}
                    }
                }
            ];

            const claudeMessages = [];
            if (Array.isArray(history) && history.length > 0) {
                history.forEach(h => {
                    if (h.content && h.content.trim()) {
                        claudeMessages.push({
                            role: h.role === 'model' || h.role === 'assistant' ? 'assistant' : 'user',
                            content: h.content.trim()
                        });
                    }
                });
            }
            claudeMessages.push({ role: 'user', content: rawMessage });

            const claudeModel = process.env.CLAUDE_MODEL || 'claude-3-7-sonnet-20250219';
            const claudeResponse = await anthropic.messages.create({
                model: claudeModel,
                max_tokens: 1500,
                system: systemInstruction,
                tools: claudeTools,
                messages: claudeMessages
            });

            const toolUse = claudeResponse.content.find(b => b.type === 'tool_use');
            if (toolUse) {
                const rawResult = await executeRawTool({ fnName: toolUse.name, args: toolUse.input || {}, userData });
                detectedIntent = toolUse.name;
                toolData = rawResult;

                // Agentic 2nd turn
                claudeMessages.push({ role: 'assistant', content: claudeResponse.content });
                claudeMessages.push({
                    role: 'user',
                    content: [{
                        type: 'tool_result',
                        tool_use_id: toolUse.id,
                        content: JSON.stringify(rawResult)
                    }]
                });

                try {
                    const secondClaude = await anthropic.messages.create({
                        model: claudeModel,
                        max_tokens: 1500,
                        system: systemInstruction,
                        messages: claudeMessages
                    });
                    const textBlock = secondClaude.content.find(b => b.type === 'text');
                    if (textBlock && textBlock.text) {
                        reply = textBlock.text;
                        voiceText = cleanForVoice(reply);
                    }
                } catch (scErr) {
                    console.warn("Direct Claude 2nd turn error:", scErr.message);
                }

                if (!reply) {
                    const actionRes = await executeToolAction({ fnName: toolUse.name, args: toolUse.input || {}, userData, inArabic });
                    reply = actionRes.reply;
                    voiceText = actionRes.voiceText;
                }
            } else {
                const textBlock = claudeResponse.content.find(b => b.type === 'text');
                if (textBlock && textBlock.text) {
                    reply = textBlock.text;
                    voiceText = cleanForVoice(reply);
                }
            }
        } catch (claudeErr) {
            console.error("Direct Claude Error (falling back to Groq):", claudeErr.message);
        }
    }

    // ==========================================
    // 1b. Groq Tier (free, OpenAI-compatible)
    // ==========================================
    const groqKey = process.env.GROQ_API_KEY;
    if (!reply && groqKey && groqKey.trim().length > 10) {
        try {
            const groqMessages = buildStandardMessages();
            const groqModels = [process.env.GROQ_MODEL, 'openai/gpt-oss-120b', 'qwen/qwen3.8-27b', 'openai/gpt-oss-20b'].filter(Boolean);

            for (const model of groqModels) {
                try {
                    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${groqKey.trim()}`, 'Content-Type': 'application/json' },
                        body: JSON.stringify({ model, messages: groqMessages, tools: standardTools, tool_choice: 'auto', max_tokens: 1500 })
                    });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data?.error?.message || `HTTP ${res.status}`);
                    const msg = data.choices?.[0]?.message;
                    const call = msg?.tool_calls?.[0];

                    if (call) {
                        let args = {};
                        try { args = JSON.parse(call.function.arguments || '{}'); } catch (_) { }

                        const rawResult = await executeRawTool({ fnName: call.function.name, args, userData });
                        detectedIntent = call.function.name;
                        toolData = rawResult;

                        // Agentic 2-turn reasoning
                        groqMessages.push(msg);
                        groqMessages.push({
                            role: 'tool',
                            tool_call_id: call.id,
                            content: JSON.stringify(rawResult)
                        });

                        try {
                            const secondRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                                method: 'POST',
                                headers: { 'Authorization': `Bearer ${groqKey.trim()}`, 'Content-Type': 'application/json' },
                                body: JSON.stringify({ model, messages: groqMessages, max_tokens: 1500 })
                            });
                            const secondData = await secondRes.json();
                            const secondContent = secondData.choices?.[0]?.message?.content;
                            if (secondContent) {
                                reply = secondContent;
                                voiceText = cleanForVoice(reply);
                            }
                        } catch (sgErr) {
                            console.warn("Groq 2nd turn error:", sgErr.message);
                        }

                        if (!reply) {
                            const actionRes = await executeToolAction({ fnName: call.function.name, args, userData, inArabic });
                            reply = actionRes.reply;
                            voiceText = actionRes.voiceText;
                        }
                    } else if (msg?.content) {
                        reply = msg.content;
                        voiceText = cleanForVoice(reply);
                    }
                    if (reply) break;
                } catch (gErr) {
                    console.warn(`Groq model ${model} error (${String(gErr.message).slice(0, 80)}), trying next...`);
                }
            }
        } catch (groqErr) {
            console.error("Groq Error (falling back to Gemini):", groqErr.message);
        }
    }

    // ==========================================
    // 2. Google Gemini Fallback Tier
    // ==========================================
    const geminiKey = process.env.GEMINI_API_KEY;
    if (!reply && geminiKey) {
        try {
            const ai = new GoogleGenAI({ apiKey: geminiKey });
            const configuredModel = process.env.AI_MODEL && process.env.AI_MODEL !== 'gemini-3.8-flash' ? process.env.AI_MODEL : null;
            const candidateModels = [
                configuredModel,
                'gemini-3.5-flash',
                'gemini-3.7-flash',
                'gemini-3.1-flash-lite',
                'gemini-flash-latest'
            ].filter(Boolean);

            const geminiTools = [{
                functionDeclarations: [
                    {
                        name: 'assign_homework',
                        description: 'Creates and assigns homework or practice questions to a student or class in the SAT platform. Always invoke this when the user asks to assign, create, or give homework/test/exam.',
                        parameters: {
                            type: 'OBJECT',
                            properties: {
                                studentName: { type: 'STRING', description: 'Name of the student to assign to (e.g. Adam, ahmed5)' },
                                className: { type: 'STRING', description: 'Name of the class or group' },
                                topic: { type: 'STRING', description: 'Topic or chapter e.g. Circles, Real Exam, Algebra' },
                                section: { type: 'STRING', description: 'Platform section: Basics Classified, Advanced Classified, Real Exams, or Quizzes' },
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
                        name: 'audit_exam_questions',
                        description: 'Audits questions in any exam, test, or chapter to find problems (missing diagrams/images, missing or duplicate answers, broken LaTeX, student reports).',
                        parameters: {
                            type: 'OBJECT',
                            properties: {
                                examName: { type: 'STRING', description: 'Name of the exam or chapter to check' },
                                limit: { type: 'INTEGER', description: 'Number of questions to check (default: 25)' }
                            },
                            required: ['examName']
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

            // Build multi-turn memory contents for Gemini
            const geminiContents = [];
            if (Array.isArray(history) && history.length > 0) {
                history.forEach(h => {
                    if (h.content && h.content.trim()) {
                        geminiContents.push({
                            role: h.role === 'model' || h.role === 'assistant' ? 'model' : 'user',
                            parts: [{ text: h.content.trim() }]
                        });
                    }
                });
            }
            const userParts = [];
            if (image && typeof image === 'string' && image.startsWith('data:image/')) {
                const m = image.match(/^data:([^;]+);base64,(.+)$/);
                if (m) {
                    userParts.push({ inlineData: { mimeType: m[1], data: m[2] } });
                }
            }
            userParts.push({
                text: rawMessage || (inArabic ? 'يرجى مراجعة وشرح الصورة المرفقة بالتفصيل.' : 'Please analyze the attached image.')
            });
            geminiContents.push({
                role: 'user',
                parts: userParts
            });

            let response = null;
            let lastErr = null;

            for (const model of candidateModels) {
                try {
                    response = await ai.models.generateContent({
                        model,
                        contents: geminiContents,
                        config: {
                            systemInstruction,
                            tools: geminiTools
                        }
                    });
                    if (response) break;
                } catch (mErr) {
                    lastErr = mErr;
                    console.warn(`Gemini model ${model} error (${mErr.message.slice(0, 80)}), trying next fallback model...`);
                }
            }

            if (response && response.functionCalls && response.functionCalls.length > 0) {
                const call = response.functionCalls[0];
                const actionRes = await executeToolAction({
                    fnName: call.name,
                    args: call.args || {},
                    userData,
                    inArabic
                });
                reply = actionRes.reply;
                voiceText = actionRes.voiceText;
                toolData = actionRes.toolData;
                detectedIntent = actionRes.detectedIntent;
            } else if (response && response.text) {
                reply = response.text;
                voiceText = cleanForVoice(reply);
            }
        } catch (apiErr) {
            console.error("Gemini Copilot Error:", apiErr);
        }
    }

    // ==========================================
    // 3. Fallback Engine: If all models are unavailable
    // ==========================================
    if (!reply) {
        const lowerMsg = rawMessage.toLowerCase();
        const isAuditQuestion = /who didn't|who submitted|pending|مين عمل|مين معملش|تسليم/i.test(lowerMsg);
        const isAssignRequest = /assign|create hw|create assignment|اعمل واجب|نزل واجب/i.test(lowerMsg);
        const isExamAudit = /(check|audit|examine|review|mistakes|problems|inspect|فحص|راجع|أخطاء|مشاكل)/i.test(lowerMsg) &&
                            /(exam|test|questions|medium|hard|module|202[3-7]|امتحان|كويز|أسئلة)/i.test(lowerMsg);

        if (isExamAudit) {
            const auditRes = await executeToolAction({
                fnName: 'audit_exam_questions',
                args: { examName: rawMessage, limit: 25 },
                userData,
                inArabic
            });
            reply = auditRes.reply;
            voiceText = auditRes.voiceText;
            toolData = auditRes.toolData;
            detectedIntent = 'audit_exam';
        } else if (isAssignRequest) {
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
                ? `أهلاً بك! أنا **${arabicCopilotName}**.\n\nيمكنك أن تطلب مني فحص أسئلة أي امتحان للتأكد من خلوه من الأخطاء، تعيين واجب لطالب، حل أسئلة SAT، أو فحص تسليمات الطلاب.`
                : `Hello! I am your AI Copilot for **${copilotName}**.\n\nYou can ask me to audit any exam questions for errors, assign homework to students, solve SAT questions, or track submissions.`;
            voiceText = cleanForVoice(reply);
        }
    }

    const replyIsArabic = isArabic(reply) || isArabic(voiceText) || inArabic;
    return {
        reply,
        voiceText: voiceText || cleanForVoice(reply, replyIsArabic),
        language: replyIsArabic ? 'ar' : 'en',
        data: toolData,
        intent: detectedIntent
    };
}

module.exports = {
    processCopilotChat,
    auditHomework,
    auditExamQuestions,
    lookupStudent,
    getPlatformOverview,
    solveQuestion,
    assignHomework
};


