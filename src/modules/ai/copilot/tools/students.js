const userModel = require('../../../../../DB/models/user.model');
const assignmentModel = require('../../../../../DB/models/assignment.model');
const answerModel = require('../../../../../DB/models/answer.model');
const questionModel = require('../../../../../DB/models/question.model');
const { getStudentHistory } = require('../../../teacher/controller/teacher.controller');
const callController = require('../callController');
const { gradeAttempts, countedAttemptsBy } = require('../../../../services/grading');
const { ToolError, containsRegex, today } = require('../util');

const pct = (part, whole) => (whole > 0 ? Math.round((part / whole) * 100) : null);

// Topic of a question for reports: its SAT lesson if classified, else its chapter
const topicOf = (q) => q.topic || (q.chapter && q.chapter.chapterName) || 'Unclassified';

// Counted (best submitted) attempt per (student, assignment) as a percentage, the mark the teacher's sheet shows
const bestPercentages = async (answers, assignmentsById) => {
    const submitted = answers.filter(ans => ans.completedAt);
    const grades = await gradeAttempts(submitted, { assignmentsById });
    const best = new Map();
    countedAttemptsBy(submitted, grades, ans => `${ans.solveBy}:${ans.assignment}`)
        .forEach(({ counted }, key) => best.set(key, counted.grade.percentage));
    return best;
};

// Accuracy per topic over every answered question in these answers
const topicAccuracy = async (answers) => {
    const questionIds = [...new Set(answers.flatMap(a => (a.questions || []).map(q => String(q.question))).filter(Boolean))];
    if (questionIds.length === 0) return [];
    const questions = await questionModel.find({ _id: { $in: questionIds } }).select('topic chapter').populate('chapter', 'chapterName').lean();
    const topicById = new Map(questions.map(q => [String(q._id), topicOf(q)]));
    const totals = new Map();
    answers.forEach(ans => (ans.questions || []).forEach(q => {
        if (q.isCorrect === undefined || q.isCorrect === null) return;
        const topic = topicById.get(String(q.question)) || 'Unclassified';
        const row = totals.get(topic) || { topic, answered: 0, correct: 0 };
        row.answered += 1;
        if (q.isCorrect) row.correct += 1;
        totals.set(topic, row);
    }));
    return [...totals.values()]
        .map(r => ({ topic: r.topic, answered: r.answered, percentCorrect: pct(r.correct, r.answered) }))
        .sort((a, b) => a.percentCorrect - b.percentCorrect);
};

const listMyClasses = {
    name: 'list_my_classes',
    kind: 'read',
    status: () => 'Checking your classes',
    description: 'Lists the classes and courses this teacher can manage, with their ids and student counts. Call this first whenever the teacher mentions a class or course by name, so you work with the right id.',
    input_schema: { type: 'object', properties: {}, additionalProperties: false },
    run: async (input, { scope }) => {
        await scope.load();
        const classIds = scope.classes.map(c => c._id);
        const counts = await userModel.aggregate([
            { $match: { role: 'Student', disable: { $ne: true }, class: { $in: classIds } } },
            { $group: { _id: '$class', count: { $sum: 1 } } },
        ]);
        const countById = new Map(counts.map(c => [String(c._id), c.count]));
        return {
            classes: scope.classes.map(c => ({ classId: String(c._id), name: c.class, students: countById.get(String(c._id)) || 0 })),
            courses: scope.courses.map(c => ({
                courseId: String(c._id),
                name: c.name,
                students: (c.students || []).length,
                sessions: (c.sessions || []).length,
            })),
        };
    },
};

const listStudents = {
    name: 'list_students',
    kind: 'read',
    status: () => 'Looking up students',
    description: 'Lists students in the teacher\'s classes or courses, optionally filtered by class, course or a name search. Use it to turn a student name into a studentId. Set includeContacts only when phone numbers are really needed (for example before drafting parent messages).',
    input_schema: {
        type: 'object',
        properties: {
            classId: { type: 'string', description: 'Only students in this class (from list_my_classes)' },
            courseId: { type: 'string', description: 'Only students enrolled in this course (from list_my_classes)' },
            search: { type: 'string', description: 'Part of the student\'s name or email' },
            includeContacts: { type: 'boolean', description: 'Also return student phone, parent name and parent phone' },
        },
        additionalProperties: false,
    },
    run: async ({ classId, courseId, search, includeContacts }, { scope }) => {
        await scope.load();
        const extra = {};
        const and = [];
        if (classId) {
            scope.requireClass(classId);
            and.push({ $or: [{ class: classId }, { classList: classId }] });
        }
        if (courseId) {
            const course = scope.courses.find(c => String(c._id) === String(courseId));
            if (!course) throw new ToolError('That course is not one of yours. Use list_my_classes to get the right id.');
            and.push({ _id: { $in: course.students || [] } });
        }
        if (search && search.trim()) and.push({ $or: [{ userName: containsRegex(search) }, { email: containsRegex(search) }] });
        if (and.length) extra.$and = and;

        const fields = includeContacts ? 'userName email class phone parentName parentPhone' : 'userName email class';
        const students = await userModel.find(scope.studentFilter(extra)).select(fields).sort({ userName: 1 }).limit(300).lean();
        return {
            count: students.length,
            students: students.map(s => ({
                studentId: String(s._id),
                name: s.userName,
                email: s.email,
                className: scope.className(s.class) || null,
                ...(includeContacts ? { phone: s.phone || null, parentName: s.parentName || null, parentPhone: s.parentPhone || null } : {}),
            })),
        };
    },
};

const getStudentReport = {
    name: 'get_student_report',
    kind: 'read',
    status: () => 'Reading the student\'s history',
    description: 'Full progress report for one student: every assignment they did with score, percentage, grade and time, overall statistics, and their weakest topics. Needs a studentId from list_students.',
    input_schema: {
        type: 'object',
        properties: { studentId: { type: 'string' } },
        required: ['studentId'],
        additionalProperties: false,
    },
    run: async ({ studentId }, { scope, user }) => {
        const student = await scope.requireStudent(studentId);
        const history = await callController(getStudentHistory, { user, params: { studentID: studentId } });
        if (!history.ok) throw new ToolError(history.body?.message || 'Could not load this student\'s history.');

        const answers = await answerModel.find({ solveBy: studentId })
            .select('assignment questions.question questions.isCorrect')
            .sort({ _id: -1 }).limit(60).lean();
        const visible = await assignmentModel.find({ _id: { $in: answers.map(a => a.assignment) } }).select('createdBy classes').lean();
        const visibleIds = new Set(visible.filter(a => scope.canSeeAssignment(a)).map(a => String(a._id)));
        const weakTopics = (await topicAccuracy(answers.filter(a => visibleIds.has(String(a.assignment))))).slice(0, 6);

        return {
            student: { studentId, name: student.userName, email: student.email, className: scope.className(student.class) },
            statistics: history.body.statistics,
            assignments: (history.body.assignments || []).map(a => ({
                assignmentId: String(a.assignmentID),
                title: a.assignmentTitle,
                percentage: a.percentage,
                grade: a.grade,
                score: `${a.score}/${a.totalPossible}`,
                completedAt: a.completedAt,
                timeSpent: a.timeSpent,
            })),
            weakTopics,
        };
    },
};

const getClassInsights = {
    name: 'get_class_insights',
    kind: 'read',
    status: () => 'Analysing the class',
    description: 'Analyses a class over its most recent assignments: completion rate and average per assignment, each student\'s average and missed homework, the students at risk, and accuracy per topic (weakest first). Use it for questions like "how is class X doing", "who is struggling", "what should I revise".',
    input_schema: {
        type: 'object',
        properties: {
            classId: { type: 'string' },
            lastAssignments: { type: 'integer', minimum: 1, maximum: 20, description: 'How many recent assignments to analyse (default 8)' },
        },
        required: ['classId'],
        additionalProperties: false,
    },
    run: async ({ classId, lastAssignments = 8 }, { scope }) => {
        await scope.load();
        scope.requireClass(classId);
        const assignments = await assignmentModel.find({ classes: classId })
            .select('title startDate endDate totalPoints questions createdBy classes')
            .sort({ _id: -1 }).limit(lastAssignments).lean();
        const students = await userModel.find(scope.studentFilter({ $and: [{ $or: [{ class: classId }, { classList: classId }] }] }))
            .select('userName').lean();
        if (assignments.length === 0) {
            return { className: scope.className(classId), students: students.length, message: 'This class has no assignments yet.' };
        }

        const answers = await answerModel.find({
            assignment: { $in: assignments.map(a => a._id) },
            solveBy: { $in: students.map(s => s._id) },
        }).select('assignment solveBy attemptNumber total totalPossible questionSet completedAt questions').lean();

        const assignmentsById = new Map(assignments.map(a => [String(a._id), a]));
        const best = await bestPercentages(answers, assignmentsById);
        const now = today();

        const assignmentRows = assignments.map(a => {
            const scores = students.map(s => best.get(`${s._id}:${a._id}`)).filter(v => v !== undefined);
            return {
                assignmentId: String(a._id),
                title: a.title,
                endDate: a.endDate || null,
                completed: `${scores.length}/${students.length}`,
                completionRate: pct(scores.length, students.length),
                averagePercent: scores.length ? Math.round(scores.reduce((x, y) => x + y, 0) / scores.length) : null,
            };
        });

        const studentRows = students.map(s => {
            const scores = [];
            let missed = 0;
            assignments.forEach(a => {
                const value = best.get(`${s._id}:${a._id}`);
                if (value !== undefined) scores.push(value);
                else if (a.endDate && a.endDate < now) missed += 1;
            });
            return {
                studentId: String(s._id),
                name: s.userName,
                completed: scores.length,
                missedPastDeadline: missed,
                averagePercent: scores.length ? Math.round(scores.reduce((x, y) => x + y, 0) / scores.length) : null,
            };
        }).sort((a, b) => (a.averagePercent ?? -1) - (b.averagePercent ?? -1));

        return {
            className: scope.className(classId),
            studentCount: students.length,
            assignmentsAnalysed: assignmentRows,
            atRisk: studentRows.filter(s => s.missedPastDeadline >= 2 || (s.averagePercent !== null && s.averagePercent < 60)),
            students: studentRows,
            topics: await topicAccuracy(answers),
        };
    },
};

// Phone numbers are stored in local format; WhatsApp needs the country code
const COUNTRY_CODE_BY_BRAND = { ais: '966', mrshahin: '20', satarea: '20' };
const toWhatsAppNumber = (raw, brand) => {
    let digits = String(raw || '').replace(/\D/g, '');
    if (!digits) return null;
    if (digits.startsWith('00')) digits = digits.slice(2);
    if (digits.startsWith('0')) {
        const code = process.env.COPILOT_DEFAULT_COUNTRY_CODE || COUNTRY_CODE_BY_BRAND[brand] || '20';
        digits = code + digits.slice(1);
    }
    return digits.length >= 10 ? digits : null;
};

const draftParentMessages = {
    name: 'draft_parent_messages',
    kind: 'read',
    status: () => 'Preparing WhatsApp messages',
    description: 'Prepares a personalised WhatsApp message for the parent of each given student and returns a link per parent. Nothing is sent: the teacher taps each link to send it from their own WhatsApp. In the message, {student} and {parent} are replaced with each student\'s and parent\'s name. Write the message in the language the teacher is using.',
    input_schema: {
        type: 'object',
        properties: {
            studentIds: { type: 'array', items: { type: 'string' }, maxItems: 60 },
            message: { type: 'string', description: 'Message text, may use {student} and {parent}' },
        },
        required: ['studentIds', 'message'],
        additionalProperties: false,
    },
    run: async ({ studentIds, message }, { scope, brand }) => {
        const drafts = [];
        for (const studentId of studentIds) {
            const student = await scope.requireStudent(studentId);
            const text = message
                .replace(/\{student\}/g, student.userName || '')
                .replace(/\{parent\}/g, student.parentName || '');
            const number = toWhatsAppNumber(student.parentPhone || student.phone, brand);
            drafts.push({
                studentId,
                student: student.userName,
                parentName: student.parentName || null,
                usesStudentPhone: !student.parentPhone && !!student.phone,
                link: number ? `https://wa.me/${number}?text=${encodeURIComponent(text)}` : null,
                problem: number ? null : 'No valid phone number saved for this student or parent',
            });
        }
        return {
            note: 'The chat window shows one button per parent. Tell the teacher to tap each one to send it; nothing has been sent yet.',
            drafts: drafts.map(({ link, ...rest }) => ({ ...rest, ready: !!link })),
            // Shown in the chat window only; not sent to Claude
            ui: {
                type: 'whatsapp_links',
                items: drafts.map(d => ({ label: d.parentName ? `${d.parentName} (${d.student})` : d.student, link: d.link, problem: d.problem })),
            },
        };
    },
};

module.exports = { tools: [listMyClasses, listStudents, getStudentReport, getClassInsights, draftParentMessages], topicAccuracy };
