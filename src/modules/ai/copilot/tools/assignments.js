const assignmentModel = require('../../../../../DB/models/assignment.model');
const answerModel = require('../../../../../DB/models/answer.model');
const userModel = require('../../../../../DB/models/user.model');
const questionModel = require('../../../../../DB/models/question.model');
const chapterModel = require('../../../../../DB/models/chapter.model');
const {
    createAssignment, updateAssignment, deleteAssignment, duplicateAssignment, getStudentResults, getQuestionStats,
} = require('../../../assignment/controller/assignment.controller');
const callController = require('../callController');
const { ToolError, isId, containsRegex, shorten, today, addDays, isIsoDate } = require('../util');
const { courseTarget, freshTarget, attachToSession, RELOAD_NOTE, RELOAD_LINE } = require('./courses');

const pointsOf = (questions) => questions.reduce((sum, q) => sum + ((typeof q.questionPoints === 'number' && q.questionPoints > 0) ? q.questionPoints : 1), 0);

const classNames = (scope, ids) => ids.map(id => scope.className(id) || 'a class outside your list').join(', ');

const checkDates = (startDate, endDate) => {
    if (startDate !== undefined && !isIsoDate(startDate)) throw new ToolError('startDate must look like 2026-11-02.');
    if (endDate !== undefined && !isIsoDate(endDate)) throw new ToolError('endDate must look like 2026-11-09.');
    if (startDate && endDate && endDate < startDate) throw new ToolError('The due date is before the start date.');
};

const requireClasses = (scope, classIds) => {
    if (!Array.isArray(classIds) || classIds.length === 0) throw new ToolError('Pick at least one class. Students only see homework given to their class.');
    classIds.forEach(id => scope.requireClass(id));
    return [...new Set(classIds.map(String))];
};

// Picks the questions for a new assignment from explicit ids, a chapter, or a topic
const pickQuestions = async ({ questionIds, chapterId, topic, questionCount }) => {
    if (Array.isArray(questionIds) && questionIds.length > 0) {
        const bad = questionIds.filter(id => !isId(id));
        if (bad.length) throw new ToolError(`These are not valid question ids: ${bad.join(', ')}`);
        const found = await questionModel.find({ _id: { $in: questionIds } }).select('question questionPoints typeOfAnswer').lean();
        const byId = new Map(found.map(q => [String(q._id), q]));
        const missing = questionIds.filter(id => !byId.has(String(id)));
        if (missing.length) throw new ToolError(`These questions do not exist: ${missing.join(', ')}`);
        return { questions: questionIds.map(id => byId.get(String(id))), source: 'the questions you chose' };
    }
    if (chapterId) {
        if (!isId(chapterId)) throw new ToolError('chapterId is not valid. Use browse_question_bank or search_question_bank to find it.');
        const chapter = await chapterModel.findById(chapterId).select('chapterName questions').lean();
        if (!chapter) throw new ToolError('That chapter does not exist.');
        let ids = (chapter.questions || []).map(String);
        if (ids.length === 0) ids = (await questionModel.find({ chapter: chapterId }).select('_id').lean()).map(q => String(q._id));
        if (ids.length === 0) throw new ToolError(`The chapter "${chapter.chapterName}" has no questions.`);
        if (questionCount && questionCount < ids.length) {
            ids = ids.map(id => ({ id, r: Math.random() })).sort((a, b) => a.r - b.r).slice(0, questionCount).map(x => x.id);
        }
        const found = await questionModel.find({ _id: { $in: ids } }).select('question questionPoints typeOfAnswer').lean();
        const byId = new Map(found.map(q => [String(q._id), q]));
        return {
            questions: ids.map(id => byId.get(id)).filter(Boolean),
            source: questionCount ? `${questionCount} random questions from "${chapter.chapterName}"` : `all of "${chapter.chapterName}"`,
        };
    }
    if (topic && topic.trim()) {
        const size = questionCount || 10;
        const pool = await questionModel.aggregate([
            { $match: { $or: [{ topic: containsRegex(topic) }, { question: containsRegex(topic) }] } },
            { $sample: { size } },
            { $project: { question: 1, questionPoints: 1, typeOfAnswer: 1 } },
        ]);
        if (pool.length === 0) throw new ToolError(`No questions match the topic "${topic}". Try search_question_bank to find a chapter instead.`);
        return { questions: pool, source: `${pool.length} random questions on "${topic}"` };
    }
    throw new ToolError('Say which questions to use: questionIds, a chapterId, or a topic.');
};

const assignmentRow = (a, scope) => ({
    assignmentId: String(a._id),
    title: a.title,
    classes: (a.classes || []).map(c => scope.className(c) || 'other class'),
    startDate: a.startDate || null,
    endDate: a.endDate || null,
    questions: (a.questions || []).length,
    totalPoints: a.totalPoints || null,
    timerMinutes: a.timer ?? null,
    attemptsNumber: a.attemptsNumber || 1,
    createdByYou: String(a.createdBy) === scope.userId,
});

const listAssignments = {
    name: 'list_assignments',
    kind: 'read',
    status: () => 'Looking up your assignments',
    description: 'Lists the teacher\'s homework and quizzes, newest first, with ids, classes, dates and size. Filter by part of the title or by class. Use it to turn "the last homework" or an assignment name into an assignmentId.',
    input_schema: {
        type: 'object',
        properties: {
            search: { type: 'string', description: 'Part of the assignment title' },
            classId: { type: 'string', description: 'Only assignments given to this class' },
            limit: { type: 'integer', minimum: 1, maximum: 50, description: 'Default 15' },
        },
        additionalProperties: false,
    },
    run: async ({ search, classId, limit = 15 }, { scope }) => {
        await scope.load();
        const access = [
            { createdBy: scope.user._id },
            { classes: { $in: [...scope.classIds] } },
            { _id: { $in: [...scope.courseAssignmentIds] } },
        ];
        const filter = { $and: [{ $or: access }] };
        if (search && search.trim()) filter.$and.push({ title: containsRegex(search) });
        if (classId) {
            scope.requireClass(classId);
            filter.$and.push({ classes: classId });
        }
        const rows = await assignmentModel.find(filter)
            .select('title classes startDate endDate questions totalPoints timer attemptsNumber createdBy')
            .sort({ _id: -1 }).limit(limit).lean();
        return { count: rows.length, today: today(), assignments: rows.map(a => assignmentRow(a, scope)) };
    },
};

const getAssignmentResults = {
    name: 'get_assignment_results',
    kind: 'read',
    status: () => 'Checking who submitted',
    description: 'Results of one assignment: every student on it (its classes and the courses it is on) with status (Completed, In Progress, Not Started), best score and percentage, plus totals. Use it for "who didn\'t do the homework", "who got below 60%", "what is the class average".',
    input_schema: {
        type: 'object',
        properties: { assignmentId: { type: 'string' } },
        required: ['assignmentId'],
        additionalProperties: false,
    },
    run: async ({ assignmentId }, { scope, user }) => {
        const assignment = await scope.requireAssignment(assignmentId);
        const result = await callController(getStudentResults, { user, params: { assignmentID: assignmentId } });
        if (!result.ok) throw new ToolError(result.body?.message || 'Could not load the results.');
        const students = (result.body.students || []).map(s => ({
            studentId: String(s.studentId),
            name: s.userName,
            status: s.status,
            score: `${s.score}/${s.totalPossible}`,
            percentage: Math.round(s.percentage || 0),
            attemptsUsed: s.attemptsUsed,
            completedAt: s.completedAt || null,
        }));
        // The controller lists class members plus whoever opened it, so course students who haven't
        // started would be missing from "who didn't do it"
        const onCourses = scope.coursesWith(assignmentId);
        const listed = new Set(students.map(s => s.studentId));
        const missing = [...new Set(onCourses.flatMap(c => (c.students || []).map(String)))].filter(sid => !listed.has(sid));
        if (missing.length) {
            const total = result.body.assignment?.totalPoints ?? assignment.totalPoints ?? 0;
            const found = await userModel.find(scope.studentFilter({ _id: { $in: missing } })).select('userName').lean();
            found.forEach(st => students.push({
                studentId: String(st._id), name: st.userName, status: 'Not Started', score: `0/${total}`, percentage: 0, attemptsUsed: 0, completedAt: null,
            }));
        }
        const done = students.filter(s => s.status === 'Completed');
        return {
            assignment: {
                assignmentId, title: assignment.title, endDate: assignment.endDate || null, classes: classNames(scope, assignment.classes || []),
                ...(onCourses.length ? { courses: onCourses.map(c => c.name) } : {}),
            },
            totals: {
                students: students.length,
                completed: done.length,
                inProgress: students.filter(s => s.status === 'In Progress').length,
                notStarted: students.filter(s => s.status === 'Not Started').length,
                averagePercentOfCompleted: done.length ? Math.round(done.reduce((x, s) => x + s.percentage, 0) / done.length) : null,
            },
            students,
        };
    },
};

const getQuestionStatsTool = {
    name: 'get_question_stats',
    kind: 'read',
    status: () => 'Checking each question',
    description: 'Per-question breakdown of one assignment: percent correct, who got it wrong and what they answered, and the correct answer. Use it to find the hardest questions or a question whose answer key may be wrong (almost everyone "wrong" with the same answer).',
    input_schema: {
        type: 'object',
        properties: { assignmentId: { type: 'string' } },
        required: ['assignmentId'],
        additionalProperties: false,
    },
    run: async ({ assignmentId }, { scope, user }) => {
        await scope.requireAssignment(assignmentId);
        const result = await callController(getQuestionStats, { user, params: { assignmentID: assignmentId } });
        if (!result.ok) throw new ToolError(result.body?.message || 'Could not load the question stats.');
        const { assignment, summary, questions = [] } = result.body;
        return {
            assignment: { assignmentId, title: assignment?.title },
            summary,
            questions: questions.map(q => {
                const wrongAnswers = {};
                (q.wrongStudents || []).forEach(w => { wrongAnswers[w.answer] = (wrongAnswers[w.answer] || 0) + 1; });
                return {
                    number: q.index,
                    questionId: String(q._id),
                    type: q.typeOfAnswer,
                    question: shorten(q.question, 140),
                    correctAnswer: shorten(q.correctAnswer, 80),
                    percentCorrect: q.stats?.percentCorrect ?? null,
                    correct: q.stats?.correct,
                    wrong: q.stats?.wrong,
                    notAnswered: q.stats?.notAnswered,
                    commonWrongAnswers: Object.entries(wrongAnswers).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([answer, count]) => ({ answer: shorten(answer, 60), count })),
                    wrongStudents: (q.wrongStudents || []).map(w => w.userName),
                };
            }),
        };
    },
};

const createAssignmentTool = {
    name: 'create_assignment',
    kind: 'write',
    status: () => 'Preparing the assignment',
    description: 'Creates homework or a quiz for one or more of the teacher\'s classes, and/or puts it on a session of one of their courses (courseId and sessionId from get_course; course students only see assignments that are on a session). Questions come from exact questionIds, from a chapterId (the whole chapter, or a random questionCount from it), or from a topic (random questionCount, default 10). Defaults when the teacher does not say: starts today and due in 7 days (homework only on a course session has no dates and stays open, like on the course page), 35 minute timer, 1 attempt, attached as homework. The teacher sees a confirmation card with the exact details and nothing is created until they press Confirm.',
    input_schema: {
        type: 'object',
        properties: {
            title: { type: 'string' },
            classIds: { type: 'array', items: { type: 'string' }, maxItems: 30, description: 'Classes that get it (from list_my_classes). Needed unless courseId and sessionId are given' },
            courseId: { type: 'string', description: 'Put it on a session of this course (from list_my_classes)' },
            sessionId: { type: 'string', description: 'The course session it goes on (from get_course)' },
            attachAs: { type: 'string', enum: ['homework', 'classwork'], description: 'On the course session: homework (default) or classwork, which the course page calls a test' },
            questionIds: { type: 'array', items: { type: 'string' }, maxItems: 100 },
            chapterId: { type: 'string', description: 'Take questions from this question-bank chapter' },
            topic: { type: 'string', description: 'Take random questions on this topic, e.g. "Quadratic functions"' },
            questionCount: { type: 'integer', minimum: 1, maximum: 100 },
            timerMinutes: { type: 'integer', minimum: 0, maximum: 300, description: '0 means no time limit' },
            attemptsNumber: { type: 'integer', minimum: 1, maximum: 20 },
            startDate: { type: 'string', description: 'YYYY-MM-DD' },
            endDate: { type: 'string', description: 'YYYY-MM-DD, the due date' },
            explanationMode: { type: 'string', enum: ['independent', 'guided'], description: 'guided shows explanations while solving' },
        },
        required: ['title'],
        additionalProperties: false,
    },
    prepare: async (input, { scope }) => {
        await scope.load();
        const onCourse = input.courseId !== undefined || input.sessionId !== undefined;
        if (!onCourse && input.attachAs !== undefined) throw new ToolError('attachAs only applies together with courseId and sessionId.');
        if (onCourse && (!input.courseId || !input.sessionId)) throw new ToolError('To put it on a course, give both courseId and sessionId (get_course lists the sessions).');
        const attachAs = input.attachAs || 'homework';
        const target = onCourse ? courseTarget(scope, { ...input, attachAs }) : null;
        const classIds = target && !(input.classIds || []).length ? [] : requireClasses(scope, input.classIds);
        checkDates(input.startDate, input.endDate);
        // The course page creates session homework with no dates (always open); class homework defaults to a week
        const dated = classIds.length > 0 || input.startDate !== undefined || input.endDate !== undefined;
        const startDate = dated ? (input.startDate || today()) : undefined;
        const endDate = dated ? (input.endDate || addDays(startDate, 7)) : undefined;
        checkDates(startDate, endDate);
        const { questions, source } = await pickQuestions(input);
        const timer = input.timerMinutes ?? 35;
        const payload = {
            title: input.title.trim(),
            // Like the course page, course-only homework is created without classes
            ...(classIds.length ? { classes: classIds } : {}),
            questions: questions.map(q => String(q._id)),
            totalPoints: pointsOf(questions),
            timer,
            attemptsNumber: input.attemptsNumber || 1,
            explanationMode: input.explanationMode || 'independent',
            ...(dated ? { startDate, endDate } : {}),
            ...(target ? { attachTo: { courseId: input.courseId, sessionId: input.sessionId, attachAs } } : {}),
        };
        const forWhom = [classIds.length ? classNames(scope, classIds) : null, target ? target.where : null].filter(Boolean).join(' + ');
        return {
            title: target ? 'Create assignment on a course session' : 'Create assignment',
            summary: `"${payload.title}" for ${forWhom}`,
            details: [
                ...(target ? [target.line] : []),
                `Questions: ${questions.length} (${source}), ${payload.totalPoints} points`,
                `Dates: ${dated ? `${startDate} → due ${endDate}` : 'always open (no start or due date, like homework added on the course page)'}`,
                `Timer: ${timer ? `${timer} min` : 'no limit'} · Attempts: ${payload.attemptsNumber} · Mode: ${payload.explanationMode}`,
                ...questions.slice(0, 3).map((q, i) => `Q${i + 1}: ${shorten(q.question, 90)}`),
                ...(target ? [RELOAD_LINE] : []),
            ],
            payload,
        };
    },
    execute: async ({ attachTo, ...body }, { user, scope }) => {
        // The session must still be there, or the new assignment would reach no one
        if (attachTo) await freshTarget(user, attachTo);
        const result = await callController(createAssignment, { user, body: { ...body } });
        if (!result.ok || !result.body?.assignment) throw new ToolError(result.body?.message || 'The website refused to create it.');
        const created = { created: true, assignmentId: String(result.body.assignment._id), title: body.title, endDate: body.endDate || null };
        if (!attachTo) return created;
        try {
            const where = await attachToSession(user, { ...attachTo, assignmentId: created.assignmentId });
            scope.forget();
            return { ...created, attached: true, course: where.course, session: where.session, as: attachTo.attachAs, note: RELOAD_NOTE };
        } catch (err) {
            if (!(err instanceof ToolError)) console.error('Copilot: adding a new assignment to a course session failed:', err);
            // Half done: say exactly what exists, so the teacher isn't left guessing
            const reach = body.classes?.length ? 'Its classes can see it, but it is not on the course yet.' : 'No student can see it yet.';
            throw new ToolError(`The assignment "${body.title}" was created (assignmentId ${created.assignmentId}), but adding it to the course session failed (${String(err.message).replace(/\.$/, '')}). ${reach} Ask me to add it to the session again, or to delete it.`);
        }
    },
};

const updateAssignmentTool = {
    name: 'update_assignment',
    kind: 'write',
    status: () => 'Preparing the change',
    description: 'Changes an existing assignment: title, dates (for example extend the deadline), timer, attempts, explanation mode, which classes get it, or which questions are on it. Only send the fields that change. Shows the teacher a confirmation card first.',
    input_schema: {
        type: 'object',
        properties: {
            assignmentId: { type: 'string' },
            title: { type: 'string' },
            startDate: { type: 'string', description: 'YYYY-MM-DD' },
            endDate: { type: 'string', description: 'YYYY-MM-DD' },
            timerMinutes: { type: 'integer', minimum: 0, maximum: 300 },
            attemptsNumber: { type: 'integer', minimum: 1, maximum: 20 },
            explanationMode: { type: 'string', enum: ['independent', 'guided'] },
            addClassIds: { type: 'array', items: { type: 'string' }, maxItems: 30 },
            removeClassIds: { type: 'array', items: { type: 'string' }, maxItems: 30 },
            addQuestionIds: { type: 'array', items: { type: 'string' }, maxItems: 100 },
            removeQuestionIds: { type: 'array', items: { type: 'string' }, maxItems: 100 },
        },
        required: ['assignmentId'],
        additionalProperties: false,
    },
    prepare: async (input, { scope }) => {
        const assignment = await scope.requireAssignment(input.assignmentId, { forChange: true });
        const changes = {};
        const details = [];
        if (input.title !== undefined && input.title.trim() !== assignment.title) {
            changes.title = input.title.trim();
            details.push(`Title: "${assignment.title}" → "${changes.title}"`);
        }
        checkDates(input.startDate, input.endDate);
        let startDate = input.startDate ?? assignment.startDate;
        let endDate = input.endDate ?? assignment.endDate;
        let filled = null;
        // The student page checks dates only when there is a start date, and a start with no due date
        // locks everyone out, so undated (course) homework always gets both, as create_assignment fills them
        if (input.startDate !== undefined || input.endDate !== undefined) {
            if (startDate && !endDate) {
                endDate = addDays(String(startDate).slice(0, 10), 7);
                filled = 'endDate';
            } else if (endDate && !startDate) {
                startDate = today() < endDate ? today() : String(endDate).slice(0, 10);
                filled = 'startDate';
            }
        }
        if (startDate && endDate && endDate < startDate) throw new ToolError('The due date would be before the start date.');
        if (startDate !== assignment.startDate) {
            changes.startDate = startDate;
            details.push(`Start: ${assignment.startDate || 'none'} → ${startDate}${filled === 'startDate' ? ' (added: a due date only works with a start date)' : ''}`);
        }
        if (endDate !== assignment.endDate) {
            changes.endDate = endDate;
            details.push(`Due: ${assignment.endDate || 'none'} → ${endDate}${filled === 'endDate' ? ' (added: 7 days after the start, without one students could not open it)' : ''}`);
        }
        if ((changes.startDate || changes.endDate) && endDate < today()) details.push('⚠️ The due date has passed, so students can\'t open it after this change');
        if (input.timerMinutes !== undefined && input.timerMinutes !== assignment.timer) {
            changes.timer = input.timerMinutes;
            details.push(`Timer: ${assignment.timer ?? 'none'} → ${input.timerMinutes || 'no limit'} min`);
        }
        if (input.attemptsNumber !== undefined && input.attemptsNumber !== assignment.attemptsNumber) {
            changes.attemptsNumber = input.attemptsNumber;
            details.push(`Attempts: ${assignment.attemptsNumber || 1} → ${input.attemptsNumber}`);
        }
        if (input.explanationMode !== undefined && input.explanationMode !== assignment.explanationMode) {
            changes.explanationMode = input.explanationMode;
            details.push(`Mode: ${assignment.explanationMode || 'independent'} → ${input.explanationMode}`);
        }
        if (input.addClassIds?.length || input.removeClassIds?.length) {
            await scope.load();
            (input.addClassIds || []).forEach(id => scope.requireClass(id));
            const remove = new Set((input.removeClassIds || []).map(String));
            const next = [...new Set([...(assignment.classes || []).map(String), ...(input.addClassIds || []).map(String)])].filter(id => !remove.has(id));
            // Homework on one of the teacher's course sessions still reaches the course without a class
            const onCourse = scope.courseAssignmentIds.has(String(assignment._id));
            if (next.length === 0 && !onCourse) throw new ToolError('That would leave the assignment with no class, so no student could see it.');
            changes.classes = next;
            details.push(`Classes: ${next.length ? classNames(scope, next) : 'none (it stays on your course)'}`);
        }
        if (input.addQuestionIds?.length || input.removeQuestionIds?.length) {
            const remove = new Set((input.removeQuestionIds || []).map(String));
            const next = [...new Set([...(assignment.questions || []).map(String), ...(input.addQuestionIds || []).map(String)])].filter(id => !remove.has(id));
            if (next.length === 0) throw new ToolError('That would leave the assignment with no questions.');
            const { questions } = await pickQuestions({ questionIds: next });
            changes.questions = next;
            changes.totalPoints = pointsOf(questions);
            details.push(`Questions: ${(assignment.questions || []).length} → ${next.length} (${changes.totalPoints} points)`);
        }
        if (Object.keys(changes).length === 0) throw new ToolError('Nothing would change: those values are already set.');
        return {
            title: 'Change assignment',
            summary: `"${assignment.title}"`,
            details,
            payload: { assignmentId: input.assignmentId, changes },
        };
    },
    execute: async ({ assignmentId, changes }, { user }) => {
        const result = await callController(updateAssignment, { user, params: { assignmentID: assignmentId }, body: { ...changes } });
        if (!result.ok || result.body?.message !== 'success') throw new ToolError(result.body?.message || 'The website refused the change.');
        return { updated: true, assignmentId, changed: Object.keys(changes) };
    },
};

const duplicateAssignmentTool = {
    name: 'duplicate_assignment',
    kind: 'write',
    status: () => 'Preparing the copy',
    description: 'Gives an existing assignment again, with the same questions, to other classes or with new dates (for example re-assign last week\'s homework to another class). Only the creator of the original can do this. Shows a confirmation card first.',
    input_schema: {
        type: 'object',
        properties: {
            assignmentId: { type: 'string' },
            classIds: { type: 'array', items: { type: 'string' }, maxItems: 30 },
            title: { type: 'string', description: 'Defaults to the original title' },
            startDate: { type: 'string', description: 'YYYY-MM-DD, default today' },
            endDate: { type: 'string', description: 'YYYY-MM-DD, default 7 days after start' },
            timerMinutes: { type: 'integer', minimum: 0, maximum: 300 },
            attemptsNumber: { type: 'integer', minimum: 1, maximum: 20 },
        },
        required: ['assignmentId', 'classIds'],
        additionalProperties: false,
    },
    prepare: async (input, { scope }) => {
        const original = await scope.requireAssignment(input.assignmentId);
        if (String(original.createdBy) !== scope.userId) throw new ToolError('Only the teacher who created this assignment can copy it.');
        await scope.load();
        const classIds = requireClasses(scope, input.classIds);
        // Formats first: a malformed start date would otherwise break the default due date
        checkDates(input.startDate, input.endDate);
        const startDate = input.startDate || today();
        const endDate = input.endDate || addDays(startDate, 7);
        checkDates(startDate, endDate);
        const payload = {
            assignmentId: input.assignmentId,
            body: {
                title: (input.title || original.title || 'Assignment').trim(),
                classes: classIds,
                startDate,
                endDate,
                ...(input.timerMinutes !== undefined ? { timer: input.timerMinutes } : {}),
                ...(input.attemptsNumber !== undefined ? { attemptsNumber: input.attemptsNumber } : {}),
            },
        };
        return {
            title: 'Re-assign homework',
            summary: `"${payload.body.title}" for ${classNames(scope, classIds)}`,
            details: [
                `Copy of "${original.title}" (${(original.questions || []).length} questions)`,
                `Dates: ${startDate} → due ${endDate}`,
                `Timer: ${(payload.body.timer ?? original.timer) || 'no limit'} min · Attempts: ${payload.body.attemptsNumber || original.attemptsNumber || 1}`,
            ],
            payload,
        };
    },
    execute: async ({ assignmentId, body }, { user }) => {
        const result = await callController(duplicateAssignment, { user, params: { assignmentID: assignmentId }, body: { ...body } });
        if (!result.ok || !result.body?.newAssignmentId) throw new ToolError(result.body?.message || 'The website refused to copy it.');
        return { created: true, assignmentId: String(result.body.newAssignmentId), title: body.title };
    },
};

const deleteAssignmentTool = {
    name: 'delete_assignment',
    kind: 'write',
    status: () => 'Preparing to delete',
    description: 'Deletes an assignment. Students lose access to it. Shows a confirmation card first that says how many students already submitted.',
    input_schema: {
        type: 'object',
        properties: { assignmentId: { type: 'string' } },
        required: ['assignmentId'],
        additionalProperties: false,
    },
    prepare: async ({ assignmentId }, { scope }) => {
        const assignment = await scope.requireAssignment(assignmentId, { forDelete: true });
        const submitted = (await answerModel.distinct('solveBy', { assignment: assignmentId, completedAt: { $ne: null } })).length;
        return {
            title: 'Delete assignment',
            summary: `"${assignment.title}"`,
            details: [
                `Classes: ${classNames(scope, assignment.classes || []) || 'none'}`,
                submitted ? `⚠️ ${submitted} student(s) already submitted it` : 'No student has submitted it yet',
            ],
            payload: { assignmentId },
            danger: true,
        };
    },
    execute: async ({ assignmentId }, { user, scope }) => {
        // Checked again: the assignment may have changed hands since the card was shown
        await scope.requireAssignment(assignmentId, { forDelete: true });
        const result = await callController(deleteAssignment, { user, params: { assignmentID: assignmentId } });
        if (!result.ok || result.body?.message !== 'success') throw new ToolError(result.body?.message || 'The website refused to delete it.');
        return { deleted: true, assignmentId };
    },
};

module.exports = {
    tools: [listAssignments, getAssignmentResults, getQuestionStatsTool, createAssignmentTool, updateAssignmentTool, duplicateAssignmentTool, deleteAssignmentTool],
};
