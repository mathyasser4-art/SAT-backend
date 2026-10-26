const courseModel = require('../../../../../DB/models/course.model');
const { addSession, updateSession } = require('../../../course/course.controller');
const callController = require('../callController');
const { ToolError, isId, isIsoDate, today } = require('../util');

// attachAs → the session list it goes in, named the way the course page names it
const LISTS = {
    homework: { field: 'onlineHw', label: 'online homework' },
    classwork: { field: 'onlineClasswork', label: 'classwork (test)' },
};

// The course page loads the course once and its auto-save sends the whole session back, so a page
// left open would put its old homework lists back over a Copilot change until it is reloaded
const RELOAD_NOTE = 'If the course page is open, reload it before editing there, or its next auto-save will undo this.';
const RELOAD_LINE = 'ℹ️ If the course page is open, reload it after confirming, or its next auto-save will undo this';

const idsOf = (list) => (list || []).map(x => String((x && x._id) || x));

const dayOf = (date) => {
    const d = date ? new Date(date) : null;
    return d && !isNaN(d) ? d.toISOString().slice(0, 10) : null;
};

const sessionLabel = (s) => `session ${s.order} "${s.title}"`;

const findSession = (course, sessionId) => {
    const session = isId(sessionId) && (course.sessions || []).find(s => String(s._id) === String(sessionId));
    if (!session) throw new ToolError(`Session "${sessionId}" is not in the course "${course.name}". Use get_course to see its sessions, or create_course_session to add one.`);
    return session;
};

// Which list of the session already holds this assignment, if any
const attachedAs = (session, assignmentId) => Object.keys(LISTS).find(key => idsOf(session[LISTS[key].field]).includes(String(assignmentId))) || null;

// Checks a course session against the teacher's scope and describes it for a confirmation card
const courseTarget = (scope, { courseId, sessionId, attachAs = 'homework' }) => {
    const course = scope.requireCourse(courseId);
    const session = findSession(course, sessionId);
    const date = dayOf(session.date);
    return {
        course,
        session,
        where: `${sessionLabel(session)} of the course "${course.name}"`,
        line: `Course: "${course.name}" › ${sessionLabel(session)}${date ? ` (${date})` : ''}, as ${LISTS[attachAs].label}. Its ${(course.students || []).length} enrolled students see it there`,
    };
};

// Reads the course again right before a change (only the teacher's own), so nothing is built on stale lists
const freshTarget = async (user, { courseId, sessionId }) => {
    const course = await courseModel.findOne({ _id: courseId, teacher: user._id })
        .select('name sessions._id sessions.title sessions.order sessions.onlineHw sessions.onlineClasswork').lean();
    if (!course) throw new ToolError('That course is no longer one of yours.');
    return { course, session: findSession(course, sessionId) };
};

// Puts an assignment on a session through the website's own updateSession controller
const attachToSession = async (user, { courseId, sessionId, assignmentId, attachAs }) => {
    const { course, session } = await freshTarget(user, { courseId, sessionId });
    const already = attachedAs(session, assignmentId);
    if (already) throw new ToolError(`It is already on ${sessionLabel(session)} as ${LISTS[already].label}.`);
    const { field } = LISTS[attachAs];
    // Same request as the course page's Reassign: only the changed list, so the rest of the session is untouched
    const result = await callController(updateSession, {
        user,
        params: { id: String(courseId), sessionId: String(sessionId) },
        body: { [field]: [...idsOf(session[field]), String(assignmentId)] },
    });
    if (!result.ok) throw new ToolError(result.body?.message || 'The website refused to update the session.');
    // updateSession silently drops ids it won't accept, so confirm the assignment is really there now
    const saved = (result.body?.course?.sessions || []).find(s => String(s._id) === String(sessionId));
    if (!saved || !idsOf(saved[field]).includes(String(assignmentId))) {
        throw new ToolError('The website did not keep it on the session. Only assignments you created can be added to your course.');
    }
    return { course: course.name, session: sessionLabel(session) };
};

// Being on a course lets its teacher edit the assignment, so the course endpoints only accept the
// teacher's own assignments; the same rule here gives a clear message instead of a silent drop
const requireAttachable = async (scope, assignmentId) => {
    const assignment = await scope.requireAssignment(assignmentId);
    if (String(assignment.createdBy) !== scope.userId) {
        throw new ToolError('Only an assignment you created can be added to your course, because the course\'s teacher can then edit and delete it. Make your own with create_assignment instead.');
    }
    return assignment;
};

const attachToCourseSession = {
    name: 'attach_to_course_session',
    kind: 'write',
    status: () => 'Preparing the course change',
    description: 'Adds an existing assignment to a session of one of the teacher\'s courses, as online homework or as classwork (a test), like picking it on the course page. Course students only see assignments that are on one of the course\'s sessions. Only assignments the teacher created can be added. courseId from list_my_classes, sessionId from get_course. Shows a confirmation card first.',
    input_schema: {
        type: 'object',
        properties: {
            courseId: { type: 'string', description: 'From list_my_classes' },
            sessionId: { type: 'string', description: 'From get_course' },
            assignmentId: { type: 'string', description: 'From list_assignments' },
            attachAs: { type: 'string', enum: ['homework', 'classwork'], description: 'homework, or classwork (the course page calls it a test)' },
        },
        required: ['courseId', 'sessionId', 'assignmentId', 'attachAs'],
        additionalProperties: false,
    },
    prepare: async (input, { scope }) => {
        await scope.load();
        const target = courseTarget(scope, input);
        const assignment = await requireAttachable(scope, input.assignmentId);
        const already = attachedAs(target.session, input.assignmentId);
        if (already) throw new ToolError(`"${assignment.title}" is already on ${target.where} as ${LISTS[already].label}.`);
        const elsewhere = (target.course.sessions || []).filter(s => String(s._id) !== String(input.sessionId) && attachedAs(s, input.assignmentId));
        const start = assignment.startDate ? String(assignment.startDate).slice(0, 10) : null;
        const end = assignment.endDate ? String(assignment.endDate).slice(0, 10) : null;
        const details = [
            target.line,
            `Assignment: ${(assignment.questions || []).length} questions · Timer: ${assignment.timer ? `${assignment.timer} min` : 'no limit'} · Attempts: ${assignment.attemptsNumber || 1}`,
            `Dates: ${start ? `${start} → due ${end || 'none'}` : 'always open'}`,
        ];
        // The student side refuses an assignment outside its dates, even on a course
        if (start && (!end || end < today())) details.push('⚠️ Its due date has passed, so students can\'t open it until the dates are changed');
        else if (start && start > today()) details.push(`Students can open it from ${start}`);
        if (elsewhere.length) details.push(`It also stays on ${elsewhere.map(sessionLabel).join(', ')}`);
        details.push(RELOAD_LINE);
        return {
            title: 'Add to course session',
            summary: `"${assignment.title}" → ${target.where}`,
            details,
            payload: { courseId: input.courseId, sessionId: input.sessionId, assignmentId: input.assignmentId, attachAs: input.attachAs },
        };
    },
    execute: async (payload, { user, scope }) => {
        // Checked again: the course or the assignment may have changed since the card was shown
        await scope.load();
        scope.requireCourse(payload.courseId);
        const assignment = await requireAttachable(scope, payload.assignmentId);
        const where = await attachToSession(user, payload);
        scope.forget();
        return { attached: true, assignmentId: payload.assignmentId, title: assignment.title, course: where.course, session: where.session, as: payload.attachAs, note: RELOAD_NOTE };
    },
};

const createCourseSession = {
    name: 'create_course_session',
    kind: 'write',
    status: () => 'Preparing the new session',
    description: 'Adds a new, empty session at the end of one of the teacher\'s courses, like the Add Session button on the course page. Use it when the teacher wants homework on a session that does not exist yet, then create_assignment or attach_to_course_session with the new sessionId. Shows a confirmation card first.',
    input_schema: {
        type: 'object',
        properties: {
            courseId: { type: 'string', description: 'From list_my_classes' },
            title: { type: 'string', description: 'e.g. "Session 5: Linear equations"' },
            date: { type: 'string', description: 'YYYY-MM-DD, the day of the lesson (optional)' },
        },
        required: ['courseId', 'title'],
        additionalProperties: false,
    },
    prepare: async (input, { scope }) => {
        await scope.load();
        const course = scope.requireCourse(input.courseId);
        const title = input.title.trim();
        if (!title) throw new ToolError('The session needs a title.');
        if (input.date !== undefined && !isIsoDate(input.date)) throw new ToolError('date must look like 2026-11-02.');
        const sessions = [...(course.sessions || [])].sort((a, b) => a.order - b.order);
        const last = sessions[sessions.length - 1];
        return {
            title: 'Add course session',
            summary: `"${title}" in the course "${course.name}"`,
            details: [
                `It becomes session ${sessions.length + 1}${last ? `, after "${last.title}"` : ''}`,
                `Date: ${input.date || 'none'}`,
                'It starts empty: homework, classwork, videos and PDFs can be added afterwards',
                'ℹ️ If the course page is open, reload it after confirming to see the new session',
            ],
            payload: { courseId: input.courseId, title, ...(input.date ? { date: input.date } : {}) },
        };
    },
    execute: async ({ courseId, title, date }, { user, scope }) => {
        await scope.load();
        const before = new Set((scope.requireCourse(courseId).sessions || []).map(s => String(s._id)));
        // Same body as the course page's Add Session button; the controller numbers it after the last session
        const result = await callController(addSession, {
            user,
            params: { id: String(courseId) },
            body: { title, ...(date ? { date } : {}), explanationVideoUrl: '', recordingUrl: '', pdfExercises: [], hwPdfs: [], onlineHw: [], onlineClasswork: [] },
        });
        if (!result.ok || !result.body?.course) throw new ToolError(result.body?.message || 'The website refused to add the session.');
        scope.forget();
        const sessions = result.body.course.sessions || [];
        const added = sessions.find(s => !before.has(String(s._id))) || sessions[sessions.length - 1];
        return {
            created: true, courseId, sessionId: added ? String(added._id) : null, title, order: added ? added.order : null,
            // The open page numbers its next Add Session from its old list
            note: 'If the course page is open, reload it to see the new session before adding another one there.',
        };
    },
};

module.exports = {
    tools: [createCourseSession, attachToCourseSession],
    LISTS,
    RELOAD_NOTE,
    RELOAD_LINE,
    courseTarget,
    freshTarget,
    attachToSession,
};
