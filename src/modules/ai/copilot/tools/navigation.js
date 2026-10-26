const courseModel = require('../../../../../DB/models/course.model');
const assignmentModel = require('../../../../../DB/models/assignment.model');
const { ToolError, isId } = require('../util');

const getCourse = {
    name: 'get_course',
    kind: 'read',
    status: () => 'Opening the course',
    description: 'One of the teacher\'s courses: its sessions in order with dates, how many students completed each, and the online homework and classwork attached to each session (with assignmentIds).',
    input_schema: {
        type: 'object',
        properties: { courseId: { type: 'string' } },
        required: ['courseId'],
        additionalProperties: false,
    },
    run: async ({ courseId }, { scope }) => {
        await scope.load();
        if (!isId(courseId) || !scope.courses.some(c => String(c._id) === courseId)) {
            throw new ToolError('That course is not one of yours. Use list_my_classes to get the right id.');
        }
        const course = await courseModel.findById(courseId).select('name description students sessions progress isActive').lean();
        const hwIds = (course.sessions || []).flatMap(s => [...(s.onlineHw || []), ...(s.onlineClasswork || [])]);
        const titles = new Map((await assignmentModel.find({ _id: { $in: hwIds } }).select('title').lean()).map(a => [String(a._id), a.title]));
        const completedBy = (sessionId) => (course.progress || []).filter(p => (p.completedSessions || []).some(id => String(id) === String(sessionId))).length;
        const listHw = (ids) => (ids || []).map(id => ({ assignmentId: String(id), title: titles.get(String(id)) || 'Deleted assignment' }));
        return {
            courseId,
            name: course.name,
            active: course.isActive !== false,
            students: (course.students || []).length,
            sessions: (course.sessions || []).sort((a, b) => a.order - b.order).map(s => ({
                sessionId: String(s._id),
                order: s.order,
                title: s.title,
                date: s.date || null,
                completedBy: completedBy(s._id),
                onlineHomework: listHw(s.onlineHw),
                onlineClasswork: listHw(s.onlineClasswork),
                pdfHomeworkSubmissions: (s.studentHwSubmissions || []).length,
            })),
        };
    },
};

// Pages the Copilot may open, and the id each one needs
const PAGES = {
    teacher_dashboard: { needs: [], path: () => '/dashboard/teacher', label: 'Teacher dashboard' },
    courses: { needs: [], path: () => '/teacher/courses', label: 'Courses' },
    course: { needs: ['courseId'], path: ({ courseId }) => `/teacher/course/${courseId}`, label: 'Course' },
    course_homework_matrix: { needs: ['courseId'], path: ({ courseId }) => `/teacher/course/${courseId}/hw-matrix`, label: 'Course homework report' },
    course_test_matrix: { needs: ['courseId'], path: ({ courseId }) => `/teacher/course/${courseId}/test-matrix`, label: 'Course test report' },
    assignment_reports: { needs: ['assignmentId'], path: ({ assignmentId }) => `/assignment/${assignmentId}/reports`, label: 'Assignment results' },
    assignment_class_view: { needs: ['assignmentId'], path: ({ assignmentId }) => `/teacher/assignment/${assignmentId}/view`, label: 'Homework view for the projector' },
    student_history: { needs: ['studentId'], path: ({ studentId }) => `/teacher/student/${studentId}/history`, label: 'Student history' },
    student_assignment_report: { needs: ['studentId', 'assignmentId'], path: ({ studentId, assignmentId }) => `/teacher/assignmentReport/${studentId}/${assignmentId}`, label: 'Student answers for one assignment' },
    question_bank_chapter: { needs: ['chapterId', 'questionTypeId', 'subjectId'], path: ({ chapterId, questionTypeId, subjectId }) => `/question/${chapterId}/${questionTypeId}/${subjectId}`, label: 'Question bank chapter' },
};

const openPage = {
    name: 'open_page',
    kind: 'read',
    status: () => 'Opening the page',
    description: `Opens a page of the website for the teacher, for example a student's history or an assignment's results. Pages: ${Object.entries(PAGES).map(([key, p]) => `${key} (${p.needs.join(', ') || 'no id'})`).join('; ')}. Use it when the teacher asks to open, show or go to something, or when seeing the page would help more than a text answer.`,
    input_schema: {
        type: 'object',
        properties: {
            page: { type: 'string', enum: Object.keys(PAGES) },
            courseId: { type: 'string' },
            assignmentId: { type: 'string' },
            studentId: { type: 'string' },
            chapterId: { type: 'string' },
            questionTypeId: { type: 'string' },
            subjectId: { type: 'string' },
        },
        required: ['page'],
        additionalProperties: false,
    },
    run: async (input, { scope }) => {
        const page = PAGES[input.page];
        const missing = page.needs.filter(key => !isId(input[key]));
        if (missing.length) throw new ToolError(`To open ${page.label} I need a valid ${missing.join(' and ')}.`);
        await scope.load();
        if (input.assignmentId && page.needs.includes('assignmentId')) await scope.requireAssignment(input.assignmentId);
        if (input.studentId && page.needs.includes('studentId')) await scope.requireStudent(input.studentId);
        if (input.courseId && page.needs.includes('courseId') && !scope.courses.some(c => String(c._id) === input.courseId)) {
            throw new ToolError('That course is not one of yours.');
        }
        const path = page.path(input);
        // `ui` goes to the chat window, which opens the page; Claude only sees `opened`
        return { opened: page.label, ui: { type: 'navigate', path, label: page.label } };
    },
};

module.exports = { tools: [getCourse, openPage] };
