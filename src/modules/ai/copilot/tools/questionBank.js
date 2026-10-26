const questionModel = require('../../../../../DB/models/question.model');
const chapterModel = require('../../../../../DB/models/chapter.model');
const unitModel = require('../../../../../DB/models/unit.model');
const subjectModel = require('../../../../../DB/models/subject.model');
const questionTypeModel = require('../../../../../DB/models/questionType.model');
const questionReportModel = require('../../../../../DB/models/questionReport.model');
const { ToolError, isId, cleanHtml, shorten } = require('../util');

const picUrl = (pic) => (pic && typeof pic === 'object' ? pic.secure_url : pic) || null;
const isFilled = (v) => v !== null && v !== undefined && String(v).trim() !== '';

// Every chapter with its full path (type › subject › unit › chapter), cached for a few minutes
let catalogCache = { at: 0, rows: null };
const loadCatalog = async () => {
    if (catalogCache.rows && Date.now() - catalogCache.at < 5 * 60 * 1000) return catalogCache.rows;
    const [types, subjects, units, chapters] = await Promise.all([
        questionTypeModel.find().select('typeOfquestion').lean(),
        subjectModel.find().select('subjectName').lean(),
        unitModel.find().select('unitName subject questionType').lean(),
        chapterModel.aggregate([{ $project: { chapterName: 1, unit: 1, count: { $size: { $ifNull: ['$questions', []] } } } }]),
    ]);
    const typeName = new Map(types.map(t => [String(t._id), t.typeOfquestion]));
    const subjectName = new Map(subjects.map(s => [String(s._id), s.subjectName]));
    const unitById = new Map(units.map(u => [String(u._id), u]));
    const rows = chapters.map(ch => {
        const unit = unitById.get(String(ch.unit)) || {};
        return {
            questionTypeId: unit.questionType ? String(unit.questionType) : null,
            questionType: typeName.get(String(unit.questionType)) || null,
            subjectId: unit.subject ? String(unit.subject) : null,
            subject: subjectName.get(String(unit.subject)) || null,
            unitId: unit._id ? String(unit._id) : null,
            unit: unit.unitName || null,
            chapterId: String(ch._id),
            chapter: ch.chapterName,
            questions: ch.count,
        };
    });
    catalogCache = { at: Date.now(), rows };
    return rows;
};

// Spellings that mean the same thing in exam names ("Sep" / "September", "INT" / "International")
const ALIASES = [
    ['january', 'jan'], ['february', 'feb'], ['march', 'mar'], ['april', 'apr'], ['june', 'jun'], ['july', 'jul'],
    ['august', 'aug'], ['september', 'sept', 'sep'], ['october', 'oct'], ['november', 'nov'], ['december', 'dec'],
    ['international', 'int', 'intl'], ['us', 'usa', 'american'], ['module', 'mod'],
];
const STOP_WORDS = new Set([
    'the', 'of', 'in', 'for', 'and', 'exam', 'test', 'questions', 'question', 'chapter', 'sat',
    'امتحان', 'اختبار', 'أسئلة', 'اسئلة', 'سؤال', 'في', 'من', 'على',
]);
const spellings = (token) => ALIASES.find(group => group.includes(token)) || [token];

const browseQuestionBank = {
    name: 'browse_question_bank',
    kind: 'read',
    status: () => 'Browsing the question bank',
    description: 'Walks the question bank one level at a time. With no input: the question types and their subjects (exams, topic banks). With subjectId: its units and chapters with question counts. With chapterId: the questions in that chapter. Use search_question_bank instead when you know a name.',
    input_schema: {
        type: 'object',
        properties: {
            questionTypeId: { type: 'string' },
            subjectId: { type: 'string' },
            chapterId: { type: 'string' },
        },
        additionalProperties: false,
    },
    run: async ({ questionTypeId, subjectId, chapterId }) => {
        if (chapterId) {
            if (!isId(chapterId)) throw new ToolError('chapterId is not valid.');
            const chapter = await chapterModel.findById(chapterId).select('chapterName questions').lean();
            if (!chapter) throw new ToolError('That chapter does not exist.');
            const order = (chapter.questions || []).map(String);
            const questions = order.length
                ? await questionModel.find({ _id: { $in: order } }).select('question typeOfAnswer questionPoints topic questionPic').lean()
                : await questionModel.find({ chapter: chapterId }).select('question typeOfAnswer questionPoints topic questionPic').lean();
            const byId = new Map(questions.map(q => [String(q._id), q]));
            const ordered = order.length ? order.map(id => byId.get(id)).filter(Boolean) : questions;
            return {
                chapter: chapter.chapterName,
                questions: ordered.map((q, i) => ({
                    number: i + 1,
                    questionId: String(q._id),
                    type: q.typeOfAnswer || 'Essay',
                    points: q.questionPoints || 1,
                    topic: q.topic || null,
                    hasImage: !!picUrl(q.questionPic),
                    question: shorten(q.question, 120),
                })),
            };
        }
        const catalog = await loadCatalog();
        if (subjectId) {
            const rows = catalog.filter(r => r.subjectId === subjectId && (!questionTypeId || r.questionTypeId === questionTypeId));
            if (rows.length === 0) throw new ToolError('No chapters found for that subject.');
            const units = new Map();
            rows.forEach(r => {
                const unit = units.get(r.unitId) || { unitId: r.unitId, unit: r.unit, questionTypeId: r.questionTypeId, chapters: [] };
                unit.chapters.push({ chapterId: r.chapterId, chapter: r.chapter, questions: r.questions });
                units.set(r.unitId, unit);
            });
            return { subject: rows[0].subject, units: [...units.values()] };
        }
        const types = new Map();
        catalog.forEach(r => {
            if (questionTypeId && r.questionTypeId !== questionTypeId) return;
            const type = types.get(r.questionTypeId) || { questionTypeId: r.questionTypeId, questionType: r.questionType, subjects: new Map() };
            const subject = type.subjects.get(r.subjectId) || { subjectId: r.subjectId, subject: r.subject, chapters: 0, questions: 0 };
            subject.chapters += 1;
            subject.questions += r.questions;
            type.subjects.set(r.subjectId, subject);
            types.set(r.questionTypeId, type);
        });
        return {
            questionTypes: [...types.values()].map(t => ({ questionTypeId: t.questionTypeId, questionType: t.questionType, subjects: [...t.subjects.values()] })),
        };
    },
};

const searchQuestionBank = {
    name: 'search_question_bank',
    kind: 'read',
    status: () => 'Searching the question bank',
    description: 'Finds question-bank chapters by name, matching against the full path (question type › subject › unit › chapter). Good for "May 2025 international module 2", "circles", "linear equations". Returns chapterIds you can pass to create_assignment, audit_questions or browse_question_bank.',
    input_schema: {
        type: 'object',
        properties: { text: { type: 'string' } },
        required: ['text'],
        additionalProperties: false,
    },
    run: async ({ text }) => {
        const tokens = String(text).toLowerCase().replace(/[^\p{L}\p{N}\s]/gu, ' ').split(/\s+/)
            .filter(t => t && !STOP_WORDS.has(t));
        if (tokens.length === 0) throw new ToolError('Give a name or topic to search for.');
        const catalog = await loadCatalog();
        const scored = catalog.map(r => {
            const path = [r.questionType, r.subject, r.unit, r.chapter].filter(Boolean).join(' › ');
            const words = path.toLowerCase().replace(/[^\p{L}\p{N}\s]/gu, ' ');
            // Short tokens ("us", "1") must match a whole word; longer ones may match inside a word
            const has = (s) => (s.length <= 3 ? new RegExp(`(^|\\s)${s}(\\s|$)`).test(words) : words.includes(s));
            const hits = tokens.filter(t => spellings(t).some(has)).length;
            return { ...r, path, hits };
        }).filter(r => r.hits > 0)
            .sort((a, b) => b.hits - a.hits || a.path.localeCompare(b.path));
        const best = scored.length ? scored[0].hits : 0;
        return {
            searchedFor: tokens,
            matches: scored.filter(r => r.hits === best).slice(0, 20).map(r => ({
                path: r.path, chapterId: r.chapterId, subjectId: r.subjectId, unitId: r.unitId, questionTypeId: r.questionTypeId, questions: r.questions,
            })),
            partialMatches: scored.filter(r => r.hits < best).slice(0, 8).map(r => ({ path: r.path, chapterId: r.chapterId, questions: r.questions })),
        };
    },
};

const getQuestion = {
    name: 'get_question',
    kind: 'read',
    status: () => 'Opening the question',
    description: 'Full details of one question: text, answer choices as students see them, the correct answer, the explanation, and whether it has an image. Use it to explain or solve a question for the teacher.',
    input_schema: {
        type: 'object',
        properties: { questionId: { type: 'string' } },
        required: ['questionId'],
        additionalProperties: false,
    },
    run: async ({ questionId }) => {
        if (!isId(questionId)) throw new ToolError('questionId is not valid.');
        const q = await questionModel.findById(questionId).populate('chapter', 'chapterName').lean();
        if (!q) throw new ToolError('That question does not exist.');
        const type = q.typeOfAnswer || 'Essay';
        return {
            questionId,
            chapter: q.chapter?.chapterName || null,
            topic: q.topic || null,
            type,
            points: q.questionPoints || 1,
            question: cleanHtml(q.question),
            imageUrl: picUrl(q.questionPic),
            choicesShownToStudents: type === 'MCQ' ? Array.from(new Set((q.wrongAnswer || []).filter(isFilled))).slice(0, 4).map(c => cleanHtml(c)) : [],
            correctAnswer: type === 'MCQ' ? cleanHtml(q.correctAnswer) : (type === 'Essay' ? (q.answer || []).filter(isFilled).map(cleanHtml) : picUrl(q.correctPicAnswer)),
            explanation: shorten(q.explanation, 1200) || null,
        };
    },
};

// Problems a student would hit on the homework page. The MCQ checks follow how the page renders
// choices: unique non-empty values of wrongAnswer, first four, graded against correctAnswer.
const findProblems = (q, reports) => {
    const problems = [];
    const text = cleanHtml(q.question);
    const type = q.typeOfAnswer || 'Essay';
    if (!text || text.length < 8) problems.push('Question text is empty or cut off');
    if (/(shown (above|below)|in the (figure|graph|table|diagram|scatterplot|xy-plane)|refer to the (figure|graph|table))/i.test(text) && !picUrl(q.questionPic)) {
        problems.push('Mentions a figure, graph or table but has no image');
    }
    if (type === 'MCQ') {
        const raw = (q.wrongAnswer || []).filter(isFilled);
        const unique = Array.from(new Set(raw));
        const shown = unique.slice(0, 4);
        if (shown.length < 4) problems.push(`Students see only ${shown.length} choices instead of 4`);
        if (raw.length > unique.length) problems.push('Two or more choices are identical');
        const correct = String(q.correctAnswer || '').trim();
        const winners = shown.filter(c => String(c).trim() === correct || cleanHtml(c).toLowerCase() === cleanHtml(correct).toLowerCase());
        if (winners.length === 0) problems.push('None of the choices on screen matches the correct answer — every student will be marked wrong');
        if (winners.length > 1) problems.push('More than one choice is graded as correct');
    } else if (type === 'Essay') {
        const answers = (q.answer || []).filter(isFilled);
        if (answers.length === 0) problems.push('No answer key — every student will be marked wrong');
        if (answers.some(a => /<[a-z][\s\S]*>/i.test(a))) problems.push('The answer key contains HTML, so typed answers will not match it');
    } else if (type === 'Graph') {
        if (!picUrl(q.correctPicAnswer)) problems.push('Graph question has no correct-answer image');
        if (!q.wrongPicAnswer || q.wrongPicAnswer.length === 0) problems.push('Graph question has no wrong-answer images');
    }
    if (((q.question || '').match(/\$/g) || []).length % 2 !== 0) problems.push('Unbalanced $ signs, so the math will not render');
    (reports || []).forEach(r => problems.push(`Student report: ${r.reason}${r.comment ? ` — "${shorten(r.comment, 100)}"` : ''}`));
    return problems;
};

const auditQuestions = {
    name: 'audit_questions',
    kind: 'read',
    status: () => 'Checking the questions for mistakes',
    description: 'Checks questions for problems students would hit: missing images, fewer than 4 choices, duplicate choices, no choice matching the answer key, missing answer keys, broken math, and open student reports. Give a chapterId, an assignmentId, or questionIds.',
    input_schema: {
        type: 'object',
        properties: {
            chapterId: { type: 'string' },
            assignmentId: { type: 'string' },
            questionIds: { type: 'array', items: { type: 'string' }, maxItems: 150 },
        },
        additionalProperties: false,
    },
    run: async ({ chapterId, assignmentId, questionIds }, { scope }) => {
        let ids = [];
        let label = 'the selected questions';
        if (assignmentId) {
            const assignment = await scope.requireAssignment(assignmentId);
            ids = (assignment.questions || []).map(String);
            label = `assignment "${assignment.title}"`;
        } else if (chapterId) {
            if (!isId(chapterId)) throw new ToolError('chapterId is not valid.');
            const chapter = await chapterModel.findById(chapterId).select('chapterName questions').lean();
            if (!chapter) throw new ToolError('That chapter does not exist.');
            ids = (chapter.questions || []).map(String);
            if (ids.length === 0) ids = (await questionModel.find({ chapter: chapterId }).select('_id').lean()).map(q => String(q._id));
            label = `chapter "${chapter.chapterName}"`;
        } else if (Array.isArray(questionIds) && questionIds.length) {
            ids = questionIds.filter(isId);
        } else {
            throw new ToolError('Give a chapterId, an assignmentId or questionIds to check.');
        }
        if (ids.length === 0) throw new ToolError(`There are no questions in ${label}.`);

        const questions = await questionModel.find({ _id: { $in: ids } }).lean();
        const byId = new Map(questions.map(q => [String(q._id), q]));
        const reports = await questionReportModel.find({ question: { $in: ids }, status: { $in: ['pending', 'reviewed'] } }).lean().catch(() => []);
        const reportsById = new Map();
        reports.forEach(r => {
            const key = String(r.question);
            reportsById.set(key, [...(reportsById.get(key) || []), r]);
        });

        const issues = [];
        ids.forEach((id, i) => {
            const q = byId.get(id);
            if (!q) {
                issues.push({ number: i + 1, questionId: id, problems: ['This question was deleted from the bank but is still listed here'] });
                return;
            }
            const problems = findProblems(q, reportsById.get(id));
            if (problems.length) issues.push({ number: i + 1, questionId: id, type: q.typeOfAnswer || 'Essay', question: shorten(q.question, 120), problems });
        });
        return { checked: label, totalQuestions: ids.length, healthy: ids.length - issues.length, withProblems: issues.length, issues };
    },
};

module.exports = { tools: [searchQuestionBank, browseQuestionBank, getQuestion, auditQuestions] };
