const answerModel = require('../../../DB/models/answer.model');
const questionModel = require('../../../DB/models/question.model');
const assignmentModel = require('../../../DB/models/assignment.model');
const { askClaude, isClaudeConfigured } = require('./claude');

// Official SAT Math lessons (skills) used for classification
const LESSONS = [
    'Linear equations in one variable',
    'Linear equations in two variables',
    'Linear functions',
    'Systems of linear equations',
    'Linear inequalities',
    'Equivalent expressions',
    'Nonlinear equations and systems',
    'Quadratic functions',
    'Exponential functions',
    'Polynomials and radicals',
    'Ratios, rates and proportions',
    'Percentages',
    'Units and conversions',
    'One-variable data (mean, median, spread)',
    'Two-variable data and scatterplots',
    'Probability',
    'Statistical inference and studies',
    'Area and volume',
    'Lines, angles and triangles',
    'Right triangles and trigonometry',
    'Circles',
];

// Structured output: the API holds Claude's reply to this shape (lessons are still re-checked below)
const CLASSIFY_SCHEMA = {
    type: 'object',
    properties: {
        results: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    id: { type: 'string' },
                    lesson: { type: 'string', enum: LESSONS },
                },
                required: ['id', 'lesson'],
                additionalProperties: false,
            },
        },
    },
    required: ['results'],
    additionalProperties: false,
};

const cleanText = (t = '') => String(t).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 400);

// Offline keyword classifier (fallback when Claude is unavailable or not set up)
const RULES = [
    ['Probability', /probabilit|at random|chosen randomly/i],
    ['Circles', /circle|radius|diameter|\barc\b|circumference|sector/i],
    ['Right triangles and trigonometry', /\\sin|\\cos|\\tan|\bsin\b|\bcos\b|\btan\b|right triangle|hypotenuse|radian/i],
    ['Area and volume', /\barea\b|volume|cube\b|cylinder|sphere|cone|prism|surface/i],
    ['Lines, angles and triangles', /angle|triangle|parallel|degree|perpendicular|similar|congruent/i],
    ['Percentages', /percent|%/i],
    ['Units and conversions', /convert|inches|feet|meters|kilometers|miles|gallons|liters|ounces|pounds/i],
    ['Ratios, rates and proportions', /ratio|proportion|\brate\b|for every|per hour|per minute/i],
    ['Two-variable data and scatterplots', /scatterplot|line of best fit|scatter/i],
    ['One-variable data (mean, median, spread)', /\bmean\b|median|\bmode\b|average|standard deviation|\brange\b|data set|frequency/i],
    ['Statistical inference and studies', /survey|margin of error|population|randomly selected|study/i],
    ['Exponential functions', /exponential|doubles|half-life|grows by|decays|\^\{?[a-z]/i],
    ['Quadratic functions', /quadratic|parabola|vertex|\^2|\^\{2\}|²/i],
    ['Polynomials and radicals', /polynomial|sqrt|√|radical|\^3|\^\{3\}/i],
    ['Systems of linear equations', /system of|systems of|how many solutions|\(x, ?y\)/i],
    ['Linear inequalities', /inequalit|[<>≤≥]|\\le|\\ge|at least|at most/i],
    ['Linear functions', /f\(x\)|function|slope|intercept|linear model/i],
    ['Linear equations in two variables', /\by\s*=|xy-plane/i],
    ['Equivalent expressions', /equivalent|expression|simplif|factor/i],
];
const localClassify = (q) => {
    const text = `${cleanText(q.question)} ${(q.wrongAnswer || []).join(' ')} ${q.correctAnswer || ''}`;
    for (const [lesson, re] of RULES) if (re.test(text)) return lesson;
    return 'Linear equations in one variable';
};

// Classify questions without a topic, save the result in DB (so each question is classified only once).
// Returns whether Claude is still usable for the rest of this request.
const classifyQuestions = async (questions) => {
    const pending = questions.filter(q => q && !q.topic);
    // After one failed call the remaining batches go local, so a student waits on at most one failed call
    let useClaude = isClaudeConfigured();
    for (let i = 0; i < pending.length; i += 40) {
        const batch = pending.slice(i, i + 40);
        const items = batch.map(q => ({
            id: String(q._id),
            text: cleanText(q.question),
            choices: [q.correctAnswer, ...(q.wrongAnswer || [])].filter(Boolean).map(cleanText).slice(0, 4),
        }));
        const prompt = `Classify each question into exactly ONE lesson from this list:
${LESSONS.map(l => `- ${l}`).join('\n')}
If the text is too short to tell, choose the most likely lesson.
Give one result per question, using the question's id.
Questions:
${JSON.stringify(items)}`;
        if (useClaude) {
            try {
                const parsed = await askClaude({ system: 'You are an SAT Math expert.', prompt, schema: CLASSIFY_SCHEMA });
                const ops = [];
                (Array.isArray(parsed && parsed.results) ? parsed.results : []).forEach(({ id, lesson }) => {
                    if (!LESSONS.includes(lesson)) return;
                    const q = batch.find(b => String(b._id) === String(id));
                    if (q) {
                        q.topic = lesson;
                        ops.push({ updateOne: { filter: { _id: q._id }, update: { $set: { topic: lesson } } } });
                    }
                });
                if (ops.length) await questionModel.bulkWrite(ops);
            } catch (e) {
                useClaude = false;
                console.error('Classification batch failed, using local classifier:', e.message);
            }
        }
        // Anything Claude didn't classify gets the local keyword classifier
        const fallbackOps = [];
        batch.filter(q => !q.topic).forEach(q => {
            q.topic = localClassify(q);
            fallbackOps.push({ updateOne: { filter: { _id: q._id }, update: { $set: { topic: q.topic } } } });
        });
        if (fallbackOps.length) await questionModel.bulkWrite(fallbackOps).catch(err => console.error(err.message));
    }
    return useClaude;
};

const getWrongQuestions = async (studentId) => {
    const answers = await answerModel.find({ solveBy: studentId }).populate({ path: 'questions.question' });
    const map = new Map();
    answers.forEach(ans => {
        (ans.questions || []).forEach(q => {
            if (q.isCorrect === false && q.question && q.question._id) {
                const id = String(q.question._id);
                const entry = map.get(id) || { question: q.question, count: 0 };
                entry.count += 1;
                map.set(id, entry);
            }
        });
    });
    return [...map.values()];
};

const analyzeMistakes = async (req, res) => {
    try {
        // Without ANTHROPIC_API_KEY this still works: local classifier plus the template note below
        const wrong = await getWrongQuestions(req.userData._id);
        if (wrong.length === 0) {
            return res.json({ analysis: "You don't have any recorded mistakes yet! Take a few tests and come back so I can analyze your weak lessons.", topWeaknesses: [] });
        }

        const claudeOk = await classifyQuestions(wrong.map(w => w.question));

        const counts = {};
        wrong.forEach(w => {
            if (w.question.topic) counts[w.question.topic] = (counts[w.question.topic] || 0) + w.count;
        });
        const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
        if (sorted.length === 0) {
            return res.status(500).json({ message: "The AI couldn't classify your mistakes right now. Please try again in a minute." });
        }
        const top = sorted.slice(0, 3);
        const breakdown = sorted.map(([lesson, count]) => ({ lesson, count }));
        const weaknessesText = top.map(([l, c]) => `${l} (${c} mistakes)`).join(', ');

        let analysis = `Your mistakes are concentrated in these lessons: ${weaknessesText}. Start by revising "${top[0][0]}", re-solve the questions you missed there, then move to the next lessons. Take the practice test below to check your progress.`;
        // Skipped when Claude already failed above, so the student doesn't wait on a second failure
        if (claudeOk) {
            try {
                const note = await askClaude({
                    system: 'You are a friendly, professional SAT Math tutor.',
                    prompt: `A student's mistakes by lesson are: ${breakdown.map(b => `${b.lesson}: ${b.count}`).join('; ')}.
Their weakest lessons are: ${weaknessesText}.
Write 3-4 sentences addressed to the student ("You"): name the exact lessons to revise in priority order and give one concrete tip for the weakest lesson. Plain text, no markdown.`,
                    maxTokens: 4000,
                });
                if (note) analysis = note;
            } catch (e) {
                console.error('AI tutor note failed, using the template:', e.message);
            }
        }

        res.json({ analysis, topWeaknesses: top.map(([l]) => l), breakdown });
    } catch (err) {
        console.error("AI Analysis Error:", err);
        res.status(500).json({ message: "Failed to generate AI insights.", error: err.message });
    }
};

const generateTest = async (req, res) => {
    try {
        const { weaknesses } = req.body;
        if (!weaknesses || !weaknesses.length) {
            return res.status(400).json({ message: "Please analyze your mistakes first." });
        }
        const SIZE = 10;
        const studentId = req.userData._id;

        let pool = await questionModel.aggregate([
            { $match: { topic: { $in: weaknesses } } },
            { $sample: { size: SIZE } },
        ]);

        // Not enough tagged questions yet: classify a random sample of the bank, then retry
        if (pool.length < SIZE) {
            const untagged = await questionModel.aggregate([
                { $match: { $or: [{ topic: null }, { topic: { $exists: false } }] } },
                { $sample: { size: 120 } },
            ]);
            await classifyQuestions(untagged);
            pool = await questionModel.aggregate([
                { $match: { topic: { $in: weaknesses } } },
                { $sample: { size: SIZE } },
            ]);
        }

        if (pool.length === 0) {
            return res.status(400).json({ message: "No questions found for these lessons yet. Please try again." });
        }

        const now = new Date();
        const assignment = await assignmentModel.create({
            title: `AI Revision: ${weaknesses.join(', ')}`,
            questions: pool.map(q => q._id),
            createdBy: studentId,
            classes: [],
            students: [{ attempts: 0, solveBy: studentId }],
            createdAt: now.toISOString(),
            timer: Math.max(15, pool.length * 2),
            startDate: now.toISOString(),
            endDate: new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString(),
            attemptsNumber: 100,
            explanationMode: 'independent',
            totalPoints: pool.reduce((s, q) => s + (q.questionPoints || 1), 0),
        });

        res.json({ message: "AI Revision Test Generated", assignmentId: assignment._id, title: assignment.title });
    } catch (err) {
        console.error("AI Test Gen Error:", err);
        res.status(500).json({ message: "Failed to generate test.", error: err.message });
    }
};

module.exports = { analyzeMistakes, generateTest };
