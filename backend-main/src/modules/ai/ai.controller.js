const answerModel = require('../../DB/models/answer.model');
const questionModel = require('../../DB/models/question.model');
const chapterModel = require('../../DB/models/chapter.model');
const assignmentModel = require('../../DB/models/assignment.model');
const { GoogleGenAI } = require('@google/genai');

const analyzeMistakes = async (req, res) => {
    try {
        if (!process.env.GEMINI_API_KEY) {
            return res.status(400).json({ message: "Gemini API Key is missing on the server. Please add GEMINI_API_KEY to your .env file." });
        }

        const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
        const studentId = req.userData._id;
        
        // Find all answers by student to gather mistakes
        const answers = await answerModel.find({ solveBy: studentId }).populate({
            path: 'questions.question',
            populate: { path: 'chapter' }
        });

        const mistakeCounts = {};
        answers.forEach(ans => {
            ans.questions.forEach(q => {
                if (q.isCorrect === false && q.question && q.question.chapter) {
                    const chapterName = q.question.chapter.chapterName;
                    mistakeCounts[chapterName] = (mistakeCounts[chapterName] || 0) + 1;
                }
            });
        });

        const mistakesArr = Object.keys(mistakeCounts).map(name => ({
            chapter: name,
            count: mistakeCounts[name]
        })).sort((a, b) => b.count - a.count);

        if (mistakesArr.length === 0) {
            return res.json({ analysis: "You don't have any recorded mistakes yet! Keep up the great work. Come back after you take a few tests so I can analyze your weak points." });
        }

        const topWeaknesses = mistakesArr.slice(0, 3);
        const weaknessesText = topWeaknesses.map(w => `${w.chapter} (${w.count} mistakes)`).join(', ');

        const prompt = `You are a friendly, encouraging, and highly professional SAT tutor AI. 
Your student has made mistakes primarily in the following chapters:
${weaknessesText}

Write a short, personalized, 3-sentence paragraph offering encouragement and identifying exactly what they need to focus on. Keep it professional, empathetic, and actionable. Do not use markdown like bolding or bullets, just clean text. Address the student directly ("You").`;

        const response = await ai.models.generateContent({
            model: 'gemini-2.0-flash',
            contents: prompt,
        });

        res.json({ 
            analysis: response.text, 
            topWeaknesses: topWeaknesses.map(w => w.chapter) 
        });

    } catch (err) {
        console.error("AI Analysis Error:", err);
        res.status(500).json({ message: "Failed to generate AI insights.", error: err.message });
    }
};

const generateTest = async (req, res) => {
    try {
        const { weaknesses } = req.body;
        if (!weaknesses || !weaknesses.length) {
            return res.status(400).json({ message: "Please provide weak chapters." });
        }

        // Find chapters by name
        const chapters = await chapterModel.find({ chapterName: { $in: weaknesses } });
        const chapterIds = chapters.map(c => c._id);

        // Fetch up to 10 random questions from these chapters
        const questions = await questionModel.aggregate([
            { $match: { chapter: { $in: chapterIds } } },
            { $sample: { size: 10 } }
        ]);

        if (questions.length === 0) {
            return res.status(400).json({ message: "No questions found for these topics." });
        }

        const questionIds = questions.map(q => q._id);
        const studentId = req.userData._id;

        // Create a custom assignment for the student
        const newAssignment = new assignmentModel({
            title: `AI Revision: ${weaknesses[0] || 'Mixed'}`,
            questions: questionIds,
            createdBy: studentId, // AI generated, assign creator to student
            classes: [], // No class
            students: [{ attempts: 0, solveBy: studentId }],
            createdAt: new Date().toISOString(),
            timer: 30, // 30 minutes
            startDate: new Date().toISOString(),
            endDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 1 week
            attemptsNumber: 100, // virtually unlimited
            explanationMode: 'independent',
            totalPoints: questions.length
        });

        const savedAssignment = await newAssignment.save();

        // Return the assignment ID to the frontend to redirect
        res.json({
            message: "AI Revision Test Generated",
            assignmentId: savedAssignment._id
        });

    } catch (err) {
        console.error("AI Test Gen Error:", err);
        res.status(500).json({ message: "Failed to generate test.", error: err.message });
    }
}

module.exports = { analyzeMistakes, generateTest };
