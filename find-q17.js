require('dotenv').config();
const mongoose = require('mongoose');

const questionModel = require('./DB/models/question.model');
const chapterModel = require('./DB/models/chapter.model');
const subjectModel = require('./DB/models/subject.model');
const unitModel = require('./DB/models/unit.model');

async function findLinearEquationsQ17() {
    try {
        await mongoose.connect(process.env.ONLINE_CONNECTION_DB, {
            serverSelectionTimeoutMS: 10000,
        });
        console.log('✅ Connected to database:', mongoose.connection.name);

        // Find all chapters with "linear" in the name (case-insensitive)
        const chapters = await chapterModel.find({
            chapterName: { $regex: /linear/i }
        }).populate('questions').lean();

        console.log(`\n📚 Found ${chapters.length} chapter(s) matching "linear":\n`);

        for (const chapter of chapters) {
            console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
            console.log(`📖 Chapter: ${JSON.stringify(chapter.chapterName)}`);
            console.log(`🆔 Chapter ID: ${chapter._id}`);
            console.log(`📝 Total Questions: ${chapter.questions?.length || 0}`);
            
            // Show question 17 (index 16)
            if (chapter.questions && chapter.questions.length >= 17) {
                const q17 = chapter.questions[16];
                console.log(`\n🔍 Question 17 (index 16):`);
                console.log(`   ID: ${q17._id}`);
                console.log(`   Type: ${q17.typeOfAnswer}`);
                console.log(`   Points: ${q17.questionPoints}`);
                console.log(`   Question text (first 300 chars):`);
                console.log(`   ${(q17.question || '').substring(0, 300)}`);
                if (q17.question && q17.question.length > 300) {
                    console.log(`   ... (truncated, total ${q17.question.length} chars)`);
                }
                console.log(`   Has image: ${!!q17.questionPic}`);
                if (q17.questionPic) console.log(`   Image URL: ${q17.questionPic}`);
                console.log(`   Correct Answer: ${q17.typeOfAnswer === 'MCQ' ? q17.correctAnswer : JSON.stringify(q17.answer)}`);
                if (q17.wrongAnswer && q17.wrongAnswer.length) {
                    console.log(`   Wrong Answers: ${JSON.stringify(q17.wrongAnswer)}`);
                }
                console.log(`   Explanation: ${(q17.explanation || '').substring(0, 200)}`);
            } else {
                console.log(`   ⚠️  Chapter has fewer than 17 questions`);
                
                // Show all questions
                if (chapter.questions) {
                    chapter.questions.forEach((q, i) => {
                        console.log(`\n   Q${i+1}: ${(q.question || '').substring(0, 100)}`);
                    });
                }
            }
        }

        // Also try to find by searching for "hard" in chapter names
        const hardChapters = await chapterModel.find({
            chapterName: { $regex: /hard/i }
        }).populate('questions').lean();

        console.log(`\n\n📚 Found ${hardChapters.length} chapter(s) matching "hard":`);
        for (const ch of hardChapters) {
            console.log(`\n  - ${JSON.stringify(ch.chapterName)} (${ch.questions?.length || 0} questions)`);
        }

    } catch (error) {
        console.error('❌ ERROR:', error.message);
    } finally {
        await mongoose.connection.close();
        console.log('\n🔌 Connection closed');
    }
}

findLinearEquationsQ17();
