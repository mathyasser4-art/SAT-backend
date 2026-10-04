require('dotenv').config();
const mongoose = require('mongoose');
const questionModel = require('./DB/models/question.model');

// The question ID from Q17 Hard - Linear Equations in One Variable
const Q17_ID = '6a9eea51df63ca493d47088d';

// The fixed wrong answer option 4 - replacing the duplicate "I and III only" 
// with "II and III only" (which is a plausible but incorrect distractor)
const NEW_WRONG_OPTION_4 = `<p><span class="ql-formula" data-value="\\text{II and III only}">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mtext>II and III only</mtext></mrow><annotation encoding="application/x-tex">\\text{II and III only}</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.8889em; vertical-align: -0.1944em;"></span><span class="mord text"><span class="mord">II&nbsp;and&nbsp;III&nbsp;only</span></span></span></span></span></span>﻿</span></p>`;

async function fixQ17() {
    try {
        await mongoose.connect(process.env.ONLINE_CONNECTION_DB, {
            serverSelectionTimeoutMS: 10000,
        });
        console.log('✅ Connected to database');

        const q = await questionModel.findById(Q17_ID);
        if (!q) {
            console.log('❌ Question not found!');
            return;
        }

        console.log('\n📋 Current state of Q17:');
        const stripHtml = (str) => (str || '').replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').trim();
        console.log('  Correct Answer:', stripHtml(q.correctAnswer));
        console.log('  Wrong Options:');
        q.wrongAnswer.forEach((w, i) => console.log(`    [${i}]: ${stripHtml(w)}`));

        // Check if wrong[3] == correct (the bug)
        const w3Clean = stripHtml(q.wrongAnswer[3] || '');
        const correctClean = stripHtml(q.correctAnswer || '');
        if (w3Clean === correctClean) {
            console.log(`\n⚠️  CONFIRMED BUG: wrongAnswer[3] "${w3Clean}" == correctAnswer "${correctClean}"`);
            console.log('🔧 Fixing by replacing wrongAnswer[3] with "II and III only"...');
            
            const newWrongAnswers = [...q.wrongAnswer];
            newWrongAnswers[3] = NEW_WRONG_OPTION_4;
            
            await questionModel.findByIdAndUpdate(Q17_ID, { wrongAnswer: newWrongAnswers });
            
            console.log('✅ Fixed! Verifying...');
            const updated = await questionModel.findById(Q17_ID);
            console.log('\n📋 Updated wrong answers:');
            updated.wrongAnswer.forEach((w, i) => console.log(`    [${i}]: ${stripHtml(w)}`));
            console.log('  Correct Answer:', stripHtml(updated.correctAnswer));
        } else {
            console.log(`\n✅ No duplicate found. wrongAnswer[3] = "${w3Clean}", correctAnswer = "${correctClean}"`);
        }

    } catch (error) {
        console.error('❌ Error:', error.message);
    } finally {
        await mongoose.connection.close();
        console.log('\n🔌 Connection closed');
    }
}

fixQ17();
