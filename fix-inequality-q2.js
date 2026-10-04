require('dotenv').config();
const mongoose = require('mongoose');
const questionModel = require('./DB/models/question.model');

const TARGET_ID = '6aa2c24dec7ba02921a43504';

// Correct KaTeX HTML representation for Choice A: w - 5 > 20
const CORRECT_CHOICE_A = `<p><span class="ql-formula" data-value="w - 5 &gt; 20">﻿<span contenteditable="false"><span class="katex"><span class="katex-mathml"><math xmlns="http://www.w3.org/1998/Math/MathML"><semantics><mrow><mi>w</mi><mo>−</mo><mn>5</mn><mo>&gt;</mo><mn>20</mn></mrow><annotation encoding="application/x-tex">w - 5 &gt; 20</annotation></semantics></math></span><span class="katex-html" aria-hidden="true"><span class="base"><span class="strut" style="height: 0.6667em; vertical-align: -0.0833em;"></span><span class="mord mathnormal" style="margin-right: 0.0269em;">w</span><span class="mspace" style="margin-right: 0.2222em;"></span><span class="mbin">−</span><span class="mspace" style="margin-right: 0.2222em;"></span></span><span class="base"><span class="strut" style="height: 0.6835em; vertical-align: -0.0391em;"></span><span class="mord">5</span><span class="mspace" style="margin-right: 0.2778em;"></span><span class="mrel">&gt;</span><span class="mspace" style="margin-right: 0.2778em;"></span></span><span class="base"><span class="strut" style="height: 0.6444em;"></span><span class="mord">20</span></span></span></span></span>﻿</span></p>`;

async function fixInequalityQ2() {
    try {
        await mongoose.connect(process.env.ONLINE_CONNECTION_DB, {
            serverSelectionTimeoutMS: 10000,
        });
        console.log('✅ Connected to MongoDB Atlas');

        const q = await questionModel.findById(TARGET_ID);
        if (!q) {
            console.log('❌ Question not found in MongoDB!');
            return;
        }

        console.log('\n📋 Current state in DB:');
        console.log('  Question snippet:', (q.question || '').substring(0, 100));
        console.log('  wrongAnswer[0]:', q.wrongAnswer[0]);

        // Replace choice 0 (Choice A)
        const updatedChoices = [...q.wrongAnswer];
        updatedChoices[0] = CORRECT_CHOICE_A;

        await questionModel.findByIdAndUpdate(TARGET_ID, { wrongAnswer: updatedChoices });
        console.log('\n✅ Successfully updated Question in MongoDB!');

        const verified = await questionModel.findById(TARGET_ID);
        console.log('\n🔍 Verification after update:');
        console.log('  wrongAnswer[0]:', verified.wrongAnswer[0]);

    } catch (err) {
        console.error('❌ Error updating DB:', err.message);
    } finally {
        await mongoose.connection.close();
        console.log('🔌 Connection closed');
    }
}

fixInequalityQ2();
