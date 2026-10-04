const fs = require('fs');

function checkModule(jsonPath, modName) {
    const raw = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    const questions = raw.chapter?.questions || [];
    let dupeCount = 0;
    
    questions.forEach((q, idx) => {
        if (q.typeOfAnswer === 'MCQ') {
            const choices = [q.correctAnswer, ...(q.wrongAnswer || [])];
            const unique = new Set(choices);
            if (unique.size < choices.length) {
                dupeCount++;
                console.log(`[${modName} Q${idx + 1}] ID: ${q._id} has duplicate choices! Total: ${choices.length}, Unique: ${unique.size}`);
            }
        }
    });
    console.log(`${modName}: ${dupeCount} MCQs have duplicates.`);
}

console.log('Checking choices for duplicate answers...');
checkModule('scratch_sep2025_int1_m1.json', 'Module 1');
checkModule('scratch_sep2025_int1_m2.json', 'Module 2');
