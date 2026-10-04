const fs = require('fs');
const path = require('path');

const data = JSON.parse(fs.readFileSync('C:/Users/hp/Desktop/SAT/SAT-backend-master/SAT-backend-master/real_exams_refined_issues.json', 'utf8'));

const categories = {
  CRITICAL_CORRUPTED_ANSWER_KEY: [], // Correct answer is from a completely different problem
  BLANK_CORRECT_ANSWER: [],          // correctAnswer is empty <p><br></p>
  MISCONFIGURED_GRID_IN: [],        // Should be Essay, but marked MCQ with dummy "-" choices
  DUPLICATE_OPTIONS: []             // 2 choices are identical
};

data.genuineIssues.forEach(item => {
  item.issues.forEach(iss => {
    if (iss.type === 'CORRECT_ANSWER_NOT_IN_CHOICES') {
      categories.CRITICAL_CORRUPTED_ANSWER_KEY.push({
        exam: item.examName,
        module: item.moduleName,
        qNum: item.qNum,
        qId: item.qId,
        snippet: item.snippet,
        detail: iss.detail
      });
    } else if (iss.type === 'MISSING_CORRECT_ANSWER') {
      categories.BLANK_CORRECT_ANSWER.push({
        exam: item.examName,
        module: item.moduleName,
        qNum: item.qNum,
        qId: item.qId,
        snippet: item.snippet,
        detail: iss.detail
      });
    } else if (iss.type === 'DUPLICATE_CHOICES') {
      if (iss.detail.includes('("-"') || iss.detail.includes('("‎"') || iss.detail.includes('("ㅤ"')) {
        // Likely dummy options for grid-in
        categories.MISCONFIGURED_GRID_IN.push({
          exam: item.examName,
          module: item.moduleName,
          qNum: item.qNum,
          qId: item.qId,
          snippet: item.snippet,
          detail: iss.detail
        });
      } else {
        categories.DUPLICATE_OPTIONS.push({
          exam: item.examName,
          module: item.moduleName,
          qNum: item.qNum,
          qId: item.qId,
          snippet: item.snippet,
          detail: iss.detail
        });
      }
    }
  });
});

console.log('Categories Summary:');
console.log('1. Critical Corrupted Answer Keys:', categories.CRITICAL_CORRUPTED_ANSWER_KEY.length);
console.log('2. Blank Correct Answers:', categories.BLANK_CORRECT_ANSWER.length);
console.log('3. Misconfigured Grid-In Questions (dummy "-" choices):', categories.MISCONFIGURED_GRID_IN.length);
console.log('4. Duplicate Choices:', categories.DUPLICATE_OPTIONS.length);

fs.writeFileSync('C:/Users/hp/Desktop/SAT/SAT-backend-master/SAT-backend-master/real_exams_classified_issues.json', JSON.stringify(categories, null, 2));
