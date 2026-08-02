const checkAnswer = (questionData, questionAnswer) => {
    if (!questionData) return false;
    const studentAnsStr = String(questionAnswer !== undefined && questionAnswer !== null ? questionAnswer : '').trim();
    
    if (questionData.typeOfAnswer === 'Essay') {
        const studentLower = studentAnsStr.toLowerCase();
        let correctList = [];
        if (Array.isArray(questionData.answer)) {
            correctList = questionData.answer;
        } else if (typeof questionData.answer === 'string' && questionData.answer.trim() !== '') {
            correctList = [questionData.answer];
        } else if (questionData.correctAnswer) {
            correctList = [questionData.correctAnswer];
        }

        return correctList.some(correctAns => {
            return String(correctAns || '').toLowerCase().trim() === studentLower;
        });
        
    } else if (questionData.typeOfAnswer === 'MCQ') {
        const correctStr = String(questionData.correctAnswer || '').trim();
        return correctStr === studentAnsStr;
        
    } else {
        const correctPicStr = String(questionData.correctPicAnswer || '').trim();
        return correctPicStr === studentAnsStr;
    }
}

module.exports = checkAnswer;