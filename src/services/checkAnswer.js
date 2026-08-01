const normalizeAnswer = require('./normalizeAnswer');

const checkAnswer = (questionData, questionAnswer) => {
    if (!questionData) return false;
    const normalizedStudentAnswer = normalizeAnswer(questionAnswer);
    
    if (questionData.typeOfAnswer === 'Essay') {
        const normalizedStudentAnswerLower = normalizedStudentAnswer.toLowerCase();
        
        let correctList = [];
        if (Array.isArray(questionData.answer)) {
            correctList = questionData.answer;
        } else if (typeof questionData.answer === 'string' && questionData.answer.trim() !== '') {
            correctList = [questionData.answer];
        } else if (questionData.correctAnswer) {
            correctList = [questionData.correctAnswer];
        }

        return correctList.some(correctAns => {
            const normalizedCorrectAnswer = normalizeAnswer(correctAns, { toLowerCase: true });
            return normalizedCorrectAnswer === normalizedStudentAnswerLower;
        });
        
    } else if (questionData.typeOfAnswer === 'MCQ') {
        const normalizedCorrectAnswer = normalizeAnswer(questionData.correctAnswer);
        return normalizedCorrectAnswer === normalizedStudentAnswer;
        
    } else {
        const normalizedCorrectAnswer = normalizeAnswer(questionData.correctPicAnswer);
        return normalizedCorrectAnswer === normalizedStudentAnswer;
    }
}

module.exports = checkAnswer