const normalizeAnswer = require('./normalizeAnswer');

const checkAnswer = (questionData, questionAnswer) => {
    if (!questionData) return false;
    
    const studentAns = normalizeAnswer(questionAnswer, { toLowerCase: true });
    if (studentAns === '') return false;

    let possibleCorrectAnswers = [];

    if (questionData.typeOfAnswer === 'MCQ') {
        if (questionData.correctAnswer) possibleCorrectAnswers.push(questionData.correctAnswer);
        if (Array.isArray(questionData.answer)) possibleCorrectAnswers.push(...questionData.answer);
        else if (typeof questionData.answer === 'string') possibleCorrectAnswers.push(questionData.answer);
    } else if (questionData.typeOfAnswer === 'Essay') {
        if (Array.isArray(questionData.answer)) possibleCorrectAnswers.push(...questionData.answer);
        else if (typeof questionData.answer === 'string') possibleCorrectAnswers.push(questionData.answer);
        if (questionData.correctAnswer) possibleCorrectAnswers.push(questionData.correctAnswer);
    } else if (questionData.typeOfAnswer === 'Graph') {
        if (questionData.correctPicAnswer) possibleCorrectAnswers.push(questionData.correctPicAnswer);
        if (questionData.correctAnswer) possibleCorrectAnswers.push(questionData.correctAnswer);
    }

    return possibleCorrectAnswers.some(correctAns => {
        const normCorrect = normalizeAnswer(correctAns, { toLowerCase: true });
        return normCorrect === studentAns;
    });
}

module.exports = checkAnswer;