const questionModel = require('../../../../DB/models/question.model')
const chapterModel = require('../../../../DB/models/chapter.model')
const cloudinaryConfig = require('../../../services/cloudinary')
const cloudinary = require("cloudinary").v2;
cloudinaryConfig()
const fs = require('fs');

const addQuestion = async (req, res) => {
    try {
        if (req.validationErrorImg) {
            return res.json({ message: "webp او png او jpg او jpeg يجب ان يكون امتداد الصورة" })
        }

        console.log('addQuestion - req.body:', JSON.stringify(req.body));
        console.log('addQuestion - req.file:', req.file ? { fieldname: req.file.fieldname, originalname: req.file.originalname, mimetype: req.file.mimetype, path: req.file.path } : null);

        const { chapter, index } = req.body

        if (!chapter) {
            console.log('addQuestion - chapter field is missing or empty in req.body');
            return res.json({ message: "chapter ID is required but was not received by the server" });
        }

        console.log('addQuestion - looking up chapter ID:', chapter);
        const findChapter = await chapterModel.findById(chapter)
        console.log('addQuestion - findChapter result:', findChapter ? { _id: findChapter._id, name: findChapter.name } : null);

        if (findChapter) {
            console.log('addQuestion - req.file:', req.file);
            if (req.file) {
                const imageURI = req.file.path;
                const { secure_url, public_id } = await cloudinary.uploader.upload(imageURI, { folder: 'questionPic', resource_type: "image" });
                fs.unlinkSync(imageURI);
                req.body.questionPic = secure_url
                req.body.questionPicID = public_id
                console.log('addQuestion - image uploaded to Cloudinary:', secure_url);
            }
            const newQuestion = new questionModel(req.body)
            if (req.body.questionPic) {
                newQuestion.questionPic = req.body.questionPic
                newQuestion.questionPicID = req.body.questionPicID
            }
            const questionData = await newQuestion.save()
            if (questionData) {
                console.log('addQuestion - saved questionData:', JSON.stringify({ _id: questionData._id, questionPic: questionData.questionPic }));
                if (index == 'last') {
                    findChapter.questions.push(questionData._id)
                } else {
                    findChapter.questions.splice(parseInt(index) + 1, 0, questionData._id);
                }
                await findChapter.save()
                res.json({ message: "success", questionData });
            } else {
                res.json({ message: "an error is happened" });
            }
        } else {
            res.json({ message: "this chapter is not available" });
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const addGraphQuestion = async (req, res) => {
    try {
        if (req.validationErrorImg) {
            return res.json({ message: "webp او png او jpg او jpeg يجب ان يكون امتداد الصور" })
        }

        const { questionID } = req.params
        const findQuestion = await questionModel.findById(questionID)

        if (findQuestion) {
            if (req.files.length != 0) {
                const answerPicURL = []
                const answerPicID = []
                let correctAnswer = '';
                for (let i = 0; i < req.files.length; i++) {
                    const imageURI = req.files[i].path;
                    const { secure_url, public_id } = await cloudinary.uploader.upload(imageURI, { folder: 'answerPic', resource_type: "image" });
                    fs.unlinkSync(imageURI);
                    if (i == 0) {
                        correctAnswer = secure_url
                        answerPicID.push(public_id)
                    } else {
                        answerPicURL.push(secure_url)
                        answerPicID.push(public_id)
                    }
                }
                findQuestion.correctPicAnswer = correctAnswer
                findQuestion.wrongPicAnswer = answerPicURL
                findQuestion.wrongAnswerID = answerPicID
                await findQuestion.save()
                res.json({ message: "success" });
            } else {
                res.json({ message: "Upload the answer picture first" });
            }
        } else {
            res.json({ message: "this question is not available" });
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const updateAnswerPic = async (req, res) => {
    try {
        if (req.validationErrorImg) {
            return res.json({ message: "webp او png او jpg او jpeg يجب ان يكون امتداد الصورة" })
        }

        const { questionID } = req.params
        const findQuestion = await questionModel.findById(questionID)

        if (findQuestion) {
            if (req.file) {
                const imageURI = req.file.path;
                const { secure_url, public_id } = await cloudinary.uploader.upload(imageURI, { folder: 'answerPic', resource_type: "image" });
                fs.unlinkSync(imageURI);
                if (findQuestion.answerPic)
                    await cloudinary.uploader.destroy(findQuestion.answerPicID)
                findQuestion.answerPic = secure_url
                findQuestion.answerPicID = public_id
                await findQuestion.save()
                res.json({ message: "success" });
            } else {
                res.json({ message: "Upload the answer picture first" });
            }
        } else {
            res.json({ message: "this question is not available" });
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const updateQuestion = async (req, res) => {
    try {
        if (req.validationErrorImg) {
            return res.json({ message: "webp او png او jpg او jpeg يجب ان يكون امتداد الصورة" })
        }

        const { questionID } = req.params
        const findQuestion = await questionModel.findById(questionID)

        if (findQuestion) {
            if (req.file) {
                const imageURI = req.file.path;
                const { secure_url, public_id } = await cloudinary.uploader.upload(imageURI, { folder: 'questionPic', resource_type: "image" });
                fs.unlinkSync(imageURI);
                if (findQuestion.questionPicID)
                    await cloudinary.uploader.destroy(findQuestion.questionPicID)
                req.body.questionPic = secure_url
                req.body.questionPicID = public_id
                await questionModel.findByIdAndUpdate(questionID, req.body)
                res.json({ message: "success" });
            } else {
                await questionModel.findByIdAndUpdate(questionID, req.body)
                res.json({ message: "success" });
            }
        } else {
            res.json({ message: "this question is not available" });
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const checkTheAnswer = async (req, res) => {
    try {
        const { questionID } = req.params
        const { questionAnswer } = req.body
        const getQuestion = await questionModel.findById(questionID)
        if (getQuestion) {
            if (getQuestion.typeOfAnswer == 'Essay') {
                // Case-insensitive comparison for Essay
                const normalizedStudentAnswer = String(questionAnswer || '').toLowerCase().trim();
                const isCorrect = getQuestion.answer.some(a => String(a).toLowerCase().trim() === normalizedStudentAnswer);
                if (isCorrect) {
                    res.json({ message: "success" });
                } else {
                    res.json({ 
                        message: "this answer is wrong",
                        correctAnswer: getQuestion.answer.filter(Boolean).join(', ')
                    });
                }
            } else if (getQuestion.typeOfAnswer == 'MCQ') {
                if (getQuestion.correctAnswer == questionAnswer) {
                    res.json({ message: "success" });
                } else {
                    res.json({ 
                        message: "this answer is wrong",
                        correctAnswer: getQuestion.correctAnswer
                    });
                }
            } else {
                if (getQuestion.correctPicAnswer == questionAnswer) {
                    res.json({ message: "success" });
                } else {
                    res.json({ 
                        message: "this answer is wrong",
                        correctAnswer: getQuestion.correctPicAnswer
                    });
                }
            }
        } else {
            res.json({ message: "this question is not available" });
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const getQuestionDetails = async (req, res) => {
    try {
        const { questionID } = req.params
        const question = await questionModel.findById(questionID)
        if (question) {
            res.json({ message: "success", question });
        } else {
            res.json({ message: "this question is not available" });
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const deleteQuestion = async (req, res) => {
    try {
        const { questionID, chapterID } = req.params
        const question = await questionModel.findByIdAndDelete(questionID)
        if (question) {
            if (question.questionPicID)
                await cloudinary.uploader.destroy(question.questionPicID)
            if (question.answerPicID)
                await cloudinary.uploader.destroy(question.answerPicID)
            if (question.wrongAnswerID?.length != 0) {
                const picID = question.wrongAnswerID
                for (let index = 0; index < picID.length; index++) {
                    const element = picID[index];
                    await cloudinary.uploader.destroy(element)
                }
            }
            const chapter = await chapterModel.findById(chapterID)
            if (chapter) {
                const questions = chapter.questions.filter(e => e != questionID)
                const newChapter = await chapterModel.findByIdAndUpdate(chapterID, { questions }, { new: true }).populate('questions', 'question questionPic questionPoints answerPic')
                res.json({ message: "success", chapter: newChapter });
            } else {
                res.json({ message: "this chapter is not available" });
            }
        } else {
            res.json({ message: "this question is not available" });
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const updateAutoCorrect = async (req, res) => {
    try {
        const { questionID } = req.params;
        const findQuestion = await questionModel.findById(questionID)

        if (findQuestion) {
            findQuestion.autoCorrect = !findQuestion.autoCorrect;
            await findQuestion.save();
            res.json({ message: 'success', question: findQuestion });
        } else {
            res.json({ message: "this question is not available" });
        }
    } catch (error) {
        res.status(502).json({ message: error.message })
    }
}

const getAllQuestions = async (req, res) => {
    try {
        const questions = await questionModel.find().select('question questionPic questionPoints answerPic wrongAnswer autoCorrect typeOfAnswer wrongPicAnswer correctPicAnswer correctAnswer answer');
        res.json({ message: "success", questions });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
}

module.exports = { addQuestion, updateAnswerPic, updateQuestion, checkTheAnswer, getQuestionDetails, deleteQuestion, addGraphQuestion, updateAutoCorrect, getAllQuestions }