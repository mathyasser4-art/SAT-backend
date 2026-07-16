const mongoose = require('mongoose');
const courseModel = require('./DB/models/course.model');

const course = new courseModel({
    name: "Test Course",
    description: "test",
    teacher: new mongoose.Types.ObjectId(),
    students: [],
    sessions: []
});

const error = course.validateSync();
console.log("Validation error:", error);
