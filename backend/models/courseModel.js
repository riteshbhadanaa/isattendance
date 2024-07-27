const mongoose = require('mongoose');

const courseSchema = new mongoose.Schema({
    courseName: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    instructor: { type: mongoose.Schema.Types.ObjectId, ref: 'Instructor', required: true },
    students: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }] // References to users enrolled in the course
}, { timestamps: true });

const Course = mongoose.model('Course', courseSchema);
module.exports = Course;
