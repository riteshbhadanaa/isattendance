const mongoose = require('mongoose');

const instructorSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    courses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }] // References to courses taught by the instructor
}, { timestamps: true });

const Instructor = mongoose.model('Instructor', instructorSchema);
module.exports = Instructor;
