const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const helmet = require('helmet');
const http = require('http');


dotenv.config();

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB Atlas'))
.catch(err => console.error('MongoDB connection error:', err));

// User schema
const userSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    dob: { type: Date, required: true },
    contactMethod: { type: String, enum: ['email', 'mobile'], required: true },
    emailOrMobile: { type: String, required: true, unique: true },
    gender: { type: String, enum: ['male', 'female', 'other'], required: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' } // Role field
});

const User = mongoose.model('User', userSchema);

// Attendance schema
const attendanceSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    isAttendance: { type: Boolean, default: false },
    timestamp: { type: Date, default: Date.now },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    emailOrMobile: { type: String, required: true, unique: true },

});

const Attendance = mongoose.model('Attendance', attendanceSchema);

// Course schema
const courseSchema = new mongoose.Schema({
    courseName: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    instructor: { type: mongoose.Schema.Types.ObjectId, ref: 'Instructor', required: true },
    students: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }] // References to users enrolled in the course
}, { timestamps: true });

const Course = mongoose.model('Course', courseSchema);

// Instructor schema
const instructorSchema = new mongoose.Schema({
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    courses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }] // References to courses taught by the instructor
}, { timestamps: true });

const Instructor = mongoose.model('Instructor', instructorSchema);

// Middleware to authenticate JWT tokens
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token not provided' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Middleware to check if the user is an admin
const isAdmin = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.userId);
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied, admin only' });
        }
        next();
    } catch (error) {
        console.error('Error checking admin role:', error);
        res.status(500).json({ error: 'Server error' });
    }
};

// User registration
app.post('/api/register', async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            dob,
            contactMethod,
            emailOrMobile,
            gender,
            username,
            password,
            role
        } = req.body;

        // Hash the password before saving it to the database
        const hashedPassword = await bcrypt.hash(password, 10);

        // Validate and assign role (default to 'user' if not provided)
        const assignedRole = role === 'admin' ? 'admin' : 'user';

        // Create a new user with all the fields
        const newUser = new User({
            firstName,
            lastName,
            dob,
            contactMethod,
            emailOrMobile,
            gender,
            username,
            password: hashedPassword,
            role: assignedRole
        });
console.log('role',assignedRole);
        // Save the user to the database
        await newUser.save();
        res.status(201).send({ message: 'User registered' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
    }
});

// User login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ username, userId: user._id,role:user.role }, process.env.JWT_SECRET, { expiresIn: '2d' });
            res.json({ token, userId: user._id });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'Server error' });
    }
});
// Mark attendance
app.post('/api/attendance', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.user;

        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        const todayEnd = new Date();
        todayEnd.setHours(23, 59, 59, 999);

        const existingAttendance = await Attendance.findOne({
            user: userId,
            timestamp: { $gte: todayStart, $lte: todayEnd }
        });
const user = await User.findOne({
    _id:userId
})
console.log('user',user)
        if (existingAttendance) {
            return res.status(400).json({ error: 'Attendance already marked for today' });
        }

        const attendance = new Attendance({
            user: userId,
            firstName: user.firstName,
            lastName: user.lastName,
            emailOrMobile: user.emailOrMobile,
            isAttendance: true,
            timestamp: new Date()
        });
        await attendance.save();

        res.status(201).json({ message: 'Attendance marked successfully' });
    } catch (error) {
        console.error('Error marking attendance:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// View attendance records
app.get('/api/records', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; // Assuming user id is stored in req.user from the authentication middleware
        const userRole = req.user.role; // Assuming user role is stored in req.user from the authentication middleware
        let records;
        if (userRole === 'admin') {
            // Admin can see all records
            records = await Attendance.find({ isAttendance: true })
                .populate('user', 'firstName lastName username emailOrMobile')
                .select('user timestamp');
        } else if (userRole === 'user') {
            // Users can only see their own records
            records = await Attendance.find({ isAttendance: true, user: userId })
                .populate('user', 'firstName lastName username emailOrMobile')
                .select('user timestamp');
        } else {
            return res.status(403).json({ error: 'Access denied' });
        }
console.log('formatted',records)
        const formattedRecords = records.map(record => ({
            firstName: record.user.firstName,
            lastName: record.user.lastName,
            emailOrMobile: record.user.emailOrMobile,
            timestamp: record.timestamp,
            userId: record.user._id
        }));
console.log('jjjj',formattedRecords)
        res.json(formattedRecords);
    } catch (error) {
        console.error('Error retrieving attendance records:', error);
        res.status(500).json({ error: 'Server error' });
    }
});


// Edit user record
app.put('/api/records/:userId', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { firstName, lastName, emailOrMobile } = req.body;

        const updatedRecord = await User.findOneAndUpdate(
            { _id: userId },
            {
                firstName,
                lastName,
                emailOrMobile
            },
            { new: true } // Return the updated document
        );

        if (!updatedRecord) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({ message: 'Record updated successfully', updatedRecord });
    } catch (error) {
        console.error('Error updating record:', error);
        res.status(500).json({ error: 'Server error' });
    }
});


// Delete user record
app.delete('/api/records/:userId', authenticateToken,isAdmin, async (req, res) => {
    try {
        const { userId } = req.params;

        const deletedRecord = await Attendance.findOneAndDelete({ user: userId });

        if (!deletedRecord) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({ message: 'Record deleted successfully' });
    } catch (error) {
        console.error('Error deleting record:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/records/:userId', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;

        // Fetch the user record by userId
        const userRecord = await User.findOne({ _id: userId });

        if (!userRecord) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json(userRecord);
    } catch (error) {
        console.error('Error fetching user record:', error);
        res.status(500).json({ error: 'Server error' });
    }
});
const server = http.createServer(app);
const port = process.env.PORT || 3001;
server.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
