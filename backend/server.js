const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const helmet = require('helmet');
const http = require('http');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');

dotenv.config();

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  resave: false,
  saveUninitialized: true,
  secret: 'SECRET'
}));
app.use(passport.initialize());
app.use(passport.session());

// Database Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB Atlas'))
.catch(err => console.error('MongoDB connection error:', err));

// Define OAuth2 Client
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// User Schema
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

// Attendance Schema
const attendanceSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    isAttendance: { type: Boolean, default: false },
    timestamp: { type: Date, default: Date.now },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    emailOrMobile: { type: String, required: true, unique: true },
});
const Attendance = mongoose.model('Attendance', attendanceSchema);

// Course Schema
const courseSchema = new mongoose.Schema({
    courseName: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    instructor: { type: mongoose.Schema.Types.ObjectId, ref: 'Instructor', required: true },
    students: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }] // References to users enrolled in the course
}, { timestamps: true });
const Course = mongoose.model('Course', courseSchema);

// Instructor Schema
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

// Configure Passport for Google OAuth
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
  }
));

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((obj, cb) => {
  cb(null, obj);
});
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "script-src 'self' 'unsafe-inline'");
    next();
  });
  
// Google OAuth Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'login.html'));
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/error' }),
  (req, res) => {
    res.redirect('/success');
  });

app.get('/success', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'attendance.html'));
});

app.get('/error', (req, res) => {
  res.send("Error logging in");
});

// Google Sign-In Endpoint
// Google Sign-In Endpoint
app.post('/api/google-login', async (req, res) => {
    try {
        const { token } = req.body;
        
        // Verify the Google ID token
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
console.log('payload',payload)
        const userId = payload.sub; // User ID from Google

        // Find or create a user in your database
        let user = await User.findOne({ emailOrMobile: payload.email });

        if (!user) {
            // Create a new user if it doesn't exist
            user = new User({
                firstName: payload.given_name,
                lastName: payload.family_name,
                dob: null, // Set default or optional value if not available
                contactMethod: 'email', // Assume email as default for OAuth
                emailOrMobile: payload.email,
                gender: 'other', // Default or handle as per your requirement
                username: payload.email, // Use email as username or create a unique username
                password: '', // Google login doesn't use a password
                role: 'user', // Default role
            });

            await user.save();
        }

        // Generate a JWT for the user
        const jwtToken = jwt.sign(
            { username: user.username, userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '2d' }
        );

        res.json({ token: jwtToken, userId: user._id });
    } catch (error) {
        console.error('Error during Google login:', error);
        res.status(400).json({ error: 'Invalid Google token' });
    }
});


// User Registration
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

        // Save the user to the database
        await newUser.save();
        res.status(201).send({ message: 'User registered' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ username, userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '2d' });
            res.json({ token, userId: user._id });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Mark Attendance
app.post('/api/attendance', authenticateToken, async (req, res) => {
    try {
        const { isAttendance, firstName, lastName, emailOrMobile } = req.body;

        // Create a new attendance record
        const attendance = new Attendance({
            user: req.user.userId,
            isAttendance,
            firstName,
            lastName,
            emailOrMobile
        });

        await attendance.save();
        res.status(201).json({ message: 'Attendance marked' });
    } catch (error) {
        console.error('Error marking attendance:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create Course
app.post('/api/courses', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { courseName, description, instructor } = req.body;
        const newCourse = new Course({ courseName, description, instructor });
        await newCourse.save();
        res.status(201).json({ message: 'Course created' });
    } catch (error) {
        console.error('Error creating course:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Enroll in Course
app.post('/api/enroll', authenticateToken, async (req, res) => {
    try {
        const { courseId } = req.body;
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        const course = await Course.findById(courseId);
        if (!course) return res.status(404).json({ error: 'Course not found' });

        course.students.push(user._id);
        await course.save();
        res.status(200).json({ message: 'Enrolled in course' });
    } catch (error) {
        console.error('Error enrolling in course:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Courses by Instructor
app.get('/api/courses/:instructorId', async (req, res) => {
    try {
        const { instructorId } = req.params;
        const courses = await Course.find({ instructor: instructorId });
        res.json(courses);
    } catch (error) {
        console.error('Error fetching courses:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Start Server
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
