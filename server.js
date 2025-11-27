// server.js

// ------------------------------------------------------------------
// <<< CRITICAL FIX: Load environment variables BEFORE ANY OTHER IMPORT
require('dotenv').config(); 
// ------------------------------------------------------------------

const express = require('express');
const cors = require('cors'); 
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 

// --- Database Imports ---
const { connectDB } = require('./config/database'); 

// 👇 MODEL IMPORT FIXES BASED ON YOUR FILE NAMES
const User = require('./models/User.js');  // Kept Capital 'U' (Matches file)
const Goal = require('./models/Goal.js');  // Changed to lowercase 'g'
const Log = require('./models/Log.js');    // Changed to lowercase 'l'

const { protect } = require('./middleware/auth'); 
const goalRoutes = require('./routes/goalRoutes'); 
const logRoutes = require('./routes/logRoutes');
const userRoutes = require('./routes/userRoutes'); 
            
const app = express();
const PORT = 3000; 

// ------------------------------------------------------------------
// --- 1. Middleware Setup ---
// ------------------------------------------------------------------
app.use(cors({
  origin: ['http://localhost:5173', 'https://shiny-croquembouche-2237d6.netlify.app']
}));app.use(express.json());

// ------------------------------------------------------------------
// --- 0. Sequelize Model Associations ---
// ------------------------------------------------------------------
User.hasMany(Goal, { foreignKey: 'userId', onDelete: 'CASCADE' });
Goal.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Log, { foreignKey: 'userId', onDelete: 'CASCADE' });
Log.belongsTo(User, { foreignKey: 'userId' });


// ------------------------------------------------------------------
// --- 2. The Registration API Endpoint ---
// ------------------------------------------------------------------
app.post('/register', async (req, res) => {
    const { email, password, first_name, last_name, role } = req.body;
    
    if (!email || !password || !first_name || !last_name) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    try {
        // Check for existing user by email
        const existingUser = await User.findOne({ where: { email: email } });
        if (existingUser) {
            return res.status(409).json({ success: false, message: 'Email already registered.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Creating user
        const newUser = await User.create({
            email: email,
            password: hashedPassword,
            first_name: first_name,
            last_name: last_name,
            role: role || 'Member'
        });

        // Generate Token immediately upon registration
        const token = jwt.sign(
            { id: newUser.id, role: newUser.role },
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        // Return the token AND the user
        return res.status(201).json({ 
            success: true, 
            message: 'User registered successfully!',
            token: token, 
            user: { 
                id: newUser.id,
                name: `${newUser.first_name} ${newUser.last_name}`,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error('Database error during registration:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Server error during registration process.'
        });
    }
});


// ------------------------------------------------------------------
// --- 3. The Login API Endpoint ---
// ------------------------------------------------------------------
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email and password are required for login.' 
        });
    }

    try {
        const user = await User.findOne({ where: { email: email } });

        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password. Access Denied.' 
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            const token = jwt.sign(
                { id: user.id, role: user.role },
                process.env.JWT_SECRET, 
                { expiresIn: '1h' }
            );

            return res.json({ 
                success: true, 
                message: 'Login successful!',
                token: token, 
                user: { 
                    id: user.id,
                    name: `${user.first_name} ${user.last_name}`,
                    role: user.role 
                } 
            });
        } else {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password. Access Denied.' 
            });
        }

    } catch (error) {
        console.error('Database error during login:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Server error during login process.' 
        });
    }
});

// ------------------------------------------------------------------
// --- 4. Routes Integration ---
// ------------------------------------------------------------------
app.use('/api/goals', goalRoutes); 
app.use('/api/logs', logRoutes); 
app.use('/api/user', userRoutes); 

// ------------------------------------------------------------------
// --- 5. Start the Server ---
// ------------------------------------------------------------------
const startServer = async () => {
    try {
        await connectDB(); 
        app.listen(PORT, () => {
            console.log(`\nServer running securely on http://localhost:${PORT}`);
        });
    } catch (e) {
        console.error('\n!!! Server failed to start due to database error. !!!', e.message);
    }
};

startServer();