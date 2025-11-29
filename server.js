// server.js
require('dotenv').config(); 

// 1. 👇 ADDED: Stripe Initialization
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const express = require('express');
const cors = require('cors'); 
const helmet = require('helmet'); 
const rateLimit = require('express-rate-limit'); 
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 

// --- Database Imports ---
const { connectDB, sequelize } = require('./config/database'); 
const User = require('./models/User.js');  
const Goal = require('./models/Goal.js'); 
const Log = require('./models/Log.js');    

// 2. 👇 ADDED: Import 'protect' middleware (Required for the checkout route)
const { protect } = require('./middleware/auth'); 

const goalRoutes = require('./routes/goalRoutes'); 
const logRoutes = require('./routes/logRoutes');
const userRoutes = require('./routes/userRoutes'); 
            
const app = express();
const PORT = process.env.PORT || 3000; 

// ------------------------------------------------------------------
// --- SECURITY MIDDLEWARE (The Bulletproof Layer) ---
// ------------------------------------------------------------------

app.use(helmet());

app.use(cors({
    origin: ['http://localhost:5173', 'https://shiny-croquembouche-2237d6.netlify.app'],
    credentials: true
}));

const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, 
	max: 100, 
    message: { success: false, message: "Too many requests, please try again later." }
});
app.use(limiter);

app.use(express.json());


// ------------------------------------------------------------------
// --- DATABASE ASSOCIATIONS ---
// ------------------------------------------------------------------
User.hasMany(Goal, { foreignKey: 'userId', onDelete: 'CASCADE' });
Goal.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Log, { foreignKey: 'userId', onDelete: 'CASCADE' });
Log.belongsTo(User, { foreignKey: 'userId' });


// ------------------------------------------------------------------
// --- ROUTES ---
// ------------------------------------------------------------------

// Registration
app.post('/register', async (req, res, next) => { 
    try {
        const { email, password, first_name, last_name, role } = req.body;
        
        if (!email || !password || !first_name || !last_name) {
            return res.status(400).json({ success: false, message: 'All fields are required.' });
        }

        const existingUser = await User.findOne({ where: { email: email } });
        if (existingUser) {
            return res.status(409).json({ success: false, message: 'Email already registered.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({
            email,
            password: hashedPassword,
            first_name,
            last_name,
            role: role || 'Member'
        });

        const token = jwt.sign(
            { id: newUser.id, role: newUser.role },
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        return res.status(201).json({ 
            success: true, 
            message: 'User registered successfully!',
            token, 
            user: { 
                id: newUser.id,
                name: `${newUser.first_name} ${newUser.last_name}`,
                role: newUser.role
            }
        });

    } catch (error) {
        next(error); 
    }
});

// Login
app.post('/login', async (req, res, next) => { 
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password required.' });
        }

        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials.' });

        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        return res.json({ 
            success: true, 
            message: 'Login successful!',
            token, 
            user: { 
                id: user.id,
                name: `${user.first_name} ${user.last_name}`,
                role: user.role 
            } 
        });

    } catch (error) {
        next(error); 
    }
});

// ------------------------------------------------------------------
// --- 3. 💰 NEW STRIPE CHECKOUT ROUTE ---
// ------------------------------------------------------------------
app.post('/api/create-checkout-session', protect, async (req, res, next) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'subscription',
            line_items: [
                {
                    // 👇 Your Actual Price ID from the Dashboard
                    price: 'price_1SYpvSFPtgePKWbHVDFIdjxa', 
                    quantity: 1,
                },
            ],
            // Redirect URLs (Frontend)
            success_url: `${process.env.CLIENT_URL}/dashboard?success=true`,
            cancel_url: `${process.env.CLIENT_URL}/dashboard?canceled=true`,
            
            // Auto-fill user email in checkout
            customer_email: req.user.email,
            
            // Track who bought this
            metadata: {
                userId: req.user.id
            }
        });

        res.json({ url: session.url });
    } catch (error) {
        next(error); // Pass to global error handler
    }
});


// Feature Routes
app.use('/api/goals', goalRoutes); 
app.use('/api/logs', logRoutes); 
app.use('/api/user', userRoutes); 

// ------------------------------------------------------------------
// --- GLOBAL ERROR HANDLER (The Safety Net) ---
// ------------------------------------------------------------------
app.use((err, req, res, next) => {
    console.error('🔥 Global Error Catch:', err.stack); 
    res.status(500).json({ 
        success: false, 
        message: 'Something went wrong on the server. Please try again later.' 
    });
});

// ------------------------------------------------------------------
// --- START SERVER ---
// ------------------------------------------------------------------
const startServer = async () => {
    try {
        await connectDB(); 

        if (sequelize) {
            await sequelize.sync({ alter: true });
            console.log('✅ Database tables updated successfully!');
        }

        app.listen(PORT, () => {
            console.log(`\nServer running securely on http://localhost:${PORT}`);
        });
    } catch (e) {
        console.error('\n!!! Server failed to start:', e.message);
    }
};

startServer();