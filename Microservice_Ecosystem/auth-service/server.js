const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');

const app = express();
app.use(express.json());

const JWT_SECRET = 'your-secret-key';
const users = []; // In-memory store for demo

// Health check
app.get('/health', (req, res) => {
    console.log('[AUTH-SERVICE] Health check requested');
    res.json({ status: 'healthy', service: 'auth-service', timestamp: new Date() });
});

// Register user
app.post('/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log(`[AUTH-SERVICE] Registration attempt for: ${email}`);
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = { id: Date.now(), email, password: hashedPassword };
        users.push(user);
        
        console.log(`[AUTH-SERVICE] User registered successfully: ${email}`);
        res.json({ message: 'User registered successfully', userId: user.id });
    } catch (error) {
        console.error('[AUTH-SERVICE] Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login user
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log(`[AUTH-SERVICE] Login attempt for: ${email}`);
        
        const user = users.find(u => u.email === email);
        if (!user || !await bcrypt.compare(password, user.password)) {
            console.log(`[AUTH-SERVICE] Login failed for: ${email}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ userId: user.id, email }, JWT_SECRET, { expiresIn: '24h' });
        console.log(`[AUTH-SERVICE] Login successful for: ${email}`);
        res.json({ token, userId: user.id });
    } catch (error) {
        console.error('[AUTH-SERVICE] Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Verify token
app.post('/verify', (req, res) => {
    try {
        const { token } = req.body;
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log(`[AUTH-SERVICE] Token verified for user: ${decoded.email}`);
        res.json({ valid: true, userId: decoded.userId, email: decoded.email });
    } catch (error) {
        console.log('[AUTH-SERVICE] Token verification failed');
        res.status(401).json({ valid: false, error: 'Invalid token' });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`[AUTH-SERVICE] Server running on port ${PORT}`);
});
