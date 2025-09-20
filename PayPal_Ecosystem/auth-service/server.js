const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');

const app = express();
app.use(express.json());

// Use a constant secret for development (in production, use environment variables or secure storage)
const JWT_SECRET = 'very-secure-jwt-secret-that-stays-constant-across-restarts-2025';

// Log the secret being used (only in development!)
console.log('[AUTH-SERVICE] Using JWT_SECRET:', JWT_SECRET);
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
        const tokenFromHeader = req.headers.authorization?.split(' ')[1];
        const tokenFromBody = req.body.token;
        const token = tokenFromHeader || tokenFromBody;

        console.log('[AUTH-SERVICE] Request debug:');
        console.log('- Headers:', JSON.stringify(req.headers, null, 2));
        console.log('- Body:', JSON.stringify(req.body, null, 2));
        console.log('- Token from header:', tokenFromHeader);
        console.log('- Token from body:', tokenFromBody);
        console.log('- Final token:', token);
        
        if (!token) {
            console.log('[AUTH-SERVICE] No token provided');
            return res.status(401).json({ valid: false, error: 'No token provided' });
        }

        // Use the same JWT_SECRET that was used to sign the token
        console.log('[AUTH-SERVICE] About to verify token with secret:', JWT_SECRET);
        
        try {
            const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
            console.log('[AUTH-SERVICE] Successfully decoded token:', decoded);
            console.log(`[AUTH-SERVICE] Token verified for user: ${decoded.email}`);
            res.json({ valid: true, userId: decoded.userId, email: decoded.email });
        } catch (jwtError) {
            console.error('[AUTH-SERVICE] JWT verification error:');
            console.error('- Error name:', jwtError.name);
            console.error('- Error message:', jwtError.message);
            console.error('- JWT used:', token.split('.').slice(0, 2).join('.'));
            throw jwtError;
        }
    } catch (error) {
        console.error('[AUTH-SERVICE] Token verification failed');
        console.error('- Error name:', error.name);
        console.error('- Error message:', error.message);
        res.status(401).json({ valid: false, error: 'Invalid token', details: error.message });
    }
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`[AUTH-SERVICE] Server running on port ${PORT}`);
});
