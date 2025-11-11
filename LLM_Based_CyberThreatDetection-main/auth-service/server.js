process.env.TZ='Asia/Kolkata'; // Correctly sets your timezone
const { Kafka } = require('kafkajs');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');

const app = express();
app.use(express.json());

const kafka = new Kafka({
  clientId: 'paypal-app',
  brokers: ['kafka:29092'] 
});
const producer = kafka.producer();

// Centralized logger based on CSIC 2010 dataset format
const logEvent = async (req, event, details) => {
    
    // --- THIS IS THE FIX ---
    // Create a new Date object
    const now = new Date();
    
    // Format it to the 'Asia/Kolkata' timezone
    // This creates a string like: "2025-11-06T12:50:35.123+05:30"
    const timestamp = new Date(now.getTime() - (now.getTimezoneOffset() * 60000))
                          .toISOString()
                          .slice(0, -1) + "+05:30"; // Manually set IST offset
    // --- END OF FIX ---

    // Safely stringify the body
    const content = req.body ? JSON.stringify(req.body) : '';

    const logObject = {
        timestamp, // <-- This is now your local time
        'Method': req.method,
        'URL': req.originalUrl,
        'User-Agent': req.headers['user-agent'] || '-',
        'Pragma': req.headers['pragma'] || '-',
        'Cache-Control': req.headers['cache-control'] || '-',
        'Accept': req.headers['accept'] || '-',
        'Accept-encoding': req.headers['accept-encoding'] || '-',
        'Accept-charset': req.headers['accept-charset'] || '-',
        'language': req.headers['accept-language'] || '-',
        'host': req.headers['host'] || '-',
        'cookie': req.headers['cookie'] || '-',
        'content-type': req.headers['content-type'] || '-',
        'connection': req.headers['connection'] || '-',
        'length': req.headers['content-length'] || '0', // Fixed typo
        'content': content,
        'event': event, // Custom event name
        ...details, // Additional details
    };

    // Convert to key-value format for easy parsing
    const logString = Object.entries(logObject)
        .map(([key, value]) => `${key}="${value}"`)
        .join(' ');        
    try {
        await producer.send({
            topic: 'app-logs',
            messages: [ { value: logString } ],
        });
    } catch (error) {
        console.error("Failed to send log to Kafka:", error);
    }
    console.log(logString);
};

// Use a constant secret for development (in production, use environment variables or secure storage)
const JWT_SECRET = 'very-secure-jwt-secret-that-stays-constant-across-restarts-2025';

const users = []; // In-memory store for demo

// Health check
app.get('/health', async (req, res) => {
    await logEvent(req,'HealthCheck', { service: 'auth-service' });
    res.json({ status: 'healthy', service: 'auth-service', timestamp: new Date() });
});

// Register user
app.post('/register', async (req, res) => {
    const { email } = req.body;
    await logEvent(req,'RegistrationAttempt', { email });
    
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = { id: Date.now(), email, password: hashedPassword };
        users.push(user);
        
        await logEvent(req,'RegistrationSuccess', { email, userId: user.id });
        res.json({ message: 'User registered successfully', userId: user.id });
    } catch (error) {
        await logEvent(req,'RegistrationFailure', { email, error: error.message });
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login user
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    await logEvent(req, 'LoginAttempt', { email });

    try {
        const user = users.find(u => u.email === email);
        if (!user || !await bcrypt.compare(password, user.password)) {
            await logEvent(req, 'LoginFailure', { email, reason: 'InvalidCredentials' });
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ userId: user.id, email }, JWT_SECRET, { expiresIn: '24h' });
        await logEvent(req,'LoginSuccess', { email, userId: user.id });
        res.json({ token, userId: user.id });
    } catch (error) {
        await logEvent(req, 'LoginError', { email, error: error.message });
        res.status(500).json({ error: 'Login failed' });
    }
});

// Verify token
app.post('/verify', async (req, res) => {
    const tokenFromHeader = req.headers.authorization?.split(' ')[1];
    const tokenFromBody = req.body.token;
    const token = tokenFromHeader || tokenFromBody;
    
    await logEvent(req,'TokenVerificationAttempt', { hasToken: !!token });

    if (!token) {
        await logEvent(req,'TokenVerificationFailure', { reason: 'NoTokenProvided' });
        return res.status(401).json({ valid: false, error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        await logEvent(req,'TokenVerificationSuccess', { userId: decoded.userId, email: decoded.email });
        res.json({ valid: true, userId: decoded.userId, email: decoded.email });
    } catch (jwtError) {
        await logEvent(req,'TokenVerificationFailure', { 
            reason: 'InvalidToken', 
            errorName: jwtError.name, 
            errorMessage: jwtError.message 
        });
        res.status(401).json({ valid: false, error: 'Invalid token', details: jwtError.message });
    }
});

// NEW CORRECT CODE
// NEW CORRECT CODE
const PORT = 3001;
app.listen(PORT, async () => { // <-- 1. Make this function async
    try {
        // --- 2. Add this line to connect to Kafka ---
        await producer.connect(); 
        console.log("Kafka Producer connected successfully.");
        // ------------------------------------------

        // Manually create the local timestamp
        const now = new Date();
        const timestamp = new Date(now.getTime() - (now.getTimezoneOffset() * 60000))
                              .toISOString()
                              .slice(0, -1) + "+05:30";

        // Use the new local timestamp
        console.log(`timestamp="${timestamp}" event="ServerStart" service="AUTH-SERVICE" port="${PORT}"`);
        
    } catch (error) {
        console.error("Failed to start server or connect to Kafka:", error);
        process.exit(1); // Exit if we can't connect
    }
});