const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const { Kafka } = require('kafkajs');

const app = express();
app.use(express.json());

// Initialize Kafka Producer
const kafka = new Kafka({
    clientId: 'auth-service',
    brokers: [process.env.KAFKA_BROKER || 'kafka:9092'],
    retry: {
        initialRetryTime: 100,
        retries: 8,
        maxRetryTime: 30000,
    },
});

const kafkaProducer = kafka.producer();
let kafkaConnected = false;

// Connect to Kafka on startup
kafkaProducer.connect().then(() => {
    kafkaConnected = true;
    console.log('[Kafka] Connected to Kafka broker');
}).catch(err => {
    console.error('[Kafka] Failed to connect:', err.message);
});

// Centralized logger based on CSIC 2010 dataset format
const logEvent = (req,event, details) => {
    const timestamp = new Date().toISOString();
    
    // Safely stringify the body
    const content = req.body ? JSON.stringify(req.body) : '';

    const logObject = {
        timestamp,
        // Map request details to the specified feature names
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
        'lenght': req.headers['content-length'] || '0',
        'content': content, 
        'event': event, // Custom event name
        ...details, // Additional details
    };

    // Convert to key-value format for easy parsing
    const logString = Object.entries(logObject)
        .map(([key, value]) => `${key}="${value}"`)
        .join(' ');
    console.log(logString);

    // Send logs to Kafka topic
    if (kafkaConnected) {
        kafkaProducer.send({
            topic: 'application-logs',
            messages: [{
                key: `auth-${Date.now()}`,
                value: JSON.stringify(logObject)
            }]
        }).catch(err => console.error('[Kafka] Send error:', err.message));
    }
};

// Use a constant secret for development (in production, use environment variables or secure storage)
const JWT_SECRET = 'very-secure-jwt-secret-that-stays-constant-across-restarts-2025';

const users = []; // In-memory store for demo

// Health check
app.get('/health', (req, res) => {
    logEvent(req,'HealthCheck', { service: 'auth-service' });
    res.json({ status: 'healthy', service: 'auth-service', timestamp: new Date() });
});

// Register user
app.post('/register', async (req, res) => {
    const { email } = req.body;
    logEvent(req,'RegistrationAttempt', { email });
    
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = { id: Date.now(), email, password: hashedPassword };
        users.push(user);
        
        logEvent(req,'RegistrationSuccess', { email, userId: user.id });
        res.json({ message: 'User registered successfully', userId: user.id });
    } catch (error) {
        logEvent(req,'RegistrationFailure', { email, error: error.message });
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login user
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    logEvent(req, 'Normal', 'LoginAttempt', { email });

    try {
        const user = users.find(u => u.email === email);
        if (!user || !await bcrypt.compare(password, user.password)) {
            logEvent(req, 'LoginFailure', { email, reason: 'InvalidCredentials' });
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ userId: user.id, email }, JWT_SECRET, { expiresIn: '24h' });
        logEvent(req,'LoginSuccess', { email, userId: user.id });
        res.json({ token, userId: user.id });
    } catch (error) {
        logEvent(req, 'LoginError', { email, error: error.message });
        res.status(500).json({ error: 'Login failed' });
    }
});

// Verify token
app.post('/verify', (req, res) => {
    const tokenFromHeader = req.headers.authorization?.split(' ')[1];
    const tokenFromBody = req.body.token;
    const token = tokenFromHeader || tokenFromBody;
    
    logEvent(req,'TokenVerificationAttempt', { hasToken: !!token });

    if (!token) {
        logEvent(req,'TokenVerificationFailure', { reason: 'NoTokenProvided' });
        return res.status(401).json({ valid: false, error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        logEvent(req,'TokenVerificationSuccess', { userId: decoded.userId, email: decoded.email });
        res.json({ valid: true, userId: decoded.userId, email: decoded.email });
    } catch (jwtError) {
        logEvent(req,'TokenVerificationFailure', { 
            reason: 'InvalidToken', 
            errorName: jwtError.name, 
            errorMessage: jwtError.message 
        });
        res.status(401).json({ valid: false, error: 'Invalid token', details: jwtError.message });
    }
});

const PORT = 3001;
const server = app.listen(PORT, () => {
    // For startup, we don't have a request object, so log a simple message
    console.log(`timestamp="${new Date().toISOString()}" classification="Normal" event="ServerStart" service="AUTH-SERVICE" port="${PORT}"`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully...');
    server.close(async () => {
        try {
            await kafkaProducer.disconnect();
        } catch (err) {
            console.error('Error disconnecting Kafka:', err.message);
        }
        process.exit(0);
    });
});

process.on('SIGINT', async () => {
    console.log('SIGINT received, shutting down gracefully...');
    server.close(async () => {
        try {
            await kafkaProducer.disconnect();
        } catch (err) {
            console.error('Error disconnecting Kafka:', err.message);
        }
        process.exit(0);
    });
});
