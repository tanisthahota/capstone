const express = require('express');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const { Kafka } = require('kafkajs');

const app = express();
app.use(express.json());

// Initialize Kafka Producer
const kafka = new Kafka({
    clientId: 'payment-service',
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
const logEvent = (req, event, details) => {
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
        'length': req.headers['content-length'] || '0', // fixed typo
        'content': content,
        'event': event, // Custom event name
        ...details, // Additional details
    };

    // Convert to key-value format for easy parsing
    const logString = Object.entries(logObject)
        .map(([key, value]) => `${key}="${value}"`)
        .join(' ');
    console.log(logString);
    
    // Send to Kafka (non-blocking)
    if (kafkaConnected) {
        kafkaProducer.send({
            topic: 'application-logs',
            messages: [{
                key: `payment-${Date.now()}`,
                value: JSON.stringify(logObject)
            }]
        }).catch(err => console.error('[Kafka] Send error:', err.message));
    }
};

// In-memory store for demo
const payments = [];

// Health check
app.get('/health', (req, res) => {
    logEvent(req, 'HealthCheck', { service: 'payment-service' });
    res.json({ status: 'healthy', service: 'payment-service', timestamp: new Date() });
});

// Middleware to verify token
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    logEvent(req, 'AuthenticationAttempt', { hasToken: !!token });

    if (!token) {
        logEvent(req, 'AuthenticationFailure', { reason: 'NoTokenProvided' });
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        // The payment service should not have the secret. It asks the auth service.
        const response = await axios.post('http://auth-service:3001/verify', { token });
        if (response.data.valid) {
            req.user = response.data; // Attach user info to request
            logEvent(req, 'AuthenticationSuccess', { userId: req.user.userId, email: req.user.email });
            next();
        } else {
            logEvent(req, 'AuthenticationFailure', { reason: 'InvalidToken' });
            res.status(401).json({ error: 'Invalid token' });
        }
    } catch (error) {
        logEvent(req, 'AuthenticationError', { 
            reason: 'AuthServiceUnreachable', 
            error: error.message 
        });
        res.status(500).json({ error: 'Failed to verify token with auth service' });
    }
};

// Process payment
app.post('/process', authenticate, async (req, res) => {
    const { amount, recipient } = req.body;
    const { userId, email } = req.user;

    logEvent(req, 'PaymentProcessingAttempt', { userId, email, amount, recipient });

    try {
        const payment = { 
            id: Date.now(), 
            userId, 
            email,
            amount, 
            recipient, 
            description: req.body.description, 
            timestamp: new Date() 
        };
        payments.push(payment);

        // Asynchronously notify the notification service
        axios.post('http://notification-service:3003/send', {
            userId,
            email,
            type: 'PAYMENT_SUCCESS',
            message: `Your payment of $${amount} to ${recipient} was successful.`,
        }).catch(err => {
            // This is an internal error, not directly tied to the user's request,
            // so we log it differently.
            console.log(`timestamp="${new Date().toISOString()}" event="NotificationDispatchFailure" error="${err.message}"`);
        });

        logEvent(req, 'PaymentProcessingSuccess', { paymentId: payment.id, userId, amount });
        res.json({ message: 'Payment processed successfully', paymentId: payment.id });
    } catch (error) {
        logEvent(req, 'PaymentProcessingFailure', { userId, amount, error: error.message });
        res.status(500).json({ error: 'Payment processing failed' });
    }
});

// Get payment history
app.get('/history', authenticate, (req, res) => {
    const { userId } = req.user;
    logEvent(req, 'PaymentHistoryRetrieval', { userId });
    
    const userPayments = payments.filter(p => p.userId === userId);
    res.json(userPayments);
});

// Get payment details
app.get('/payment/:id', authenticate, (req, res) => {
    const { userId } = req.user;
    const paymentId = parseInt(req.params.id, 10);
    
    logEvent(req, 'PaymentDetailsRetrieval', { userId, paymentId });

    const payment = payments.find(p => p.id === paymentId && p.userId === userId);
    if (payment) {
        res.json(payment);
    } else {
        logEvent(req, 'PaymentDetailsNotFound', { userId, paymentId });
        res.status(404).json({ error: 'Payment not found' });
    }
});

const PORT = 3002;
app.listen(PORT, () => {
    // For startup, we don't have a request object, so log a simple message
    console.log(`timestamp="${new Date().toISOString()}" event="ServerStart" service="PAYMENT-SERVICE" port="${PORT}"`);
});
