process.env.TZ='Asia/Kolkata'; // Correctly sets your timezone
const express = require('express');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const { Kafka } = require('kafkajs');

const kafka = new Kafka({
  clientId: 'paypal-app',
  brokers: ['kafka:29092'] 
});
const producer = kafka.producer();
const app = express();
app.use(express.json());

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
// In-memory store for demo
const payments = [];

// Health check
app.get('/health', async (req, res) => {
    await logEvent(req, 'HealthCheck', { service: 'payment-service' });
    res.json({ status: 'healthy', service: 'payment-service', timestamp: new Date() });
});

// Middleware to verify token
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    await logEvent(req, 'AuthenticationAttempt', { hasToken: !!token });

    if (!token) {
        await logEvent(req, 'AuthenticationFailure', { reason: 'NoTokenProvided' });
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        // The payment service should not have the secret. It asks the auth service.
        const response = await axios.post('http://auth-service:3001/verify', { token });
        if (response.data.valid) {
            req.user = response.data; // Attach user info to request
            await logEvent(req, 'AuthenticationSuccess', { userId: req.user.userId, email: req.user.email });
            next();
        } else {
            await logEvent(req, 'AuthenticationFailure', { reason: 'InvalidToken' });
            res.status(401).json({ error: 'Invalid token' });
        }
    } catch (error) {
        await logEvent(req, 'AuthenticationError', { 
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

    await logEvent(req, 'PaymentProcessingAttempt', { userId, email, amount, recipient });

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

        await logEvent(req, 'PaymentProcessingSuccess', { paymentId: payment.id, userId, amount });
        res.json({ message: 'Payment processed successfully', paymentId: payment.id });
    } catch (error) {
        await logEvent(req, 'PaymentProcessingFailure', { userId, amount, error: error.message });
        res.status(500).json({ error: 'Payment processing failed' });
    }
});

// Get payment history
app.get('/history', authenticate, async (req, res) => {
    const { userId } = req.user;
    await logEvent(req, 'PaymentHistoryRetrieval', { userId });
    
    const userPayments = payments.filter(p => p.userId === userId);
    res.json(userPayments);
});

// Get payment details
app.get('/payment/:id', authenticate, async (req, res) => {
    const { userId } = req.user;
    const paymentId = parseInt(req.params.id, 10);
    
    await logEvent(req, 'PaymentDetailsRetrieval', { userId, paymentId });

    const payment = payments.find(p => p.id === paymentId && p.userId === userId);
    if (payment) {
        res.json(payment);
    } else {
        await logEvent(req, 'PaymentDetailsNotFound', { userId, paymentId });
        res.status(404).json({ error: 'Payment not found' });
    }
});

// NEW CORRECT CODE
// NEW CORRECT CODE
const PORT = process.env.PORT || 3002;
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
        console.log(`timestamp="${timestamp}" event="ServerStart" service="PAYMENT-SERVICE" port="${PORT}"`);
        
    } catch (error) {
        console.error("Failed to start server or connect to Kafka:", error);
        process.exit(1); // Exit if we can't connect
    }
});