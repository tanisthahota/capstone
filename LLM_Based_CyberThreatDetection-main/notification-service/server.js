process.env.TZ = 'Asia/Kolkata'; // Correctly sets your timezone
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { Kafka } = require('kafkajs');

const app = express();
app.use(express.json());

const kafka = new Kafka({
  clientId: 'paypal-app',
  brokers: ['kafka:29092'] 
});
const producer = kafka.producer();

// Centralized logger
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
const notifications = [];

// Health check
app.get('/health', async (req, res) => {
    await logEvent(req, 'HealthCheck', { service: 'notification-service' });
    res.json({ status: 'healthy', service: 'notification-service', timestamp: new Date() });
});

// Send notification (called by payment-service)
app.post('/send', async (req, res) => {
    const { userId, email, type, message } = req.body;
    await logEvent(req, 'NotificationReceived', { userId, email, type });

    try {
        const notification = { 
            id: uuidv4(), // Use uuid for a unique ID
            userId,
            email,
            type,
            message,
            timestamp: new Date().toISOString(),
            read: false
        };
        notifications.push(notification);
        
        await logEvent(req, 'NotificationStored', { notificationId: notification.id, userId });
        res.status(201).json({ message: 'Notification stored', notificationId: notification.id });
    } catch (error) {
        await logEvent(req, 'NotificationStoreFailure', { userId, type, error: error.message });
        res.status(500).json({ error: 'Failed to store notification' });
    }
});

// Get user notifications
app.get('/notifications/:userId', async (req, res) => {
    const userId = req.params.userId; // Keep as string for comparison or parse if IDs are numbers
    await logEvent(req, 'NotificationRetrievalAttempt', { userId });

    const userNotifications = notifications.filter(n => n.userId === userId);
    res.json(userNotifications);
});

// Mark notification as read
app.put('/read/:id', async (req, res) => {
    const notificationId = req.params.id;
    await logEvent(req, 'NotificationMarkReadAttempt', { notificationId });

    const notification = notifications.find(n => n.id === notificationId);
    if (notification) {
        notification.read = true;
        await logEvent(req, 'NotificationMarkReadSuccess', { notificationId });
        res.json({ message: 'Notification marked as read', notification });
    } else {
        await logEvent(req, 'NotificationMarkReadFailure', { notificationId, reason: 'NotFound' });
        res.status(404).json({ error: 'Notification not found' });
    }
});

// --- THIS IS THE ONLY app.listen() YOU NEED ---
// NEW CORRECT CODE
// NEW CORRECT CODE
const PORT = 3003;
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
        console.log(`timestamp="${timestamp}" event="ServerStart" service="NOTIFICATION-SERVICE" port="${PORT}"`);
        
    } catch (error) {
        console.error("Failed to start server or connect to Kafka:", error);
        process.exit(1); // Exit if we can't connect
    }
});