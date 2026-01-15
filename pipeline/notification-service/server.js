const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { Kafka } = require('kafkajs');

const app = express();
app.use(express.json());

// Initialize Kafka Producer
const kafka = new Kafka({
    clientId: 'notification-service',
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
    
    // Send to Kafka (non-blocking)
    if (kafkaConnected) {
        kafkaProducer.send({
            topic: 'application-logs',
            messages: [{
                key: `notification-${Date.now()}`,
                value: JSON.stringify(logObject)
            }]
        }).catch(err => console.error('[Kafka] Send error:', err.message));
    }
};

// In-memory store for demo
const notifications = [];

// Health check
app.get('/health', (req, res) => {
    logEvent(req, 'HealthCheck', { service: 'notification-service' });
    res.json({ status: 'healthy', service: 'notification-service', timestamp: new Date() });
});

// Send notification
app.post('/send', (req, res) => {
    const { userId, email, type } = req.body;
    logEvent(req, 'NotificationReceived', { userId, email, type });

    try {
        const notification = { 
            id: Date.now(),
            userId,
            email,
            type,
            message: `Notification of type ${type}`,
            read: false,
            createdAt: new Date().toISOString()
        };
        notifications.push(notification);
        
        logEvent(req, 'NotificationStored', { notificationId: notification.id, userId });
        res.status(201).json({ message: 'Notification stored', notificationId: notification.id });
    } catch (error) {
        logEvent(req, 'NotificationStoreFailure', { userId, type, error: error.message });
        res.status(500).json({ error: 'Failed to store notification' });
    }
});

// Get user notifications
app.get('/notifications/:userId', (req, res) => {
    const userId = parseInt(req.params.userId, 10);
    logEvent(req, 'NotificationRetrievalAttempt', { userId });

    const userNotifications = notifications.filter(n => n.userId === userId);
    res.json(userNotifications);
});

// Mark notification as read
app.put('/read/:id', (req, res) => {
    const notificationId = parseInt(req.params.id, 10);
    logEvent(req, 'NotificationMarkReadAttempt', { notificationId });

    const notification = notifications.find(n => n.id === notificationId);
    if (notification) {
        notification.read = true;
        logEvent(req, 'NotificationMarkReadSuccess', { notificationId });
        res.json({ message: 'Notification marked as read', notification });
    } else {
        logEvent(req, 'NotificationMarkReadFailure', { notificationId, reason: 'NotFound' });
        res.status(404).json({ error: 'Notification not found' });
    }
});

const PORT = 3003;
const server = app.listen(PORT, () => {
    // For startup, we don't have a request object, so log a simple message
    console.log(`timestamp="${new Date().toISOString()}" classification="Normal" event="ServerStart" service="NOTIFICATION-SERVICE" port="${PORT}"`);
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
