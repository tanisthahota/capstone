const express = require('express');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

const notifications = []; // In-memory store for demo

// Health check
app.get('/health', (req, res) => {
    console.log('[NOTIFICATION-SERVICE] Health check requested');
    res.json({ status: 'healthy', service: 'notification-service', timestamp: new Date() });
});

// Send notification
app.post('/send', (req, res) => {
    try {
        const { userId, email, type, message, paymentId } = req.body;
        const notificationId = uuidv4();
        
        console.log(`[NOTIFICATION-SERVICE] Sending ${type} notification to: ${email}`);
        console.log(`[NOTIFICATION-SERVICE] Message: ${message}`);
        
        const notification = {
            id: notificationId,
            userId,
            email,
            type,
            message,
            paymentId,
            timestamp: new Date(),
            status: 'sent'
        };
        
        notifications.push(notification);
        
        // Simulate email/SMS sending
        console.log(`[NOTIFICATION-SERVICE] ✉️  EMAIL SENT to ${email}: ${message}`);
        
        res.json({ 
            success: true, 
            notificationId, 
            message: 'Notification sent successfully' 
        });
    } catch (error) {
        console.error('[NOTIFICATION-SERVICE] Error sending notification:', error);
        res.status(500).json({ error: 'Failed to send notification' });
    }
});

// Get user notifications
app.get('/notifications/:userId', (req, res) => {
    const userId = req.params.userId;
    console.log(`[NOTIFICATION-SERVICE] Fetching notifications for user: ${userId}`);
    
    const userNotifications = notifications.filter(n => n.userId === userId);
    res.json({ notifications: userNotifications });
});

// Mark notification as read
app.put('/read/:id', (req, res) => {
    const notification = notifications.find(n => n.id === req.params.id);
    if (!notification) {
        return res.status(404).json({ error: 'Notification not found' });
    }
    
    notification.status = 'read';
    console.log(`[NOTIFICATION-SERVICE] Notification marked as read: ${req.params.id}`);
    res.json({ message: 'Notification marked as read' });
});

const PORT = process.env.PORT || 3003;
app.listen(PORT, () => {
    console.log(`[NOTIFICATION-SERVICE] Server running on port ${PORT}`);
});
