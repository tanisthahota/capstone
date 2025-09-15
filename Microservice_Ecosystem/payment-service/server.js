const express = require('express');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

const payments = []; // In-memory store for demo
const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://auth-service:3001';
const NOTIFICATION_SERVICE_URL = process.env.NOTIFICATION_SERVICE_URL || 'http://notification-service:3003';

// Health check
app.get('/health', (req, res) => {
    console.log('[PAYMENT-SERVICE] Health check requested');
    res.json({ status: 'healthy', service: 'payment-service', timestamp: new Date() });
});

// Middleware to verify token
const verifyToken = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        console.log('[PAYMENT-SERVICE] Verifying token with auth service');
        const response = await axios.post(`${AUTH_SERVICE_URL}/verify`, { token });
        req.user = response.data;
        next();
    } catch (error) {
        console.error('[PAYMENT-SERVICE] Token verification failed:', error.message);
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Process payment
app.post('/process', verifyToken, async (req, res) => {
    try {
        const { amount, recipient, description } = req.body;
        const paymentId = uuidv4();
        
        console.log(`[PAYMENT-SERVICE] Processing payment: $${amount} from ${req.user.email} to ${recipient}`);
        
        // Simulate payment processing
        const payment = {
            id: paymentId,
            senderId: req.user.userId,
            senderEmail: req.user.email,
            recipient,
            amount,
            description,
            status: 'completed',
            timestamp: new Date()
        };
        
        payments.push(payment);
        
        // Send notification
        try {
            console.log('[PAYMENT-SERVICE] Sending notification');
            await axios.post(`${NOTIFICATION_SERVICE_URL}/send`, {
                userId: req.user.userId,
                email: req.user.email,
                type: 'payment_sent',
                message: `Payment of $${amount} sent to ${recipient}`,
                paymentId
            });
        } catch (notifError) {
            console.error('[PAYMENT-SERVICE] Notification failed:', notifError.message);
        }
        
        console.log(`[PAYMENT-SERVICE] Payment processed successfully: ${paymentId}`);
        res.json({ 
            success: true, 
            paymentId, 
            message: 'Payment processed successfully',
            payment 
        });
    } catch (error) {
        console.error('[PAYMENT-SERVICE] Payment processing error:', error);
        res.status(500).json({ error: 'Payment processing failed' });
    }
});

// Get payment history
app.get('/history', verifyToken, (req, res) => {
    console.log(`[PAYMENT-SERVICE] Fetching payment history for: ${req.user.email}`);
    const userPayments = payments.filter(p => p.senderId === req.user.userId);
    res.json({ payments: userPayments });
});

// Get payment by ID
app.get('/payment/:id', verifyToken, (req, res) => {
    const payment = payments.find(p => p.id === req.params.id);
    if (!payment) {
        return res.status(404).json({ error: 'Payment not found' });
    }
    
    console.log(`[PAYMENT-SERVICE] Payment details requested: ${req.params.id}`);
    res.json({ payment });
});

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
    console.log(`[PAYMENT-SERVICE] Server running on port ${PORT}`);
});
