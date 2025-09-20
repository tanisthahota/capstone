# PayPal Clone Ecosystem

A complete microservices ecosystem with 4 layers:
1. **Service Layer**: 3 microservices (Auth, Payment, Notification)
2. **Virtualization Layer**: Docker containers  
3. **Orchestration Layer**: Kubernetes deployment
4. **API Gateway**: Nginx reverse proxy

## Quick Start

### Development (Docker Compose)
```bash
chmod +x deploy.sh
./deploy.sh
```

### Production (Kubernetes)  
```bash
chmod +x deploy-k8s.sh
./deploy-k8s.sh
```

### Test the API
```bash
chmod +x test-api.sh
./test-api.sh
```

## API Endpoints

- **Auth Service**: `/api/auth/`
  - POST `/register` - Register user
  - POST `/login` - Login user  
  - POST `/verify` - Verify token

- **Payment Service**: `/api/payment/`
  - POST `/process` - Process payment
  - GET `/history` - Get payment history
  - GET `/payment/:id` - Get payment details

- **Notification Service**: `/api/notification/`
  - POST `/send` - Send notification
  - GET `/notifications/:userId` - Get user notifications
  - PUT `/read/:id` - Mark as read

## Architecture

```
[Client] → [API Gateway] → [Microservices]
                ↓
    [Auth] ←→ [Payment] ←→ [Notification]
```

## Logs & Monitoring

All services provide detailed logging with service prefixes:
- `[AUTH-SERVICE]` - Authentication events
- `[PAYMENT-SERVICE]` - Payment processing  
- `[NOTIFICATION-SERVICE]` - Notification delivery

Inter-service communication is logged at each step for full traceability.
# LLM_Based_CyberThreatDetection
