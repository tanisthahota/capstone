#!/bin/bash

echo "🚀 Deploying PayPal Clone Ecosystem"

# Build Docker images
echo "📦 Building Docker images..."
docker build -t auth-service:latest ./auth-service
docker build -t payment-service:latest ./payment-service  
docker build -t notification-service:latest ./notification-service

# Deploy with Docker Compose (for development)
echo "🐳 Starting services with Docker Compose..."
docker-compose up -d

echo "✅ Services deployed successfully!"
echo "🌐 API Gateway available at: http://localhost:8080"
echo "🔐 Auth Service: http://localhost:3001"
echo "💳 Payment Service: http://localhost:3002" 
echo "📧 Notification Service: http://localhost:3003"
