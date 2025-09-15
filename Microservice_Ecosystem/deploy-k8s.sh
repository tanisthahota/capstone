#!/bin/bash

echo "☸️  Deploying to Kubernetes"

# Create namespace
kubectl apply -f k8s/namespace.yaml

# Deploy services
kubectl apply -f k8s/auth-service.yaml
kubectl apply -f k8s/payment-service.yaml
kubectl apply -f k8s/notification-service.yaml
kubectl apply -f k8s/api-gateway.yaml

# Wait for deployments
echo "⏳ Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/auth-service -n paypal-clone
kubectl wait --for=condition=available --timeout=300s deployment/payment-service -n paypal-clone
kubectl wait --for=condition=available --timeout=300s deployment/notification-service -n paypal-clone
kubectl wait --for=condition=available --timeout=300s deployment/api-gateway -n paypal-clone

echo "✅ Kubernetes deployment complete!"
kubectl get pods -n paypal-clone
