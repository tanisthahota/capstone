#!/bin/bash

# Function to check if a command exists
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ $1 is not installed. Please install it first."
        exit 1
    fi
}

# Function to check if Kubernetes cluster is running
check_kubernetes() {
    if ! kubectl cluster-info &> /dev/null; then
        echo "❌ Kubernetes cluster is not running. Please start your cluster first."
        echo "📝 Common solutions:"
        echo "   1. If using minikube: Run 'minikube start'"
        echo "   2. If using kind: Run 'kind create cluster'"
        echo "   3. If using Docker Desktop: Enable Kubernetes in Docker Desktop settings"
        exit 1
    fi
}

echo "🔍 Checking prerequisites..."

# Check required tools
check_command kubectl
check_command docker

# Check Kubernetes cluster
check_kubernetes

echo "✅ Prerequisites met"
echo "☸️  Deploying to Kubernetes"

# Create namespace with validation disabled for first run
kubectl apply -f k8s/namespace.yaml --validate=false

# Deploy services with validation disabled for first run
echo "📦 Deploying services..."
kubectl apply -f k8s/auth-service.yaml --validate=false
kubectl apply -f k8s/payment-service.yaml --validate=false
kubectl apply -f k8s/notification-service.yaml --validate=false
kubectl apply -f k8s/api-gateway.yaml --validate=false

# Wait for deployments
echo "⏳ Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/auth-service -n paypal-clone
kubectl wait --for=condition=available --timeout=300s deployment/payment-service -n paypal-clone
kubectl wait --for=condition=available --timeout=300s deployment/notification-service -n paypal-clone
kubectl wait --for=condition=available --timeout=300s deployment/api-gateway -n paypal-clone

echo "✅ Kubernetes deployment complete!"
kubectl get pods -n paypal-clone
