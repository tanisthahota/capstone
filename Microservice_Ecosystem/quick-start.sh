#!/bin/bash

echo "🚀 PayPal Clone - Quick Start"
echo "============================="
echo ""

# Check if ecosystem is already running
if curl -s http://localhost:8080/health >/dev/null 2>&1; then
    echo "✅ Ecosystem is already running!"
else
    echo "🔧 Starting ecosystem..."
    ./deploy.sh
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to start ecosystem. Check the logs above."
        exit 1
    fi
fi

echo ""
echo "🎯 Generating sample logs and testing all endpoints..."
./generate-logs.sh

echo ""
echo "🎉 Quick start completed!"
echo ""
echo "📋 What's available:"
echo "  🌐 API Gateway: http://localhost:8080"
echo "  📊 Live logs: ./monitor-logs.sh"
echo "  🔍 Service logs: docker-compose logs [service-name]"
echo ""
echo "🛑 To stop everything: docker-compose down"
