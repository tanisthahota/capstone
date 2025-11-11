#!/bin/bash

echo "🚀 PayPal Clone - Quick Start"
echo "============================="
echo ""

# Check if ecosystem is already running
if curl -s http://localhost:8080/api/health >/dev/null 2>&1; then
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
echo "  📊 Logs:"
echo "     - Application logs: ./monitor-logs.sh --app"
echo "     - System logs: ./monitor-logs.sh --system"
echo "     - Docker events: ./monitor-logs.sh --docker"
echo "     - Help: ./monitor-logs.sh --help"
echo ""
echo "🛑 To stop everything: docker compose down"
