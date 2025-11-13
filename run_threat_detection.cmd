@echo off
REM Threat Detection Pipeline Startup Script

echo.
echo ========================================
echo 3-Layer Threat Detection System
echo ========================================
echo.

REM Check if Docker is running
docker ps >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker is not running!
    pause
    exit /b 1
)

echo [1/7] Starting Container Stream...
start "Container Stream" cmd /k "cd c:\Users\tanis\Documents\PROJECTS\capstone\pipeline && docker exec -it python-scripts python /app/container_stream.py"
timeout /t 2

echo [2/7] Starting Network Stream...
start "Network Stream" cmd /k "cd c:\Users\tanis\Documents\PROJECTS\capstone\pipeline && docker exec -it python-scripts python /app/network_stream.py"
timeout /t 2

echo [3/7] Starting App Traffic Generator...
start "App Traffic" cmd /k "cd c:\Users\tanis\Documents\PROJECTS\capstone\pipeline && docker exec -it python-scripts python /app/app_traffic_gen.py"
timeout /t 2

echo [4/7] Watching Application Logs...
start "App Logs Consumer" cmd /k "docker exec kafka kafka-console-consumer.sh --bootstrap-server kafka:9092 --topic application-logs --from-beginning"
timeout /t 2

echo [5/7] Watching Container Logs...
start "Container Logs Consumer" cmd /k "docker exec kafka kafka-console-consumer.sh --bootstrap-server kafka:9092 --topic container-logs --from-beginning"
timeout /t 2

echo [6/7] Watching Network Logs...
start "Network Logs Consumer" cmd /k "docker exec kafka kafka-console-consumer.sh --bootstrap-server kafka:9092 --topic network-logs --from-beginning"
timeout /t 2

echo [7/7] Starting Threat Detector...
start "Threat Detector" cmd /k "docker run -it --rm --network pipeline_paypal-network -v c:\Users\tanis\Documents\PROJECTS\capstone\slm:/app python:3.9 bash -c \"pip install torch transformers peft kafka-python docker pandas numpy && python /app/final_flow.py\""

echo.
echo ========================================
echo All services started!
echo ========================================
echo.
pause