# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY auth_service.py .

RUN pip install flask

EXPOSE 5000

CMD ["python", "auth_service.py"]


