# Dockerfile for python-scripts service
FROM python:3.9-slim

WORKDIR /app

# Install Docker CLI and necessary tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        gnupg \
        iproute2 \
        tcpdump \
        ansible \
        sshpass \
        lsb-release && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/debian \
        $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    kafka-python \
    requests \
    docker \
    cicflowmeter \
    pandas \
    scapy \
    chromadb

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN apt-get update && apt-get install -y python3-requests

# Copy app code (venv excluded via .dockerignore)
COPY . /app

ENV ANSIBLE_PYTHON_INTERPRETER=/usr/bin/python3

CMD ["bash", "-c", "tail -f /dev/null"]

