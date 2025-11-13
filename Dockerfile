FROM python:3.9

WORKDIR /app

# Install system dependencies for network capture and build tools
RUN apt-get update && apt-get install -y \
    tcpdump \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    torch==1.13.1 \
    transformers==4.25.1 \
    peft==0.4.0 \
    kafka-python==2.0.2 \
    scapy==2.5.0 \
    cicflowmeter==0.1.6 \
    requests==2.28.2 \
    numpy==1.23.5 \
    pandas==1.5.3

CMD ["bash"]