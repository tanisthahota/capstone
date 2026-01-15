FROM python:3.9

WORKDIR /workspace

ENV PIP_DEFAULT_TIMEOUT=300 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# In your python-scripts.Dockerfile, add these lines at the top:
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*


# Install OS dependencies (tcpdump + network tools)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      tcpdump \
      iproute2 \
      iputils-ping \
      net-tools \
      dnsutils \
      curl \
      procps && \
    rm -rf /var/lib/apt/lists/*

# Install smaller Python packages first
RUN pip install --no-cache-dir \
    kafka-python \
    requests \
    docker \
    numpy \
    pandas \
    chromadb \
    ansible

# Install torch CPU-only (smaller)
RUN pip install --no-cache-dir \
    --timeout=300 \
    torch torchvision torchaudio \
    --index-url https://download.pytorch.org/whl/cpu

# Install transformers + peft
RUN pip install --no-cache-dir \
    --timeout=300 \
    transformers \
    peft

# Keep container alive
CMD ["tail", "-f", "/dev/null"]
