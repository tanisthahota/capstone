FROM python:3.9-slim

WORKDIR /workspace

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire project
COPY . /workspace/

# Install Python dependencies
RUN pip install --no-cache-dir \
    -r requirements.txt \
    chromadb==0.4.0 \
    sentence-transformers \
    torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu \
    transformers \
    peft

# Set working directory to slm
WORKDIR /workspace/slm

# Initialize the vector store (one-time setup)
RUN python -c "from RAG.vector_store import VectorStoreManager; VectorStoreManager().initialize_store()"

CMD ["python", "container_detector.py"]