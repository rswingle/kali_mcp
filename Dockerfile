
# Kali MCP Server Docker image - Minimal version
FROM python:3.10-slim
FROM kalilinux/kali-rolling

# Install system dependencies needed for MCP
RUN apt-get update && apt-get dist-upgrade -y \
    #apt-get install -y \
    aptitude\
    build-essential \
    libffi-dev \
    libssl-dev \
    kali-linux-everything \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment and install MCP SDK
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install "mcp[cli]" uvicorn

# Copy server files
WORKDIR /app
COPY server.py .
COPY main.py .

# Make scripts executable
RUN chmod +x server.py main.py

# Use virtual environment Python as default
ENV PATH="/opt/venv/bin:$PATH"

# Default command - run with stdio transport for MCP
CMD ["python3", "-u", "/app/server.py"]
