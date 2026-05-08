# Kali MCP Server Docker image
FROM kalilinux/kali-rolling

ARG KALI_REPO_URL="http://http.kali.org/kali"
ARG KALI_SUITE="kali-rolling"
ARG CUSTOM_CA_PEM=""

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

# Set Kali repository source. Defaults to Kali's documented HTTP mirrorlist endpoint.
# Override at build time if needed:
#   --build-arg KALI_REPO_URL=https://http.kali.org/kali
RUN printf '%s\n' \
    "deb ${KALI_REPO_URL} ${KALI_SUITE} main contrib non-free non-free-firmware" \
    > /etc/apt/sources.list

# Optionally inject a custom corporate/proxy CA before apt-get update.
# Example:
#   docker build \
#     --build-arg CUSTOM_CA_PEM="$(cat company-root-ca.crt)" \
#     -t kali-mcp-server:latest .
RUN if [ -n "$CUSTOM_CA_PEM" ]; then \
      mkdir -p /usr/local/share/ca-certificates && \
      printf '%s\n' "$CUSTOM_CA_PEM" > /usr/local/share/ca-certificates/custom-proxy-ca.crt && \
      update-ca-certificates; \
    fi

# Install Python runtime and build dependencies needed for MCP.
RUN apt-get update -o Acquire::Retries=3 && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-pip \
    build-essential \
    libffi-dev \
    libssl-dev \
    ca-certificates \
    kali-linux-everything && \
    rm -rf /var/lib/apt/lists/*
# Create virtual environment and install MCP SDK.
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install "mcp[cli]" uvicorn

# Copy server files.
WORKDIR /app
COPY server.py .
COPY main.py .

# Make scripts executable.
RUN chmod +x server.py main.py

# Default command - run with stdio transport for MCP.
CMD ["python3", "-u", "/app/server.py"]
