FROM kalilinux/kali-rolling

# Install required tools and Python
RUN apt-get update && apt-get install -y \
  kali-linux-everything \
  # Add other tools as needed
  && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pipx install mcp fastapi uvicorn

# Copy your server code
COPY mcp_server.py /app/
WORKDIR /app

# Make it executable
RUN chmod +x mcp_server.py

# Set the entry point
ENTRYPOINT ["python3", "mcp_server.py"]
