FROM kalilinux/kali-rolling

# Install required tools and Python
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    # Add only the specific Kali tools you actually need
    kali-linux-default \
    kali-tools-information-gathering \
    kali-tools-vulnerability \
    kali-tools-web \
    kali-tools-database\
    kali-tools-passwords\
    kali-tools-exploitation\
    kali-tools-reverse-engineering\
    kali-tools-social-engineering\
    kali-tools-sniffing-spoofing\
    kali-tools-post-exploitation\
    kali-tools-forensics\
    kali-tools-reporting\
    && rm -rf /var/lib/apt/lists/*

# Install Python packages (using pip3 directly, not pipx)
RUN pip3 install --break-system-packages fastapi uvicorn[standard] pydantic

# Copy server file
WORKDIR /app
COPY main.py .
RUN chmod +x main.py

# Expose port
EXPOSE 3001

# Option 1: Run the Python script directly (RECOMMENDED)
CMD ["python3", "main.py"]

# Option 2: Use uvicorn command (alternative)
# CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3001"]

# Option 3: Use uvicorn directly (alternative)
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3001"]