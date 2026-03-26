FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed for Docker SDK and Python packages
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libffi-dev \
    libssl-dev \
    libcairo2-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip first
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY web/ ./web/
COPY ml/ ./ml/

# Create log and report directories
RUN mkdir -p logs reports

# Expose ports
# Honeypot ports: 21 (FTP), 22 (SSH), 23 (Telnet), 80 (HTTP)
# Dashboard port: 5000
EXPOSE 21 22 23 80 5000

# Default command (can be overridden by docker-compose)
CMD ["python", "honeypot.py"]
