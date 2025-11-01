# Phishing Automation Tool - Docker Image
# Based on Python 3.12

FROM python:3.12.4-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs landing_pages config backups

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=src/api/app_secure.py
ENV PYTHONPATH=/app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Create volume mount points
VOLUME ["/app/logs", "/app/config", "/app/landing_pages"]

# Run the application
CMD ["python", "start_web_secure.py"]
