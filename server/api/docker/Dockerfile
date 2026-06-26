FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy entire sigma_ai repo (for pysigma translation_script access)
COPY . /app/sigma_ai

# Install Python dependencies
COPY server/api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Set working directory to API
WORKDIR /app/sigma_ai/server/api

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

# Run the API
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
