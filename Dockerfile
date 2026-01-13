# API Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install git for cloning repos
RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY src/ src/
COPY patterns/ patterns/

# Install dependencies
RUN pip install --no-cache-dir -e .

# Create data directory
RUN mkdir -p /data

# Expose port
EXPOSE 8000

# Run the API server
CMD ["uvicorn", "github_security_scanner.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

