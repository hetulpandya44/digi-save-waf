FROM python:3.11-slim

WORKDIR /app

# System dependencies for PyCryptodome or Pillow if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/
COPY frontend/ frontend/

WORKDIR /app/backend

# Generate default self-signed certs for dummy HTTPS
RUN mkdir -p certs && \
    openssl req -x509 -newkey rsa:2048 -keyout certs/default.key -out certs/default.crt -days 365 -nodes -subj "/CN=localhost" || true

EXPOSE 8005 8085

CMD ["python", "main.py"]
