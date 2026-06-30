FROM python:3.11-slim

WORKDIR /app

# Install dependencies for SQLite if necessary
RUN apt-get update && apt-get install -y sqlite3 tzdata && rm -rf /var/lib/apt/lists/*

# Set timezone
ENV TZ="Asia/Dhaka"

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Ensure data directory exists
RUN mkdir -p /app/data

# Expose port (Railway sets $PORT dynamically)
EXPOSE ${PORT:-5000}

# Start Gunicorn server (shell form so $PORT env var is expanded)
CMD gunicorn -c gunicorn_config.py run:app
