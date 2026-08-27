# ------------------------------------------------------------
# Stage 1 – Build / install dependencies
# ------------------------------------------------------------
FROM python:3.11-slim AS builder

# Install system deps needed for some wheels (e.g., cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc libssl-dev libffi-dev python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ------------------------------------------------------------
# Stage 2 – Runtime image (smaller)
# ------------------------------------------------------------
FROM python:3.11-slim

WORKDIR /app

# Copy the virtual‑env from builder (all packages)
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy source code
COPY . .

# Ensure the model exists (you can also mount it as a volume)
# In CI you would run the training scripts before building the image.
# Here we just raise an error if missing.
RUN if [ ! -f models/ensemble.pkl ]; then \
        echo "Model not found – please run scripts/train_ensemble.py before building the image."; \
        exit 1; \
    fi

EXPOSE 5000

# Use a non‑root user for security
RUN useradd -ms /bin/bash appuser && chown -R appuser /app
USER appuser

# Entrypoint – Gunicorn with 4 workers
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app.app:app"]
