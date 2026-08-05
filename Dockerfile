# Multi-stage build for WADE Engine API
FROM python:3.10-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.10-slim AS runner

WORKDIR /app

# Install system whois utility
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local /root/.local
COPY backend /app/backend

ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/app

EXPOSE 7860

CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "7860"]
