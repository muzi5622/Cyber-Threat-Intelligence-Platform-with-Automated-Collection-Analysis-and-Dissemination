FROM python:3.11-slim

WORKDIR /app

# Basic deps (optional but useful)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY models /app/models

ENV PYTHONUNBUFFERED=1
CMD ["python", "/app/app.py"]
