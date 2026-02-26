FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc g++ \
    libmagic1 file \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
CMD ["python", "-u", "app.py"]
