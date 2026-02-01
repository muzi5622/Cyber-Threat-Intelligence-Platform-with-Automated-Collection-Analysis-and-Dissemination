FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir feedparser requests python-dateutil

COPY app.py /app/app.py
COPY feeds.txt /app/feeds.txt

# state DB folder (mounted)
RUN mkdir -p /state

CMD ["python", "/app/app.py"]
 
