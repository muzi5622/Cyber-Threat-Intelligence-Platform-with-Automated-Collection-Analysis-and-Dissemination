FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests
COPY export.py /app/export.py
CMD ["python", "/app/export.py"]
