FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests pyyaml
COPY export.py /app/export.py
CMD ["python", "/app/export.py"]
