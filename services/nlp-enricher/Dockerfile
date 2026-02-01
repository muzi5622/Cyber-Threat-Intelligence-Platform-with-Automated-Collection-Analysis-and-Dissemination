FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn requests spacy scikit-learn pydantic
RUN python -m spacy download en_core_web_sm

COPY app.py /app/app.py
CMD ["python", "/app/app.py"]
