FROM dtagdevsec/spiderfoot:24.04

WORKDIR /app

COPY app.py /app/app.py

# Persist scan state + scan outputs
VOLUME ["/data"]

CMD ["python3", "/app/app.py"]



# We only need requests + dateutil (SpiderFoot itself already exists in the base i
