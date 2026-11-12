FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN mkdir -p /data
# single worker: sessions are kept in memory
CMD ["gunicorn", "-w", "1", "-k", "gthread", "--threads", "32", "-t", "0", "-b", "0.0.0.0:8000", "app:app"]
