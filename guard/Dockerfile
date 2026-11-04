# The embargo guard: Switch calls this before every message it sends.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

EXPOSE 19000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "19000"]
