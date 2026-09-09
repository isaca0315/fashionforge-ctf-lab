FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production

RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY config.py .
COPY models.py .
COPY jwt_utils.py .
COPY jwt_custom.py .
COPY templates/ ./templates/
COPY static/ ./static/
COPY oauth_server.py ./
COPY templates_oauth/ ./templates_oauth/
COPY init_db.sh .

RUN mkdir -p uploads instance
RUN chmod +x init_db.sh

EXPOSE 5000
EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/')"

CMD ["sh", "-c", "./init_db.sh && gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 app:app"]