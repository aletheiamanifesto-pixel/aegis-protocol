FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN useradd --create-home --uid 10001 aegis && chown -R aegis /app
USER aegis

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

# Migrations first; --proxy-headers so the login lockout sees the real client IP behind a proxy
# (set FORWARDED_ALLOW_IPS to the proxy's address).
CMD ["sh", "-c", "alembic upgrade head && uvicorn main_app:app --host 0.0.0.0 --port 8000 --proxy-headers"]
