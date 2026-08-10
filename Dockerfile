# ---------------------------------------------------------------------------
# Tikpilot — минимальный образ на базе python:3.12-slim
# ---------------------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data

WORKDIR /app

# Зависимости ставим отдельным слоем — так пересборка при правке кода быстрее
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/       ./app/
COPY templates/ ./templates/
COPY static/    ./static/

# Каталог для SQLite, ключей и бэкапов (монтируется томом)
RUN mkdir -p /data/backups
VOLUME ["/data"]

EXPOSE 8080

# Проверка живости для docker compose / оркестраторов
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/login', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
