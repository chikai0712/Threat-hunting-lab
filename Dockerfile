FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY dart_lab ./dart_lab
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home dart && mkdir /data && chown dart:dart /data
USER dart
ENV DART_DB_PATH=/data/dart.db
EXPOSE 8000
CMD ["uvicorn", "dart_lab.api:app", "--host", "0.0.0.0", "--port", "8000"]
