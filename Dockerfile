FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY dart_lab ./dart_lab
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home dart && mkdir /data && chown dart:dart /data
USER dart
ENV DART_DB_PATH=/data/dart.db
ENV SOURCE_PUSH_SPOOL=/data/source-push.db
EXPOSE 8000
CMD ["threat-lab"]
