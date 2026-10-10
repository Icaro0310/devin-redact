# syntax=docker/dockerfile:1
FROM python:3.12-slim
ARG VERSION
RUN pip install --no-cache-dir "devin-redact==${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/Icaro0310/devin-state" \
      org.opencontainers.image.description="devin-redact CLI: secret scanning and redaction gates for CI"
ENTRYPOINT ["devin-redact"]
CMD ["--help"]
