# Stage 1: Builder
FROM python:3.12-slim as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Runtime
FROM python:3.12-slim

# Security: run as non-root
RUN groupadd -r shadowgate && useradd -r -g shadowgate shadowgate

WORKDIR /app

# Copy installed packages
COPY --from=builder /install /usr/local

# Copy application
COPY . .

# Create log directory
RUN mkdir -p /app/logs && chown -R shadowgate:shadowgate /app

USER shadowgate

# Expose ports: proxy, http honeypot, ssh honeypot, ftp honeypot, smtp honeypot, dashboard
EXPOSE 8080 8443 2222 2121 2525 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9090/api/health')" || exit 1

ENTRYPOINT ["python", "-m", "shadowgate"]
CMD ["all"]
