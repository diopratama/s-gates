FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user "setuptools<70"
RUN pip install --no-cache-dir --user -r requirements.txt
RUN pip install --no-cache-dir --user semgrep==1.95.0

# Install GuardDog in an isolated virtualenv to avoid click/packaging conflicts with Semgrep
RUN python3 -m venv /opt/guarddog-venv && \
    /opt/guarddog-venv/bin/pip install --no-cache-dir guarddog==3.2.0

# Final Runtime Image with Real Security Scanners Support (Trivy, Gitleaks, Semgrep, OSV-Scanner, GuardDog)
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    unzip \
    tar \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -u 1000 -m -s /bin/bash appuser \
    && mkdir -p /app/evidence_vault /home/appuser/.cache/trivy \
    && chown -R appuser:appuser /app/evidence_vault /home/appuser/.cache

# Install Aqua Trivy, Gitleaks, and Google OSV-Scanner CLIs (multi-arch support)
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
      x86_64) TRIVY_ARCH="64bit"; GL_ARCH="x64"; OSV_ARCH="amd64" ;; \
      aarch64|arm64) TRIVY_ARCH="ARM64"; GL_ARCH="arm64"; OSV_ARCH="arm64" ;; \
      *) echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-${TRIVY_ARCH}.tar.gz" | tar -xz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy && \
    curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${GL_ARCH}.tar.gz" | tar -xz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    curl -sfL "https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_${OSV_ARCH}" -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

COPY --chown=appuser:appuser --from=builder /opt/guarddog-venv /opt/guarddog-venv
RUN ln -sf /opt/guarddog-venv/bin/guarddog /usr/local/bin/guarddog
COPY --chown=appuser:appuser --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

COPY --chown=appuser:appuser . /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

