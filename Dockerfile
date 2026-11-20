# VulnHGNN 2.0 SecureCC — full stack (Flask API + static web workbench)
# Build:  docker build -t vulnhgnn-securecc:2.0 .
# Run:    docker run --rm -p 5050:5050 --env-file .env vulnhgnn-securecc:2.0

FROM python:3.12-bookworm

LABEL org.opencontainers.image.title="VulnHGNN SecureCC" \
      org.opencontainers.image.description="LLVM-backed security workbench (web UI + analysis API)"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SECURECC_WEB_HOST=0.0.0.0 \
    SECURECC_WEB_PORT=5050

# Compilers for C/C++/Java live lint, IR, and sandbox paths
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    build-essential \
    default-jdk-headless \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY configs ./configs
COPY data ./data
COPY docs ./docs
COPY test_files ./test_files
COPY scripts ./scripts
COPY requirements.txt ./

RUN python -m pip install --upgrade pip setuptools \
    && python -m pip install -e . --no-deps \
    && python -m pip install \
        flask \
        networkx \
        groq \
        python-dotenv

# Optional: copy example env; real secrets should be supplied at runtime
COPY .env.example ./.env.example

RUN mkdir -p /app/build/web_uploads

EXPOSE 5050

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5050/api/meta', timeout=4)" || exit 1

CMD ["sh", "-c", "exec securecc web --host \"${SECURECC_WEB_HOST}\" --port \"${SECURECC_WEB_PORT}\""]