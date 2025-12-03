FROM python:3.11-slim

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install system dependencies, CLI tools, and Postgres client
RUN apt-get update && apt-get install -y \
    # Core utilities
    bash \
    curl \
    wget \
    git \
    gnupg \
    lsb-release \
    ca-certificates \
    # Build tools
    gcc \
    g++ \
    make \
    cmake \
    # Process & system utilities
    procps \
    htop \
    iputils-ping \
    net-tools \
    dnsutils \
    # Text editors & viewers
    vim \
    nano \
    less \
    # File utilities
    tree \
    fd-find \
    ripgrep \
    patch \
    zip \
    unzip \
    tar \
    gzip \
    # Data processing
    jq \
    csvkit \
    # SSH & networking
    openssh-client \
    rsync \
    # Other useful tools
    tmux \
    screen \
    sqlite3 \
    # Postgres client
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Node.js (LTS)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get update && apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# 3. Install Google Cloud SDK (gcloud)
RUN curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee /etc/apt/sources.list.d/google-cloud-sdk.list && \
    apt-get update && apt-get install -y google-cloud-cli && \
    rm -rf /var/lib/apt/lists/*

# 4. Install GitHub CLI (gh)
RUN mkdir -p -m 755 /etc/apt/keyrings && \
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null && \
    chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null && \
    apt-get update && apt-get install -y gh && \
    rm -rf /var/lib/apt/lists/*

# 5. Download Cloud SQL Proxy (v2)
RUN curl -fsSL \
      https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.19.0/cloud-sql-proxy.linux.amd64 \
      -o /usr/local/bin/cloud-sql-proxy && \
    chmod +x /usr/local/bin/cloud-sql-proxy

# 6. Setup Python app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# Workspace for your other tooling
RUN mkdir -p /app/workspace

# Git defaults (optional)
RUN git config --system init.defaultBranch main && \
    git config --system advice.detachedHead false

# ---------- Runtime configuration ----------

# Cloud SQL / DB envs (examples; you’ll set these at deploy time)
# CLOUDSQL_INSTANCE=squareapp-479519:us-central1:square-app
# DB_HOST=127.0.0.1
# DB_PORT=5432
ENV DB_HOST=127.0.0.1 \
    DB_PORT=5432 \
    PORT=8080

# Single-shot CMD: start proxy (if CLOUDSQL_INSTANCE set), wait a bit, then start server.py
CMD bash -lc '\
  if [[ -n "${CLOUDSQL_INSTANCE}" ]]; then \
    echo "[CMD] Starting Cloud SQL Proxy for ${CLOUDSQL_INSTANCE} on ${DB_PORT}"; \
    cloud-sql-proxy "${CLOUDSQL_INSTANCE}" --address 0.0.0.0 --port "${DB_PORT}" >/var/log/cloud-sql-proxy.log 2>&1 & \
    sleep 5; \
  fi; \
  echo "[CMD] Starting server.py on PORT=${PORT}"; \
  python server.py \
'
