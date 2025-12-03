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

# 5. Download Cloud SQL Proxy (v2) into a standard path
RUN curl -fsSL \
      https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.19.0/cloud-sql-proxy.linux.amd64 \
      -o /usr/local/bin/cloud-sql-proxy && \
    chmod +x /usr/local/bin/cloud-sql-proxy

# 6. Setup Python app
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server
COPY server.py .

# Create workspace directory
RUN mkdir -p /app/workspace

# Configure git defaults (useful for commits)
RUN git config --system init.defaultBranch main && \
    git config --system advice.detachedHead false

# ---------- Runtime configuration ----------

# Cloud SQL / Postgres configuration via env
# Example (you set these at deploy time):
#   CLOUDSQL_INSTANCE=squareapp-479519:us-central1:square-app
#   DB_HOST=127.0.0.1
#   DB_PORT=5432
#   DB_USER=app_user
#   DB_PASSWORD=new_secure_password
#   DB_NAME=app_db
#
# Then your apps can use DATABASE_URL built from those.
ENV DB_HOST=127.0.0.1 \
    DB_PORT=5432

# Default port for your Python server (Cloud Run convention)
ENV PORT=8040

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Use the entrypoint to start Cloud SQL Proxy (if configured) and then server.py
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["python", "server.py"]
