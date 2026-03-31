FROM python:3.12-slim

ARG DEBIAN_FRONTEND=noninteractive

# ---- OS tools (keep lean) ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    jq \
    sed \
    grep \
    gawk \
    coreutils \
    findutils \
    procps \
    unzip \
    zip \
    xz-utils \
    tini \
    netcat-openbsd \
  && rm -rf /var/lib/apt/lists/*

# ---- Optional Python libs for HTML parsing / workflow helpers ----
RUN pip install --no-cache-dir \
    beautifulsoup4==4.12.3

# ---- ffuf (pinned) ----
ARG FFUF_VERSION=2.1.0
RUN curl -fsSL -o /tmp/ffuf.tar.gz \
      "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" \
  && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf \
  && rm -f /tmp/ffuf.tar.gz \
  && chmod +x /usr/local/bin/ffuf

# ---- gobuster (pinned) ----
ARG GOBUSTER_VERSION=3.6.0
RUN curl -fsSL -o /tmp/gobuster.tar.gz \
      "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_Linux_x86_64.tar.gz" \
  && tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster \
  && rm -f /tmp/gobuster.tar.gz \
  && chmod +x /usr/local/bin/gobuster

# ---- wordlists (small, vendored) ----
RUN mkdir -p /opt/wordlists
COPY wordlists /opt/wordlists/

# Safety-ish defaults (runtime hardening is in docker run flags later)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["bash","-lc","python --version && ffuf -h | head -n 2 && gobuster version && ls -la /opt/wordlists | head"]