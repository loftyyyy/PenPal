FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# nmap, dig, whois, curl and WhatWeb for reconnaissance; Pango/HarfBuzz/Cairo
# for WeasyPrint PDF output.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        dnsutils \
        whois \
        curl \
        ruby \
        ruby-rubygems \
        ca-certificates \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libharfbuzz-subset0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libglib2.0-0 \
        fontconfig \
        libffi8 \
        shared-mime-info \
        fonts-dejavu-core \
    && gem install addressable -v 2.9.2 --no-document \
    && curl -fsSL https://github.com/urbanadventurer/WhatWeb/archive/refs/tags/v0.6.4.tar.gz \
        -o /tmp/whatweb.tar.gz \
    && mkdir -p /opt/whatweb \
    && tar -xzf /tmp/whatweb.tar.gz -C /opt/whatweb --strip-components=1 \
    && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb \
    && rm -rf /tmp/whatweb.tar.gz /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
COPY app ./app
RUN pip install .

COPY alembic.ini ./
COPY alembic ./alembic
COPY scripts ./scripts

RUN mkdir -p /app/data/evidence /app/data/reports /app/data/uploads \
    && useradd --create-home --uid 10001 penpal \
    && chown -R penpal:penpal /app/data
USER penpal

EXPOSE 8000

# Migrations run before serving; seed.py only bootstraps the first admin.
CMD ["sh", "-c", "alembic upgrade head && python scripts/seed.py --admin-only && uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers"]
