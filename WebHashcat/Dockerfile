FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /webhashcat

ARG HASHCAT_VERSION=v7.1.2

# System dependencies required to build hashcat and mysqlclient bindings
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        git \
        clinfo \
        libcurl4-openssl-dev \
        libssl-dev \
        zlib1g-dev \
        default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Install hashcat locally (same behavior as legacy Dockerfile)
RUN git clone https://github.com/hashcat/hashcat.git /hashcat && \
    cd /hashcat && git checkout ${HASHCAT_VERSION} && \
    make install -j"$(nproc)"

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

RUN sed -i 's/\r$//' /webhashcat/entrypoint.sh && \
    chmod +x /webhashcat/entrypoint.sh && \
    chmod 777 /webhashcat/Files/tmp

# Prepare configuration from *.docker templates
RUN mv /webhashcat/WebHashcat/settings.py.docker /webhashcat/WebHashcat/settings.py && \
    mv /webhashcat/settings.ini.docker /webhashcat/settings.ini

EXPOSE 8000

ENTRYPOINT ["/webhashcat/entrypoint.sh"]

