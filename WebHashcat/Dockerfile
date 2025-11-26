FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /webhashcat

ARG HASHCAT_VERSION=v7.1.2

# System dependencies required for mysqlclient bindings and hashcat CLI
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        default-libmysqlclient-dev \
        hashcat \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

RUN sed -i 's/\r$//' /webhashcat/entrypoint.sh && \
    chmod +x /webhashcat/entrypoint.sh && \
    chmod 777 /webhashcat/Files/tmp

EXPOSE 8000

ENTRYPOINT ["/webhashcat/entrypoint.sh"]
