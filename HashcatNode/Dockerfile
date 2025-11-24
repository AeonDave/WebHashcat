ARG HASHCAT_BASE=dizcza/docker-hashcat:intel-cpu
FROM ${HASHCAT_BASE}
ARG HASHCAT_VERSION=v7.1.2
ARG HASHCAT_BINARY=/usr/local/bin/hashcat
ENV HASHCATNODE_BINARY=${HASHCAT_BINARY}
ENV HASHCATNODE_DB_PATH=/hashcatnode/data/hashcatnode.db

# Install Python runtime and TLS tooling (hashcat is provided by the base image)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /hashcatnode

EXPOSE 9999

# Python requirements
COPY requirements.txt ./
RUN PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install --no-cache-dir -r requirements.txt

# Application sources
COPY . .

# Initialise sqlite DB and ensure runtime directories exist
RUN mkdir -p data hashes masks wordlists rules outputs potfiles certs && \
        HASHCATNODE_DB_PATH=${HASHCATNODE_DB_PATH} python3 ./create_database.py

# Verifica che hashcat binary esista
RUN test -f ${HASHCAT_BINARY} && echo "Hashcat binary found at ${HASHCAT_BINARY}" || \
    (echo "Hashcat binary NOT found at ${HASHCAT_BINARY}" && \
     find /usr -name "hashcat" -type f 2>/dev/null || echo "No hashcat found anywhere")

# Runtime bootstrap copies settings/sample and launches node
COPY entrypoint.sh /usr/local/bin/hashcatnode-entrypoint.sh
RUN chmod +x /usr/local/bin/hashcatnode-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/hashcatnode-entrypoint.sh"]
CMD ["python3", "/hashcatnode/hashcatnode.py"]
