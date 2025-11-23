ARG HASHCAT_BASE=dizcza/docker-hashcat:cuda
FROM ${HASHCAT_BASE}
ARG HASHCAT_VERSION=v7.1.2
ARG HASHCAT_BINARY=/usr/local/bin/hashcat

# Install Python runtime, OpenCL deps and toolchain for building hashcat
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        openssl \
        git \
        build-essential \
        libcurl4-openssl-dev \
        libssl-dev \
        zlib1g-dev \
        ocl-icd-opencl-dev \
        ocl-icd-libopencl1 \
        clinfo \
    && rm -rf /var/lib/apt/lists/*

# Build and install the requested hashcat release
RUN git clone https://github.com/hashcat/hashcat.git /tmp/hashcat && \
    cd /tmp/hashcat && git checkout ${HASHCAT_VERSION} && \
    make install -j"$(nproc)" && \
    rm -rf /tmp/hashcat

WORKDIR /hashcatnode

EXPOSE 9999

# Python requirements
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

# Application sources
COPY . .

# Initialise sqlite DB, TLS certificates and docker-friendly settings
RUN python3 ./create_database.py && \
    openssl req -x509 -newkey rsa:4096 \
      -keyout server.key -out server.crt \
      -days 365 -nodes \
      -subj "/C=IT/ST=Italy/L=Turin/O=WebHashcat/OU=HashcatNode/CN=hashcatnode" && \
    cp settings.ini.sample settings.ini && \
    sed -i 's/hashcatnodeuser/DOCKER_ENV/' settings.ini && \
    sed -i 's/hashcatnodehash/DOCKER_ENV/' settings.ini && \
    sed -i 's/\/path\/to\/hashcatnode\/hashes\/dir/\/hashcatnode\/hashes/' settings.ini && \
    sed -i 's/\/path\/to\/hashcatnode\/rule\/dir/\/hashcatnode\/rules/' settings.ini && \
    sed -i 's/\/path\/to\/hashcatnode\/wordlist\/dir/\/hashcatnode\/wordlists/' settings.ini && \
    sed -i 's/\/path\/to\/hashcatnode\/mask\/dir/\/hashcatnode\/masks/' settings.ini && \
        sed -i "s#/usr/bin/hashcat#${HASHCAT_BINARY}#" settings.ini

CMD ["python3", "./hashcatnode.py"]
