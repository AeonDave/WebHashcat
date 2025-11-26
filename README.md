# WebHashcat (Modernized)

Hashcat orchestration with a Django web UI, Celery workers, and Docker-first workflows.

> This fork tracks the original project from https://github.com/hegusung/WebHashcat and keeps it current with Python 3.11, compose profiles, and hashcat 7.1.x images.

## Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick start (Docker)](#quick-start-docker)
- [Managing nodes and assets](#managing-nodes-and-assets)
- [Manual installation](#manual-installation)
- [Operating-system improvements](#operating-system-improvements)
- [Changelog (Modernized)](#changelog-modernized)

---

## Overview

WebHashcat (Modernized) exposes the hashcat CLI through a Django application and a lightweight HTTPS node agent.

- Distributed orchestration: register many GPU or CPU nodes, sync them, and trigger cracking jobs remotely.
- Multiple attack modes: dictionary (rules plus wordlists) and mask attacks with live status, resume, and statistics.
- Near real-time visibility: cracked hashes appear immediately, global potfiles stay synchronized, and the UI offers search and analytics.
- Shared storage: uploaded hashfiles, rules, masks, and wordlists live under `WebHashcat/Files/**` and are mounted in both the `web` and `celery` containers. Metadata (md5 and line counts) is cached per category (wordlists/rules/masks) in a JSON file per folder to avoid expensive rescans.
- Safe workloads: Celery tasks and per-hashfile locks prevent long-running operations from stepping on each other.

## Architecture

```
+----------------------+    TLS + Basic Auth    +----------------------+
| WebHashcat           |<---------------------->| HashcatNode          |
| Django + Celery      |   /hashcatInfo, etc.   | Flask API + hashcat  |
+-----------+----------+                        +-----------+----------+
            | shared volume (Files/)                        | local pot/output
            v                                               v
     Hashfiles, rules, masks, wordlists             GPU or CPU worker hosts
```

- The Django monolith (apps: Hashcat, Nodes, Utils, API, Auth) relies on MySQL and Redis.
- HashcatNode is a Flask HTTPS API with Peewee + SQLite state, TLS certs, and the native hashcat binary.
- Communication always flows through `Utils/hashcatAPI.py`; there is no direct DB or SSH access to worker nodes.

## Quick start (Docker)

Requirements: Docker Engine 24+, the `docker compose` plugin 2.29+, and the matching GPU runtime (NVIDIA Container Toolkit for CUDA, /dev/dri for Intel GPU, standard OpenCL for AMD/POCL).

### 1. Prepare the shared `.env` file

```
cp .env.example .env
```

A single `.env` file powers both WebHashcat and HashcatNode: credentials, Brain, hashcat paths, and database settings. The old `settings.ini` and `variables.env` files are no longer used.

Key variables in `.env`:
- WebHashcat: `SECRET_KEY`, `DEBUG`, `DJANGO_SUPERUSER_*`, `MYSQL_*`, `HASHCAT_CACHE_*`, `HASHCAT_BRAIN_HOST`.
  - If `SECRET_KEY` is unset or set to `[generate]`, a random value is generated at container start.
- HashcatNode: `HASHCATNODE_USERNAME` / `HASHCATNODE_PASSWORD`, `HASHCATNODE_BIND` / `HASHCATNODE_PORT`, `HASHCATNODE_BINARY`, `HASHCATNODE_HASHES_DIR` / `RULES_DIR` / `WORDLISTS_DIR` / `MASKS_DIR`, `HASHCATNODE_WORKLOAD_PROFILE`, `HASHCATNODE_BRAIN_*` (by default the password falls back to `HASHCAT_BRAIN_PASSWORD`; set `HASHCATNODE_BRAIN_PASSWORD` only if you need a different one).

### 2. Start the web stack

```
cd WebHashcat/
docker compose --env-file ../.env up -d --build
```

- Creates the `webhashcat-net` bridge network.
- Starts MySQL, Redis, the Django container, and the Celery worker. `WebHashcat/Files` is bind-mounted.
- The UI listens on `http://127.0.0.1:8000` (credentials are taken from `.env`).

### 3. Start one or more nodes

```
# from the repo root
cd HashcatNode/
# If the web stack is not running on this host, ensure the shared network exists once:
# docker network inspect webhashcat-net >/dev/null 2>&1 || docker network create webhashcat-net
docker compose --env-file ../.env --profile cuda up -d --build          # Nvidia CUDA
docker compose --env-file ../.env --profile amd-gpu up -d --build       # AMD/OpenCL (tag :latest)
docker compose --env-file ../.env --profile intel-gpu up -d --build     # Intel GPU (/dev/dri)
docker compose --env-file ../.env --profile intel-cpu up -d --build     # Intel OpenCL CPU
docker compose --env-file ../.env --profile pocl up -d --build          # Generic CPU/OpenCL
```

- All profiles use the same `.env` file (Basic Auth, Brain, paths). The device type is fixed in the profile (`HASHCATNODE_DEVICE_TYPE=1` CPU, `2` GPU).
- CUDA profiles require `nvidia-container-toolkit`; Intel GPU profiles mount `/dev/dri`; AMD/OpenCL uses the `:latest` tag; CPU profiles work everywhere.
- TLS material is generated on first start under `/hashcatnode/certs`; you can mount your own certificates and point `HASHCATNODE_CERT_PATH` / `HASHCATNODE_KEY_PATH` to them via `.env`.

### 4. Register and synchronise a node

1. Open `http://127.0.0.1:8000` and go to **Nodes**.
2. Create a node with the hostname of the running container and port `9999` (e.g. `hashcatnode-cuda`, `hashcatnode-amd-gpu`, `hashcatnode-intel-gpu`, `hashcatnode-intel-cpu`, or `hashcatnode-pocl` depending on the profile you started) and the credentials configured above.
3. Open the node detail page and click **Synchronise**. Rules, masks, wordlists, and hash type metadata are pushed to the node.

Tip: Nodes on other machines do not need the shared Docker network. Just publish port 9999 on the host and register the node with that host/IP in the Web UI.

### 5. Upload assets and launch sessions

- Use **Hashcat > Files** to upload hashfiles, wordlists, masks, and rules. Uploaded files stay under `WebHashcat/Files/**` until removed. Drag & drop supports multiple files per category; compressed wordlists (`.gz`, `.zip`) remain compressed on disk and are used directly by hashcat.
- From **Hashcat > Hashfiles**, click **Add** to import a new hashfile. Use the `+` button beside a hashfile to define a cracking session, then hit **Play** to start it.
- Sessions stream progress back to the UI; Celery workers keep the potfile and cracked counts in sync.

### 6. Using Hashcat Brain with multiple nodes

WebHashcat exposes hashcat's **Brain** feature so you can coordinate work across several nodes that attack the **same hashfile**. Brain does **not** distribute keyspace by itself, but it tracks what each client has already tried and prevents duplicate work when multiple clients run the same attack.

At a high level you need:

1. A running **brain server** (native hashcat component).
2. One or more **HashcatNode** instances configured to talk to that brain server.
3. One or more sessions created by choosing **Brain cluster** in the Node field of the UI: a session is generated for every Brain-enabled node (with a detected host) and hashcat runs in Brain mode 3.

#### 6.1 Start the brain server

You can run the brain server in two ways:

1. **Docker service in the WebHashcat stack (recommended)**  
   The `WebHashcat/docker-compose.yml` file includes a `brain` service that starts a dedicated container running `hashcat --brain-server`. The service reuses the same upstream image family as the default CPU node profile:

   ```yaml
   services:
     brain:
       image: dizcza/docker-hashcat:pocl
       container_name: webhashcat-brain
       command:
         - /usr/local/bin/hashcat
         - --brain-server
         - --brain-host
         - 0.0.0.0
         - --brain-port
         - "13743"
         - --brain-password
         - bZfhCvGUSjRq
       restart: unless-stopped
       networks:
         - webhashcat
       ports:
         - "13743:13743"
   ```

   When you run:

   ```bash
   cd WebHashcat/
   docker compose up -d --build
   ```

   the `brain` service is started together with the web, Celery, database, and Redis containers. Inside the shared Docker network `webhashcat-net`, the brain server is reachable as `webhashcat-brain:13743`.

   - HashcatNode containers attached to the same `webhashcat-net` network should use `HASHCATNODE_BRAIN_HOST=webhashcat-brain` and `HASHCATNODE_BRAIN_PORT=13743` (these defaults are already in `.env.example`).
   - Nodes running on other hosts can connect to the exposed host port `13743` using the Docker host IP/hostname.

2. **Manual (bare-metal or custom) brain server**  
   On any machine reachable from all your nodes (this can be the same host as a node or a separate box), you can also start hashcat in brain-server mode directly:

   ```bash
   hashcat --brain-server \
           --brain-host 0.0.0.0 \
           --brain-port 13743 \
           --brain-password superSecretBrainPw
   ```

   Notes for the manual mode:

   - `--brain-host` should normally be `0.0.0.0` on the server so that remote nodes can connect, or a specific interface if you want to restrict it.
   - Ensure that the chosen `--brain-port` is reachable from every HashcatNode (firewall/NAT rules).
   - The `--brain-password` must match what you configure on every node.

#### 6.2 Configure each node to use the shared brain server

On every HashcatNode instance (Docker or bare-metal), set these env vars (in `.env` for Docker):

```
HASHCATNODE_BRAIN_ENABLED=true
HASHCATNODE_BRAIN_PORT=13743
HASHCATNODE_BRAIN_PASSWORD=<shared_password>
# Optional: force host; otherwise it is auto-detected from the incoming WebHashcat request
HASHCATNODE_BRAIN_HOST=webhashcat-brain
```

Keep the following points in mind:

- All nodes that should share work **must use the same port/password**.
- `HASHCATNODE_BRAIN_ENABLED` must be true or the node will ignore Brain even if sessions request it.
- If `HASHCATNODE_BRAIN_HOST` is empty, the node auto-detects the caller IP and caches it; the Web app also hints it via `X-Hashcat-Brain-Host` (value from `HASHCAT_BRAIN_HOST`, default `webhashcat-brain`).
- Restart a node container after changing Brain env vars so they take effect.

#### 6.3 Run multiple nodes

You can run several nodes on the same physical host (with different ports and/or GPUs) or on separate machines.

- **Docker:** just start multiple node containers (possibly with different profiles) on different hosts, all attached to the same network and pointing to the shared brain server as above.
- **Bare-metal:** install HashcatNode on each machine following the manual installation section and configure each one's Brain env vars the same way.

In the Web UI, register each node under **Nodes > Add node** with:

- the node's hostname or IP,
- the HTTPS port (default `9999`),
- the Basic Auth credentials configured via env on that node.

Use **Synchronise** on each node page so rules, masks, and wordlists are available everywhere.

#### 6.4 Create coordinated sessions with Brain

Once the brain server and nodes are configured:

1. Go to **Hashcat > Hashfiles** and import or select the hashfile you want to attack.
2. Click the + button beside that hashfile to define a new session.
3. In the **New session** modal:
   - Choose the attack type (dictionary or mask) and parameters (rules, wordlists, masks) as usual.
   - For **Node**, select **Brain cluster (all Brain-enabled nodes)**. This creates one session per node that has Brain enabled and a detected Brain host, always with brain_mode = 3.
4. Start the cluster: the Start/Pause/Resume/Stop/Remove buttons act on the whole group.

Notes:
- To use a single node without Brain, pick that node (not the cluster option); Brain is disabled in that case (brain_mode = 0).
- Make sure nodes show Brain status as Enabled with a detected host in **Nodes**; only those join the cluster.

Screenshots:

<p style="text-align:center;"><img src="./screenshots/webhashcat_hashfile_list.png" alt="Hashfile list"></p>

<p style="text-align:center;"><img src="./screenshots/webhashcat_node.png" alt="Node details"></p>

<p style="text-align:center;"><img src="./screenshots/webhashcat_searches.png" alt="Search view"></p>

## Managing nodes and assets

- Rules, masks, and wordlists can be uploaded through the UI or via `Utils/upload_file.py`. Synchronise a node to push updated versions (MD5 checks prevent redundant uploads).
- Rotate node credentials with `python manage.py rotate_node_passwords [--node-name NODE]` to generate new passwords, then copy the reported username/password/hash into the node's `.env`.
- Hash types are now parsed from `hashcat -hh`, so new hashcat releases only require rebuilding the node container with a newer `HASHCAT_VERSION`.
- Each cracking session stores its own potfile and optional debug output under `HashcatNode/potfiles` and `HashcatNode/outputs`. Start, pause, resume, and quit actions can be issued from the Web UI.
- Windows nodes still allow only one running session at a time (hashcat limitation).
- The **Searches** page lets you query usernames or email fragments across every imported hashfile and download the results.

### Node telemetry cache

- Celery now polls every registered node on a short interval (`HASHCAT_CACHE_REFRESH_SECONDS`, default 30s) and writes node/session snapshots into Redis.
- All dashboard/API endpoints use the cached view instead of calling each node synchronously, so UI refreshes stay non-blocking.
- Cache metadata (`available`, `age_seconds`, `is_stale`) is returned with each response and rendered beside the affected tables.
- Tune the cache via environment variables:
   - `HASHCAT_CACHE_REDIS_URL`: Redis connection used for snapshots (defaults to `redis://redis:6379/1`).
   - `HASHCAT_CACHE_TTL_SECONDS`: expiration for stored snapshots (defaults to 300 seconds).
   - `HASHCAT_CACHE_STALE_SECONDS`: threshold that marks data as stale in the UI (defaults to 90 seconds).

## Manual installation

Docker is strongly recommended, but bare-metal steps remain for completeness.

### HashcatNode (Linux or Windows)

1. Install Python 3 and the required packages:
   ```
   pip3 install -r requirements.txt
   # On Windows also run: pip3 install pywin32
   ```
2. Export the required env vars (see `.env.example` for defaults): at minimum `HASHCATNODE_USERNAME`/`HASHCATNODE_PASSWORD`, `HASHCATNODE_BIND`/`HASHCATNODE_PORT`, `HASHCATNODE_BINARY`, asset directories (`HASHCATNODE_HASHES_DIR`, etc.), and optional Brain env vars.
3. Initialise local resources:
   ```
   python3 create_database.py
   # Optionally generate TLS material or point HASHCATNODE_CERT_PATH/HASHCATNODE_KEY_PATH to existing files
   openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
   ```
4. Start the node with `python3 hashcatnode.py`. Use `systemd/hashcatnode.service` on Linux or Task Scheduler/Services on Windows to keep it running.

Limitations and dependencies:

- Windows nodes can run or pause only one session at a time.
- The hashes, rules, masks, and wordlists directories must be writable by the service user.
- Dependencies: Python 3, Flask, flask-basicauth, Peewee, hashcat 3+, OpenSSL for TLS certs.

### WebHashcat (Linux)

1. Install system packages and Python dependencies:
   ```
   apt install mysql-server libmysqlclient-dev redis supervisor
   pip3 install -r requirements.txt
   ```
2. Create the MySQL database:
   ```
   CREATE DATABASE webhashcat CHARACTER SET utf8;
   CREATE USER 'webhashcat' IDENTIFIED BY '<password>';
   GRANT ALL PRIVILEGES ON webhashcat.* TO 'webhashcat';
   ```
3. Configure Django:
   - Set env vars (see `.env.example`): `SECRET_KEY`, `DEBUG`, `DJANGO_ALLOWED_HOSTS`, `MYSQL_*`, `HASHCAT_CACHE_*`, `WEBHASHCAT_HASHCAT_BINARY`, `WEBHASHCAT_POTFILE`, `HASHCAT_BRAIN_HOST`.
   - Run migrations and create a superuser:
     ```
     python manage.py makemigrations
     python manage.py migrate
     python manage.py createsuperuser
     ```
4. Development: `python manage.py runserver 0.0.0.0:8000`.
5. Production: deploy behind gunicorn/uwsgi plus nginx or Apache, and use the Supervisor configs from `supervisor/` to run the Celery worker and beat.

Dependencies: Python 3, Django 2+, mysqlclient, humanize, requests (and requests-toolbelt), Celery, Redis, supervisor, hashcat 3+.

## Operating-system improvements

Large datasets (10 million+ hashes) benefit from a few system tweaks:

- Increase `/tmp` or point MySQL temp storage to a larger volume so big imports do not exhaust disk.
- Keep some swap available, especially on GPU nodes that can spike RAM usage.
- For MySQL InnoDB installations, raise `innodb_buffer_pool_size` so the `Hashcat_hash` table stays responsive.
- Periodically prune `WebHashcat/Files/tmp` if you upload extremely large files outside the normal Celery cleanup cadence.

---

## Changelog (Modernized)

- New dark UI built with Tailwind + Flowbite, consolidated JS, and dropzones for bulk uploads (wordlists/rules/masks).
- Asset metadata now cached per category (wordlists/rules/masks) in per-folder JSON files; md5 is recorded at upload and line counts are reused unless the file name changes.
- Wordlists support compressed uploads (`.gz`, `.zip`) stored as-is; rules count only non-empty, non-comment lines for accurate rule counts.
- Session creation hardens missing hashfiles: if the on-disk hashfile is absent it is regenerated from DB rows before contacting the node.
- Node upload endpoint accepts JSON or multipart and disables compression headers for already-compressed uploads to avoid disconnects with large payloads.
- Django/Celery cache: node and session snapshots served from Redis with staleness metadata to keep the UI responsive.

Questions, bugs, or feature ideas? Open an issue or pull request and help keep WebHashcat current.
