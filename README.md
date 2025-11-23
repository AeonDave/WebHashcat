# WebHashcat

Modern Hashcat orchestration with a Django web UI, Celery workers, and Docker-first workflows.

> This fork tracks the original project from https://github.com/hegusung/WebHashcat and keeps it current with Python 3.11, docker compose profiles, and hashcat 7.1.2 (CPU and CUDA).

## Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick start (Docker)](#quick-start-docker)
- [Managing nodes and assets](#managing-nodes-and-assets)
- [Manual installation](#manual-installation)
- [Operating-system improvements](#operating-system-improvements)

---

## Overview

WebHashcat exposes the hashcat CLI through a Django application and a lightweight HTTPS node agent.

- Distributed orchestration: register many GPU or CPU nodes, sync them, and trigger cracking jobs remotely.
- Multiple attack modes: dictionary (rules plus wordlists) and mask attacks with live status, resume, and statistics.
- Near real-time visibility: cracked hashes appear immediately, global potfiles stay synchronized, and the UI offers search and analytics.
- Shared storage: uploaded hashfiles, rules, masks, and wordlists live under `WebHashcat/Files/**` and are mounted in both the `web` and `celery` containers.
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

Requirements: Docker Engine 24+, the `docker compose` plugin 2.29+, and (for CUDA) the NVIDIA Container Toolkit with drivers that support CUDA 12 or newer.

### 1. Start the web stack

```
cd WebHashcat/
docker compose up -d --build
```

- Creates the shared bridge network `webhashcat-net`.
- Starts MySQL, Redis, the Django web container, and the Celery worker. Files under `WebHashcat/Files` are bind-mounted.
- The UI listens on `http://127.0.0.1:8000` (credentials come from `variables.env`).

### 2. Start one or more nodes

```
cd HashcatNode/

# GPU / CUDA build (default hashcat v7.1.2)
docker compose --profile cuda up -d --build

# CPU-only build
docker compose --profile cpu up -d --build

# Override the bundled hashcat version
HASHCAT_VERSION=v7.1.3 docker compose --profile cuda up -d --build
```

- Both `hashcatnode-cuda` and `hashcatnode-cpu` automatically attach to `webhashcat-net`.
- CUDA profile expects `nvidia-container-toolkit`; CPU profile works everywhere.
- Override the Basic-Auth credentials via `HASHCATNODE_USERNAME` and `HASHCATNODE_HASH` (sha256 of the password).

### 3. Register and synchronise a node

1. Open `http://127.0.0.1:8000` and go to **Nodes**.
2. Create a node with hostname `hashcatnode-cpu` (or `hashcatnode-cuda`), port `9999`, and the credentials configured above.
3. Open the node detail page and click **Synchronise**. Rules, masks, wordlists, and hash type metadata are pushed to the node.

Tip: Nodes on other machines do not need the shared Docker network. Just publish port 9999 on the host and register the node with that host/IP in the Web UI.

### 4. Upload assets and launch sessions

- Use **Hashcat → Files** to upload hashfiles, wordlists, masks, and rules. Uploaded files stay under `WebHashcat/Files/**` until removed.
- From **Hashcat → Hashfiles**, click **Add** to import a new hashfile. Use the `+` button beside a hashfile to define a cracking session, then hit **Play** to start it.
- Sessions stream progress back to the UI; Celery workers keep the potfile and cracked counts in sync.

Screenshots:

<p style="text-align:center;"><img src="./screenshots/webhashcat_hashfile_list.png" alt="Hashfile list"></p>

<p style="text-align:center;"><img src="./screenshots/webhashcat_node.png" alt="Node details"></p>

<p style="text-align:center;"><img src="./screenshots/webhashcat_searches.png" alt="Search view"></p>

## Managing nodes and assets

- Rules, masks, and wordlists can be uploaded through the UI or via `Utils/upload_file.py`. Synchronise a node to push updated versions (MD5 checks prevent redundant uploads).
- Hash types are now parsed from `hashcat -hh`, so new hashcat releases only require rebuilding the node container with a newer `HASHCAT_VERSION`.
- Each cracking session stores its own potfile and optional debug output under `HashcatNode/potfiles` and `HashcatNode/outputs`. Start, pause, resume, and quit actions can be issued from the Web UI.
- Windows nodes still allow only one running session at a time (hashcat limitation).
- The **Searches** page lets you query usernames or email fragments across every imported hashfile and download the results.

## Manual installation

Docker is strongly recommended, but bare-metal steps remain for completeness.

### HashcatNode (Linux or Windows)

1. Install Python 3 and the required packages:
   ```
   pip3 install -r requirements.txt
   # On Windows also run: pip3 install pywin32
   ```
2. Copy `settings.ini.sample` to `settings.ini`, then set the hashcat binary path, hashes/rules/wordlists/masks directories, bind host/port, and credentials.
3. Initialise local resources:
   ```
   python3 create_database.py
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
   - Copy `WebHashcat/settings.py.sample` to `WebHashcat/settings.py`, then set `SECRET_KEY`, database credentials, and `ALLOWED_HOSTS`.
   - Copy `settings.ini.sample` to `settings.ini` and set the host hashcat binary path plus potfile location.
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

Questions, bugs, or feature ideas? Open an issue or pull request and help keep WebHashcat current.
