import csv
import datetime
import json
import os
import os.path
import random
import string
import time

import requests
from celery.signals import celeryd_after_setup
from celery.utils.log import get_task_logger
from django.conf import settings
from django.db import connection
from django.utils import timezone

from Hashcat.models import Hashfile, Hash, Search
from Nodes.models import Node
from Utils.hashcat import Hashcat
from Utils.hashcatAPI import HashcatAPI
from Utils.hashcat_cache import HashcatSnapshotCache
from Utils.models import Task
from Utils.node_snapshot import NodeSnapshot
from Utils.session_snapshot import SessionSnapshot
from Utils.utils import only_one
# from celery import Celery
from WebHashcat.celery import app

logger = get_task_logger(__name__)

NODE_CACHE_REFRESH_SECONDS = getattr(settings, "HASHCAT_CACHE_REFRESH_SECONDS", 30)
NODE_CACHE_LOCK_TIMEOUT = max(NODE_CACHE_REFRESH_SECONDS * 2, NODE_CACHE_REFRESH_SECONDS + 5)
POTFILE_LOCK_TIMEOUT = getattr(settings, "HASHCAT_POTFILE_LOCK_TIMEOUT", 60 * 60)
CRACKED_COUNT_LOCK_TIMEOUT = getattr(settings, "HASHCAT_CRACKED_COUNT_LOCK_TIMEOUT", 15 * 60)
TASK_LOG_TTL_SECONDS = getattr(settings, "HASHCAT_TASK_LOG_TTL", 60 * 60)


@app.on_after_finalize.connect
def setup_periodic_tasks(sender, **kwargs):
    logger.debug("Registering periodic Celery tasks")
    sender.add_periodic_task(1 * 60, update_potfile_task.s())  # Every 5 minutes
    sender.add_periodic_task(2 * 60 * 60, update_cracked_count.s())  # Every 2 Hours
    sender.add_periodic_task(3 * 60 * 60, optimize_potfile.s())  # Every 3 Hours
    sender.add_periodic_task(NODE_CACHE_REFRESH_SECONDS, refresh_node_cache_task.s())


@celeryd_after_setup.connect
def cleanup_tasks(sender, instance, **kwargs):
    for task in Task.objects.all():
        task.delete()

    # Set all "Running" and "Starting" searches to aborted
    for search in Search.objects.filter(status__in=["Starting", "Running"]):
        search.status = "Aborted"
        search.save()


def _create_task_log(message):
    cutoff = timezone.now() - datetime.timedelta(seconds=TASK_LOG_TTL_SECONDS)
    Task.objects.filter(time__lt=cutoff).delete()
    return Task.objects.create(time=timezone.now(), message=message)


def _task_with_lock(task_message, lock_key, lock_timeout):
    def decorator(func):
        @only_one(key=lock_key, timeout=lock_timeout)
        def wrapper(*args, **kwargs):
            task = _create_task_log(task_message) if task_message else None
            try:
                return func(*args, **kwargs)
            finally:
                if task:
                    task.delete()

        return wrapper

    return decorator


def _build_session_snapshot(hashcat_api, session_name, node_name, node_id):
    fetched_at = timezone.now().isoformat()

    try:
        session_info = hashcat_api.get_session_info(session_name)
    except requests.exceptions.RequestException as exc:
        return SessionSnapshot.from_error(session_name, node_name, node_id, str(exc))

    return SessionSnapshot.from_api_response(session_name, node_name, node_id, session_info, fetched_at=fetched_at)


@app.task(name="refresh_node_cache_task")
@_task_with_lock(
    task_message="Refreshing node cache...",
    lock_key="refresh_node_cache_task",
    lock_timeout=NODE_CACHE_LOCK_TIMEOUT,
)
def refresh_node_cache_task():
    cache = HashcatSnapshotCache()
    generated_at = timezone.now()
    snapshot = {
        "generated_at": generated_at.isoformat(),
        "generated_at_epoch": generated_at.timestamp(),
        "nodes": {},
        "sessions": {},
        "errors": [],
    }

    for node in Node.objects.all():
        node_entry = NodeSnapshot.empty(node)
        node_entry.fetched_at = generated_at.isoformat()

        try:
            hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            node_info = hashcat_api.get_hashcat_info()

            if not node_info:
                raise RuntimeError("No response from node")

            if node_info.get("response") == "error":
                raise RuntimeError(node_info.get("message", "Node returned error"))

            sessions = list(node_info.get("sessions", []))
            running_sessions = len([s for s in sessions if s.get("status") == "Running"])
            node_entry.version = node_info.get("version")
            node_entry.sessions = sessions
            node_entry.session_count = len(sessions)
            node_entry.running_sessions = running_sessions
            # "status" here describes the node's activity, not its reachability:
            # - "Running": at least one session reported as Running on this node
            # - "Idle": node responded successfully but has no running sessions
            # - "Error": node unreachable or returned an error (set in the except block)
            node_entry.status = "Running" if running_sessions > 0 else "Idle"
            node_entry.error = None
            node_entry.last_success = generated_at.isoformat()

            for session in sessions:
                session_name = session.get("name")
                if not session_name:
                    continue
                session_snapshot = _build_session_snapshot(hashcat_api, session_name, node.name, node.id)
                snapshot["sessions"][session_name] = session_snapshot.as_dict()

        except Exception as exc:
            node_entry.error = str(exc)
            node_entry.status = "Error"
            node_entry.sessions = []
            snapshot["errors"].append(
                {
                    "node_id": node.id,
                    "node_name": node.name,
                    "message": node_entry.error,
                }
            )
            logger.warning("Unable to refresh node %s: %s", node.name, node_entry.error)

        snapshot["nodes"][str(node.id)] = node_entry.as_dict()

    cache.store_snapshot(snapshot)
    logger.debug(
        "Stored hashcat snapshot for %d nodes / %d sessions",
        len(snapshot["nodes"]),
        len(snapshot["sessions"]),
    )

    return {
        "nodes": len(snapshot["nodes"]),
        "sessions": len(snapshot["sessions"]),
    }


@app.task(name="import_hashfile_task")
def import_hashfile_task(hashfile_id):
    hashfile = Hashfile.objects.get(id=hashfile_id)

    task = _create_task_log("Importing hash file %s..." % hashfile.name)

    try:

        if hashfile.hash_type != -1:  # if != plaintext
            task.message = "Importing hash file %s..." % hashfile.name
            task.save()

            Hashcat.insert_hashes(hashfile)

            task.message = "Comparing hash file %s to potfile..." % hashfile.name
            task.save()

            Hashcat.compare_potfile(hashfile)
        else:
            task.message = "Importing plaintext file %s..." % hashfile.name
            task.save()

            Hashcat.insert_plaintext(hashfile)
    except Exception:
        logger.exception("Failed to import hashfile %s", hashfile.name)
        return {"error": True}
    finally:
        task.delete()


@app.task(name="remove_hashfile_task")
def remove_hashfile_task(hashfile_id):
    hashfile = Hashfile.objects.get(id=hashfile_id)

    task = _create_task_log("Removing hash file %s..." % hashfile.name)

    try:
        Hashcat.remove_hashfile(hashfile)
    except Exception:
        logger.exception("Failed to remove hashfile %s", hashfile.name)
        return {"error": True}
    finally:
        task.delete()


@app.task(name="run_search_task")
def run_search_task(search_id):
    search = Search.objects.get(id=search_id)

    task = _create_task_log("Running search %s..." % search.name)

    if os.path.exists(search.output_file):
        os.remove(search.output_file)

    try:
        search.status = "Running"
        search.output_lines = None
        search.processing_time = None
        search.save()
        search_info = json.loads(search.json_search_info)

        start_time = time.time()

        cursor = connection.cursor()

        args = []
        columns = ["hashfile_id", "username", "password", "hash_type", "hash"]

        query = "SELECT %s FROM Hashcat_hash" % ",".join(columns)

        if "pattern" in search_info or not "all_hashfiles" in search_info or "ignore_uncracked" in search_info:
            query += " WHERE "

        if "pattern" in search_info:
            query_pattern_list = []
            for pattern in search_info["pattern"].split(';'):
                query_pattern_list.append("username LIKE %s")
                args.append("%" + pattern + "%")

            query += "(" + " OR ".join(query_pattern_list) + ")"

            if not "all_hashfiles" in search_info or "ignore_uncracked" in search_info:
                query += " AND "

        query += "hashfile_id IN (%s)" % ','.join(['%s'] * len(search_info["hashfiles"]))
        args += [int(i) for i in search_info["hashfiles"]]

        if "ignore_uncracked" in search_info:
            query += " AND "

        if "ignore_uncracked" in search_info:
            query += "password IS NOT NULL"

        tmpfile_name = ''.join([random.choice(string.ascii_lowercase) for i in range(16)])
        tmp_file = os.path.join(os.path.dirname(__file__), "..", "Files", "tmp", tmpfile_name)
        f = open(tmp_file, "w")
        csv_writer = csv.writer(f)

        # We remove this so we don't need specific rights in mysql (maybe do a test ?)
        # query += " INTO OUTFILE %s FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '\"' LINES TERMINATED BY '\\n'"
        # args.append(tmp_file)

        rows = cursor.execute(query, args)

        for row in cursor.fetchall():
            csv_writer.writerow(row)
        f.close()
        cursor.close()

        if os.path.exists(tmp_file):
            hash_types_dict = Hashcat.get_hash_types()
            hashfile_dict = {}
            for hashfile in Hashfile.objects.all():
                hashfile_dict[hashfile.id] = hashfile.name

            with open(search.output_file, 'w', newline='') as out_csvfile:
                spamwriter = csv.writer(out_csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                spamwriter.writerow(["Hashfile", "Username", "Password", "Hash format", "Hash"])
                with open(tmp_file, 'r', newline='') as csvfile:
                    spamreader = csv.reader(csvfile, delimiter=',', quotechar='"')
                    for row in spamreader:
                        try:
                            row[0] = hashfile_dict[int(row[0])]
                        except KeyError:
                            pass
                        try:
                            row[3] = hash_types_dict[int(row[3])]['name'] if int(row[3]) != -1 else "Plaintext"
                        except KeyError:
                            pass
                        except ValueError:
                            pass
                        except IndexError:
                            pass
                        spamwriter.writerow(row)

            os.remove(tmp_file)

        end_time = time.time()

        search.status = "Done"
        search.output_lines = int(rows)
        search.processing_time = int(end_time - start_time)
        search.save()

    except Exception:
        logger.exception("Failed to run search %s", search.name)
        end_time = time.time()
        search.status = "Error"
        search.output_lines = 0
        search.processing_time = int(end_time - start_time)
        search.save()
    finally:
        task.delete()


@app.task(name="update_potfile_task")
@_task_with_lock(
    task_message="Updating potfile...",
    lock_key="update_potfile_task",
    lock_timeout=POTFILE_LOCK_TIMEOUT,
)
def update_potfile_task():
    logger.info("Starting potfile update job")
    Hashcat.update_hashfiles()
    logger.info("Potfile update job finished successfully")
    return {"updated": True}


@app.task(name="update_cracked_count")
@_task_with_lock(
    task_message="Updating cracked counts...",
    lock_key="update_cracked_count",
    lock_timeout=CRACKED_COUNT_LOCK_TIMEOUT,
)
def update_cracked_count():
    updated = 0
    for hashfile in Hashfile.objects.all():
        if hashfile.hash_type not in [-1]:
            hashfile.cracked_count = Hash.objects.filter(hashfile_id=hashfile.id, password__isnull=False).count()
            hashfile.save()
            updated += 1
    logger.debug("Updated cracked counts for %d hashfiles", updated)
    return {"updated": updated}


@app.task(name="optimize_potfile")
@_task_with_lock(
    task_message="Optimizing potfile...",
    lock_key="optimize_potfile",
    lock_timeout=POTFILE_LOCK_TIMEOUT,
)
def optimize_potfile():
    logger.info("Starting potfile optimization job")
    Hashcat.optimize_potfile()
    logger.info("Potfile optimization job finished successfully")
    return {"optimized": True}
