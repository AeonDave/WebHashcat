import base64
import binascii
import datetime
import json
import os
import os.path
import random
import string
from collections import OrderedDict
from html import escape

import humanize
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import connection
from django.db.models import Q
from django.db.models import Sum
from django.http import Http404
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt

from Hashcat.models import Hashfile, Session, Hash, Search
from Nodes.models import Node
from Utils.hashcat import Hashcat
from Utils.hashcatAPI import HashcatAPI, HashcatAPIError
from Utils.hashcat_cache import HashcatSnapshotCache
from Utils.models import Task
from Utils.session_snapshot import SessionSnapshot
from Utils.tasks import import_hashfile_task, run_search_task, logger
from Utils.tasks import remove_hashfile_task
from Utils.utils import init_hashfile_locks


def _get_cache_and_snapshot():
    cache = HashcatSnapshotCache()
    snapshot = cache.get_snapshot()
    metadata = cache.get_metadata(snapshot)
    return cache, snapshot, metadata


def _node_snapshots(snapshot):
    return snapshot.get("nodes", {}) if snapshot else {}


def _session_snapshots(snapshot):
    return snapshot.get("sessions", {}) if snapshot else {}


def _session_row_from_cache(session, cached):
    crack_type = cached.get("crack_type")
    if crack_type == "dictionary":
        rule_mask = cached.get("rule")
        wordlist = cached.get("wordlist")
    elif crack_type == "mask":
        rule_mask = cached.get("mask")
        wordlist = ""
    else:
        rule_mask = ""
        wordlist = ""

    progress_value = cached.get("progress")
    progress_display = "%s %%" % progress_value if progress_value is not None else ""
    speed_value = cached.get("speed") or ""

    return {
        "hashfile": session.hashfile.name,
        "node": cached.get("node_name") or session.node.name,
        "type": crack_type,
        "rule_mask": rule_mask or "",
        "wordlist": wordlist or "",
        "remaining": cached.get("time_estimated") or "",
        "progress": progress_display,
        "speed": speed_value,
    }


def _error_session_row(session, status="Node data unavailable", reason=""):
    return {
        "hashfile": session.hashfile.name,
        "node": session.node.name,
        "type": "",
        "rule_mask": "",
        "wordlist": "",
        "status": status,
        "reason": reason,
    }


def _hash_type_label(hash_type_id: int) -> str:
    if hash_type_id == -1:
        return "Plaintext"
    return Hashcat.get_hash_types().get(hash_type_id, {}).get("name", f"Unknown ({hash_type_id})")


def _paginate_queryset(params, queryset, order_fields):
    total = queryset.count()
    search_value = params.get("search[value]", "")
    if search_value:
        queryset = queryset.filter(name__contains=search_value)
    filtered = queryset.count()

    order_index = int(params.get("order[0][column]", "0"))
    order_dir = params.get("order[0][dir]", "asc")
    sort_field = order_fields[order_index]
    sort_field = "-" + sort_field if order_dir == "desc" else sort_field

    queryset = queryset.order_by(sort_field)
    start = int(params.get("start", 0))
    length = int(params.get("length", 10))
    return queryset[start:start + length], total, filtered


# Create your views here.

@login_required
def api_node_status(request):
    params = request.POST if request.method == "POST" else request.GET
    draw = params.get("draw", "0")
    result = {
        "draw": draw,
    }

    cache, snapshot, metadata = _get_cache_and_snapshot()
    node_snapshots = _node_snapshots(snapshot)

    data = []
    for node in Node.objects.all():
        cached = node_snapshots.get(str(node.id))
        version = cached.get("version") if cached else ""
        status = cached.get("status") if cached else "Unknown"
        data.append({
            "name": node.name,
            "version": version or "",
            "status": status or "Unknown",
        })

    result["data"] = data
    result["cache"] = metadata

    return HttpResponse(json.dumps(result), content_type="application/json")


@login_required
def api_statistics(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    result = {
        "draw": params.get("draw", "0"),
    }

    data = []

    if request.user.is_staff:
        count_lines = Hashfile.objects.aggregate(Sum('line_count'))["line_count__sum"]
        count_cracked = Hashfile.objects.aggregate(Sum('cracked_count'))["cracked_count__sum"]
    else:
        count_lines = Hashfile.objects.filter(owner=request.user).aggregate(Sum('line_count'))["line_count__sum"]
        count_cracked = Hashfile.objects.filter(owner=request.user).aggregate(Sum('cracked_count'))[
            "cracked_count__sum"]

    if count_cracked == None:
        count_cracked = 0
    if count_lines == None:
        data.append({"label": "<b>Lines</b>", "value": humanize.intcomma(0)})
        data.append({"label": "<b>Cracked</b>", "value": "%s (%.2f%%)" % (humanize.intcomma(count_cracked), 0)})
    else:
        data.append({"label": "<b>Lines</b>", "value": humanize.intcomma(count_lines)})
        data.append({"label": "<b>Cracked</b>", "value": "%s (%.2f%%)" % (humanize.intcomma(count_cracked),
                                                        count_cracked / count_lines * 100.0 if count_lines != 0 else 0.0)})
    data.append({"label": "<b>Hashfiles</b>", "value": Hashfile.objects.count()})
    data.append({"label": "<b>Nodes</b>", "value": Node.objects.count()})

    result["data"] = data

    return HttpResponse(json.dumps(result), content_type="application/json")


@login_required
def api_cracked_ratio(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    if request.user.is_staff:
        count_lines = Hashfile.objects.aggregate(Sum('line_count'))["line_count__sum"]
        count_cracked = Hashfile.objects.aggregate(Sum('cracked_count'))["cracked_count__sum"]
    else:
        count_lines = Hashfile.objects.filter(owner=request.user).aggregate(Sum('line_count'))["line_count__sum"]
        count_cracked = Hashfile.objects.filter(owner=request.user).aggregate(Sum('cracked_count'))[
            "cracked_count__sum"]

    if count_cracked == None:
        count_cracked = 0
    if count_lines == None:
        result = [
            ["Cracked", 0.0],
            ["Uncracked", 0.0],
        ]
    else:
        result = [
            ["Cracked", count_cracked / count_lines * 100.0 if count_lines != 0 else 0.0],
            ["Uncracked", (1 - count_cracked / count_lines) * 100.0 if count_lines != 0 else 0.0],
        ]

    return HttpResponse(json.dumps(result), content_type="application/json")


@login_required
def api_running_sessions(request):
    params = request.POST if request.method == "POST" else request.GET
    draw = params.get("draw", "0")
    result = {
        "draw": draw,
    }

    cache, snapshot, metadata = _get_cache_and_snapshot()
    session_snapshots = _session_snapshots(snapshot)

    if request.user.is_staff:
        session_list = Session.objects.all()
    else:
        session_list = Session.objects.filter(hashfile__owner=request.user)

    session_list = session_list.select_related("hashfile", "node")

    data = []
    for session in session_list:
        cached = session_snapshots.get(session.name)
        if not cached or cached.get("response") == "error" or cached.get("status") != "Running":
            continue

        snapshot = SessionSnapshot.from_api_response(session.name, cached.get("node_name") or session.node.name,
                                                     session.node.id, cached)
        data.append(snapshot.as_running_row(session.hashfile.name))

    result["data"] = data
    result["cache"] = metadata

    return HttpResponse(json.dumps(result), content_type="application/json")


@login_required
def api_error_sessions(request):
    params = request.POST if request.method == "POST" else request.GET
    draw = params.get("draw", "0")
    result = {
        "draw": draw,
    }

    cache, snapshot, metadata = _get_cache_and_snapshot()
    session_snapshots = _session_snapshots(snapshot)

    if request.user.is_staff:
        session_list = Session.objects.all()
    else:
        session_list = Session.objects.filter(hashfile__owner=request.user)

    session_list = session_list.select_related("hashfile", "node")

    healthy_statuses = {"Not started", "Running", "Paused", "Done"}
    data = []

    for session in session_list:
        cached = session_snapshots.get(session.name)
        node_name = cached.get("node_name") if cached else session.node.name

        if cached is None:
            data.append(_error_session_row(session, status="Node data unavailable"))
            continue

        if cached.get("response") == "error":
            snapshot = SessionSnapshot.from_error(session.name, node_name, session.node.id,
                                                  cached.get("reason") or cached.get("error") or "")
            data.append(snapshot.as_error_row(session.hashfile.name, status_override="Inexistant session on node"))
            continue

        status_value = cached.get("status")
        if status_value in healthy_statuses:
            continue

        snapshot = SessionSnapshot.from_api_response(session.name, node_name, session.node.id, cached)
        data.append(snapshot.as_error_row(session.hashfile.name, status_override=status_value or "Unknown"))

    result["data"] = data
    result["cache"] = metadata

    return HttpResponse(json.dumps(result), content_type="application/json")


@login_required
def api_hashfiles(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    result = {
        "draw": params["draw"],
    }

    cache, snapshot, metadata = _get_cache_and_snapshot()

    session_status = {}
    if snapshot:
        for node_snapshot in snapshot.get("nodes", {}).values():
            for session in node_snapshot.get("sessions", []):
                session_name = session.get("name")
                if session_name:
                    session_status[session_name] = session.get("status")

    if request.user.is_staff:
        hashfile_list = Hashfile.objects
    else:
        hashfile_list = Hashfile.objects.filter(owner=request.user)

    order_fields = ["name", "name", "hash_type", "line_count", "cracked_count", "name", "name", "name"]
    hashfile_list, records_total, records_filtered = _paginate_queryset(params, hashfile_list, order_fields)

    data = []
    for hashfile in hashfile_list:

        running_session_count = 0
        total_session_count = Session.objects.filter(hashfile_id=hashfile.id).count()
        for session in Session.objects.filter(hashfile_id=hashfile.id):
            try:
                if session_status.get(session.name) == "Running":
                    running_session_count += 1
            except KeyError:
                pass

        data.append({
            "DT_RowId": "row_%d" % hashfile.id,
            "name": "<a href='%s'>%s<a/>" % (reverse('Hashcat:hashfile', args=(hashfile.id,)), hashfile.name),
            "type": _hash_type_label(hashfile.hash_type),
            "hash_type_id": hashfile.hash_type,
            "hash_type_value": hashfile.hash_type,
            "line_count": humanize.intcomma(hashfile.line_count),
            "cracked": "%s (%.2f%%)" % (humanize.intcomma(hashfile.cracked_count),
                                        hashfile.cracked_count / hashfile.line_count * 100) if hashfile.line_count > 0 else "0",
            "username_included": "yes" if hashfile.username_included else "no",
            "sessions_count": "%d / %d" % (running_session_count, total_session_count),
        })

    result["data"] = data

    result["recordsTotal"] = records_total
    result["recordsFiltered"] = records_filtered
    result["cache"] = metadata

    return HttpResponse(json.dumps(result), content_type="application/json")


@login_required
def api_hashfile_sessions(request):
    params = request.POST if request.method == "POST" else request.GET
    draw = params.get("draw", "0")
    result = {
        "draw": draw,
    }

    hashfile_id = int(params["hashfile_id"][4:] if params["hashfile_id"].startswith("row_") else params["hashfile_id"])

    cache, snapshot, metadata = _get_cache_and_snapshot()
    session_snapshots = _session_snapshots(snapshot)
    node_snapshots = _node_snapshots(snapshot)

    data = []
    primary_clusters = set()

    def _status_with_reason(label: str, reason: str) -> str:
        if not reason:
            return label
        safe_reason = escape(str(reason))
        safe_label = escape(str(label))
        return f'{safe_label} - <span class="text-xs text-amber-300" title="{safe_reason}">{safe_reason}</span>'

    for session in Session.objects.filter(hashfile_id=hashfile_id).select_related("node", "hashfile"):
        node = session.node
        hashfile = session.hashfile

        if hashfile.owner != request.user and not request.user.is_staff:
            continue

        cached = session_snapshots.get(session.name)
        node_label = cached.get("node_name") if cached and cached.get("node_name") else node.name

        cluster_id = getattr(session, "cluster", None)
        is_primary_cluster = False
        if cluster_id:
            if cluster_id not in primary_clusters:
                primary_clusters.add(cluster_id)
                is_primary_cluster = True

        if cached is None:
            node_cached = node_snapshots.get(str(node.id)) if snapshot else None
            offline = node_cached and node_cached.get("status") == "Error"
            reason = node_cached.get("error") if node_cached else ""
            status_label = _status_with_reason("Node not accessible" if offline else "Node data unavailable", reason)
            if cluster_id and is_primary_cluster:
                # Mostra solo Remove all per cluster orfani
                buttons = (
                    f'<button class="btn btn-danger" data-cluster="{cluster_id}" '
                    f'onClick="cluster_action(\\\'{cluster_id}\\\', \\\'remove\\\')">Remove all</button>'
                )
            elif cluster_id and not is_primary_cluster:
                buttons = ""
            else:
                # Solo Remove per sessioni orfane
                buttons = (
                    f'<button class="btn btn-danger" data-session="{session.name}" '
                    f'onClick="session_action(\\\'{session.name}\\\', \\\'remove\\\')">Remove</button>'
                )
            data.append({
                "node": node_label,
                "type": "",
                "rule_mask": "",
                "wordlist": "",
                "status": status_label,
                "remaining": "",
                "progress": "",
                "speed": "",
                "buttons": buttons,
                "cluster": cluster_id or "",
            })
            continue

        if cached.get("response") == "error":
            if cluster_id and is_primary_cluster:
                buttons = _render_cluster_buttons("Error", cluster_id)
            elif cluster_id and not is_primary_cluster:
                buttons = ""
            else:
                buttons = _render_session_buttons("Error", session.name)
            status_label = _status_with_reason("Error", cached.get("reason") or cached.get("error") or "")
            crack_type = ""
            rule_mask = ""
            wordlist = ""
            remaining = ""
            progress = ""
            speed = ""
        else:
            status_value = cached.get("status") or "Unknown"
            if cluster_id and is_primary_cluster:
                buttons = _render_cluster_buttons(status_value, cluster_id)
            elif cluster_id and not is_primary_cluster:
                buttons = ""
            else:
                buttons = _render_session_buttons(status_value, session.name)

            crack_type = cached.get("crack_type")
            if crack_type == "dictionary":
                rule_mask = cached.get("rule")
                wordlist = cached.get("wordlist")
            elif crack_type == "mask":
                rule_mask = cached.get("mask")
                wordlist = ""
            else:
                rule_mask = ""
                wordlist = ""

            status_label = status_value
            reason = cached.get("reason") or cached.get("error")
            if reason:
                status_label = _status_with_reason(status_label, reason)

            remaining = cached.get("time_estimated") or ""
            progress_value = cached.get("progress")
            progress = "%s %%" % progress_value if progress_value is not None else ""
            speed = cached.get("speed") or ""

        data.append({
            "node": node_label,
            "type": crack_type,
            "rule_mask": rule_mask,
            "wordlist": wordlist,
            "status": status_label,
            "remaining": remaining,
            "progress": progress,
            "speed": speed,
            "buttons": buttons,
            "cluster": cluster_id or "",
        })

    result["data"] = data
    result["cache"] = metadata

    return HttpResponse(json.dumps(result), content_type="application/json")


@login_required
def api_hashfile_cracked(request, hashfile_id):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    if hashfile.owner != request.user and not request.user.is_staff:
        raise Http404("You do not have permission to view this object.")

    result = {
        "draw": params["draw"],
    }

    if hashfile.username_included:
        sort_index = ["username", "password"][int(params["order[0][column]"])]
        sort_index = "-" + sort_index if params["order[0][dir]"] == "desc" else sort_index
    else:
        sort_index = ["hash", "password"][int(params["order[0][column]"])]
        sort_index = "-" + sort_index if params["order[0][dir]"] == "desc" else sort_index

    total_count = Hash.objects.filter(password__isnull=False, hashfile_id=hashfile.id).count()

    if len(params["search[value]"]) == 0:
        if hashfile.username_included:
            cracked_list = Hash.objects.filter(password__isnull=False, hashfile_id=hashfile.id).order_by(sort_index)[
                int(params["start"]):int(params["start"]) + int(params["length"])]
            filtered_count = total_count
        else:
            cracked_list = Hash.objects.filter(password__isnull=False, hashfile_id=hashfile.id).order_by(sort_index)[
                int(params["start"]):int(params["start"]) + int(params["length"])]
            filtered_count = total_count
    else:
        if hashfile.username_included:
            cracked_list = Hash.objects.filter(
                Q(username__contains=params["search[value]"]) | Q(password__contains=params["search[value]"]),
                password__isnull=False, hashfile_id=hashfile.id).order_by(sort_index)[
                int(params["start"]):int(params["start"]) + int(params["length"])]
            filtered_count = Hash.objects.filter(
                Q(username__contains=params["search[value]"]) | Q(password__contains=params["search[value]"]),
                password__isnull=False, hashfile_id=hashfile.id).count()
        else:
            cracked_list = Hash.objects.filter(
                Q(hash__contains=params["search[value]"]) | Q(password__contains=params["search[value]"]),
                password__isnull=False, hashfile_id=hashfile.id).order_by(sort_index)[
                int(params["start"]):int(params["start"]) + int(params["length"])]
            filtered_count = Hash.objects.filter(
                Q(hash__contains=params["search[value]"]) | Q(password__contains=params["search[value]"]),
                password__isnull=False, hashfile_id=hashfile.id).count()

    data = []
    for cracked in cracked_list:
        if hashfile.username_included:
            data.append([cracked.username, cracked.password])
        else:
            data.append([cracked.hash, cracked.password])

    result["data"] = data
    result["recordsTotal"] = total_count
    result["recordsFiltered"] = filtered_count

    return HttpResponse(json.dumps(result), content_type="application/json")


@login_required
def api_hashfile_top_password(request, hashfile_id, N):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    if hashfile.owner != request.user and not request.user.is_staff:
        raise Http404("You do not have permission to view this object.")

    pass_count_list = Hash.objects.raw(
        "SELECT 1 AS id, MAX(password) AS password, COUNT(*) AS count FROM Hashcat_hash WHERE hashfile_id=%s AND password IS NOT NULL GROUP BY BINARY password ORDER BY count DESC LIMIT 10",
        [hashfile.id])

    top_password_list = []
    count_list = []
    for item in pass_count_list:
        top_password_list.append(item.password)
        count_list.append(item.count)

    res = {
        "top_password_list": top_password_list,
        "count_list": count_list,
    }

    return HttpResponse(json.dumps(res), content_type="application/json")


@login_required
def api_hashfile_top_password_len(request, hashfile_id, N):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    if hashfile.owner != request.user and not request.user.is_staff:
        raise Http404("You do not have permission to view this object.")

    # didn't found the correct way in pure django...
    pass_count_list = Hash.objects.raw(
        "SELECT 1 AS id, MAX(password_len) AS password_len, COUNT(*) AS count FROM Hashcat_hash WHERE hashfile_id=%s AND password IS NOT NULL GROUP BY password_len",
        [hashfile.id])

    min_len = None
    max_len = None
    len_count = {}
    for item in pass_count_list:
        if min_len == None:
            min_len = item.password_len
        else:
            min_len = min(min_len, item.password_len)
        if max_len == None:
            max_len = item.password_len
        else:
            max_len = min(max_len, item.password_len)
        len_count[item.password_len] = item.count

    if min_len != None and max_len != None:
        for length in range(min_len, max_len + 1):
            if not length in len_count:
                len_count[length] = 0

    len_count = OrderedDict(sorted(len_count.items()))

    res = {
        "password_length_list": list(len_count.keys()),
        "count_list": list(len_count.values()),
    }

    return HttpResponse(json.dumps(res), content_type="application/json")


@login_required
def api_hashfile_top_password_charset(request, hashfile_id, N):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    if hashfile.owner != request.user and not request.user.is_staff:
        raise Http404("You do not have permission to view this object.")

    # didn't found the correct way in pure django...
    pass_count_list = Hash.objects.raw(
        "SELECT 1 AS id, MAX(password_charset) AS password_charset, COUNT(*) AS count FROM Hashcat_hash WHERE hashfile_id=%s AND password IS NOT NULL GROUP BY password_charset ORDER BY count DESC LIMIT 10",
        [hashfile.id])

    password_charset_list = []
    count_list = []
    for item in pass_count_list:
        password_charset_list.append(item.password_charset)
        count_list.append(item.count)

    res = {
        "password_charset_list": password_charset_list,
        "count_list": count_list,
    }

    for query in connection.queries[-1:]:
        print(query["sql"])
        print(query["time"])

    return HttpResponse(json.dumps(res), content_type="application/json")


@login_required
def api_session_action(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    session = get_object_or_404(Session, name=params["session_name"])

    hashfile = session.hashfile

    if hashfile.owner != request.user and not request.user.is_staff:
        raise Http404("You do not have permission to view this object.")

    node = session.node

    # Use cached snapshot to avoid restarting an already running session
    cache, snapshot, _ = _get_cache_and_snapshot()
    session_snapshots = _session_snapshots(snapshot)
    cached_status = (session_snapshots.get(session.name) or {}).get("status")
    def _can_start(status: str | None) -> bool:
        return status in (None, "", "Not started", "Aborted", "Error", "Done")

    try:
        hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
        action = params["action"]
        if action == "start" and not _can_start(cached_status):
            return HttpResponse(
                json.dumps({"response": "error", "message": f"Session {session.name} is already {cached_status}"}),
                content_type="application/json",
                status=400,
            )
        res = hashcat_api.action(session.name, action)
    except HashcatAPIError as exc:
        return HttpResponse(
            json.dumps({"response": "error", "message": str(exc)}),
            content_type="application/json",
            status=502,
        )

    if action == "remove":
        session.delete()

    return HttpResponse(json.dumps(res), content_type="application/json")


@login_required
def api_cluster_action(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    cluster_id = params.get("cluster")
    action = params.get("action")

    if not cluster_id or not action:
        return HttpResponse(
            json.dumps({"response": "error", "message": "Missing cluster or action"}),
            content_type="application/json",
            status=400,
        )

    sessions = list(Session.objects.filter(cluster=cluster_id).select_related("hashfile", "node"))
    if not sessions:
        return HttpResponse(
            json.dumps({"response": "error", "message": "Cluster not found"}),
            content_type="application/json",
            status=404,
        )

    # Permission check: user must be owner (or staff) for all hashfiles in the cluster.
    for s in sessions:
        if s.hashfile.owner != request.user and not request.user.is_staff:
            raise Http404("You do not have permission to control this cluster.")

    errors = []

    cache, snapshot, _ = _get_cache_and_snapshot()
    session_snapshots = _session_snapshots(snapshot)

    def _can_start(status: str | None) -> bool:
        return status in (None, "", "Not started", "Aborted", "Error", "Done")

    for s in sessions:
        node = s.node
        try:
            hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            cached_status = (session_snapshots.get(s.name) or {}).get("status")
            if action == "start" and not _can_start(cached_status):
                errors.append(f"{s.name}: already {cached_status}")
                continue
            hashcat_api.action(s.name, action)
        except HashcatAPIError as exc:
            errors.append(f"{s.name}@{node.name}: {exc}")

    if action == "remove":
        for s in sessions:
            s.delete()

    if errors:
        return HttpResponse(
            json.dumps({
                "response": "partial_error",
                "message": "; ".join(errors[:3]),
            }),
            content_type="application/json",
            status=207,
        )

    return HttpResponse(json.dumps({"response": "ok"}), content_type="application/json")


@login_required
def api_hashfile_action(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    hashfile = get_object_or_404(Hashfile, id=params["hashfile_id"])

    if hashfile.owner != request.user and not request.user.is_staff:
        raise Http404("You do not have permission to view this object.")

    if params["action"] == "remove":
        try:
            # Prefer synchronous removal to ensure filesystem cleanup even if Celery is down
            Hashcat.remove_hashfile(hashfile)
        except Exception as exc:  # pragma: no cover - log and fall back to async
            logger.exception("Synchronous hashfile removal failed for %s, scheduling task: %s", hashfile.name, exc)
            remove_hashfile_task.delay(hashfile.id)

    return HttpResponse(json.dumps({"result": "success"}), content_type="application/json")


def api_get_messages(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    message_list = []
    for task in Task.objects.all():
        message_list.append({
            "type": "error" if "error" in (task.message or "").lower() else "info",
            "content": task.message,
        })

    return HttpResponse(json.dumps({"result": "success", "messages": message_list}), content_type="application/json")


@login_required
def api_search_list(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    result = {
        "draw": params["draw"],
    }

    if request.user.is_staff:
        search_list = Search.objects
    else:
        search_list = Search.objects.filter(owner=request.user)

    sort_index = ["name", "status", "output_lines"][int(params.get("order[0][column]", 0))]
    sort_index = "-" + sort_index if params.get("order[0][dir]") == "desc" else sort_index
    filtered = search_list.filter(name__contains=params.get("search[value]", ""))
    search_list = filtered.order_by(sort_index)[int(params.get("start", 0)):int(params.get("start", 0)) + int(params.get("length", 10))]

    data = []
    for search in search_list:
        actions = []
        if os.path.exists(search.output_file):
            actions.append("<button class='px-2 py-1 text-xs rounded bg-emerald-900/40 border border-emerald-700 text-emerald-200' data-search-action='view' data-search-id='%d'>View</button>" % search.id)
            actions.append("<a href='%s'><button class='px-2 py-1 text-xs rounded bg-primary/20 border border-primary/40 text-primary'>Download</button></a>" % reverse(
                'Hashcat:export_search', args=(search.id,)))
        if search.status in ["Done", "Aborted", "Error"]:
            actions.append("<button class='px-2 py-1 text-xs rounded bg-sky-900/40 border border-sky-700 text-sky-100' data-search-action='reload' data-search-id='%d'>Restart</button>" % search.id)
            actions.append("<button class='px-2 py-1 text-xs rounded bg-red-900/40 border border-red-700 text-red-200' data-search-action='remove' data-search-id='%d'>Delete</button>" % search.id)
        actions_html = "<div class='flex gap-2 justify-end'>" + "".join(actions) + "</div>"

        data.append({
            "name": search.name,
            "status": search.status,
            "lines": humanize.intcomma(search.output_lines) if search.output_lines is not None else "",
            "processing_time": str(datetime.timedelta(seconds=search.processing_time)) if search.processing_time is not None else "",
            "actions": actions_html,
        })

    result["data"] = data
    result["recordsTotal"] = Search.objects.all().count()
    result["recordsFiltered"] = filtered.count()

    return HttpResponse(json.dumps(result), content_type="application/json")


@login_required
def api_search_action(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    search = get_object_or_404(Search, id=params["search_id"])

    if search.owner != request.user and not request.user.is_staff:
        raise Http404("You do not have permission to view this object.")

    action = params.get("action")
    if action == "remove":
        if os.path.exists(search.output_file):
            os.remove(search.output_file)
        search.delete()
    elif action == "reload":
        run_search_task.delay(search.id)
    elif action == "view":
        if not os.path.exists(search.output_file):
            return HttpResponse(json.dumps({"result": "error", "message": "No results file found"}), content_type="application/json")
        # Limit content size to avoid huge responses
        try:
            with open(search.output_file, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            if len(content) > 200000:
                content = content[:200000] + "\n... (truncated)"
            return HttpResponse(json.dumps({"result": "success", "content": content}), content_type="application/json")
        except OSError as exc:
            return HttpResponse(json.dumps({"result": "error", "message": str(exc)}), content_type="application/json")

    return HttpResponse(json.dumps({"result": "success"}), content_type="application/json")


@csrf_exempt
def api_upload_file(request):
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    token_type, _, credentials = auth_header.partition(' ')

    if token_type != 'Basic' or not credentials:
        return HttpResponse(status=401)

    try:
        decoded = base64.b64decode(credentials).decode()
    except (binascii.Error, ValueError):
        return HttpResponse(status=401)

    if ':' not in decoded:
        return HttpResponse(status=401)

    username, password = decoded.split(':', 1)

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return HttpResponse(status=401)

    if not user.is_staff or not user.check_password(password):
        return HttpResponse(status=401)

    if request.method == "POST":
        params = request.POST
    else:
        return HttpResponse(json.dumps({"result": "error", "value": "Only POST accepted"}),
                            content_type="application/json")

    if not 'name' in params:
        return HttpResponse(json.dumps({"result": "error", "value": "Please specify the uploaded file name"}),
                            content_type="application/json")
    if not 'type' in params:
        return HttpResponse(json.dumps({"result": "error", "value": "Please specify the uploaded file type"}),
                            content_type="application/json")
    if not 'file' in request.FILES:
        return HttpResponse(json.dumps({"result": "error", "value": "Please upload a file"}),
                            content_type="application/json")

    print(params)

    if params['type'] == 'hashfile':
        if not 'hash_type' in params:
            return HttpResponse(json.dumps({"result": "error", "value": "Please specify the hash type"}),
                                content_type="application/json")

        hash_type = int(params["hash_type"])

        hashfile_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12)) + ".hashfile"
        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile_name)

        with open(hashfile_path, 'w', encoding='utf-8', errors='backslashreplace') as f:
            for chunk in request.FILES['file'].chunks():
                f.write(chunk.decode('UTF-8', 'backslashreplace'))

        username_included = "username_included" in params

        hashfile = Hashfile(
            owner=user,
            name=request.POST['name'],
            hashfile=hashfile_name,
            hash_type=hash_type,
            line_count=0,
            cracked_count=0,
            username_included=username_included,
        )
        hashfile.save()
        init_hashfile_locks(hashfile)

        # Update the new file with the potfile, this may take a while, but it is processed in a background task
        import_hashfile_task.delay(hashfile.id)
    elif params['type'] == 'wordlist':
        f = request.FILES["file"]
        wordlist_file = f.read()

        Hashcat.upload_wordlist(params['name'], wordlist_file)
    elif params['type'] == 'rule':
        f = request.FILES["file"]
        rule_file = f.read()

        Hashcat.upload_rule(params['name'], rule_file)
    elif params['type'] == 'mask':
        f = request.FILES["file"]
        mask_file = f.read()

        Hashcat.upload_mask(params['name'], mask_file)

    return HttpResponse(json.dumps({"result": "success"}), content_type="application/json")


def _render_session_buttons(status: str, session_name: str) -> str:
    def btn(label, action, style):
        return (
            f"<button type='button' class='px-2 py-1 text-xs rounded {style}' "
            f"data-session='{session_name}' data-action='{action}' "
            f"onClick='session_action(\"{session_name}\", \"{action}\")'>{label}</button>"
        )

    buttons = []
    if status == "Not started":
        buttons.append(btn("Start", "start", "bg-emerald-900/40 border border-emerald-700 text-emerald-200"))
        buttons.append(btn("Remove", "remove", "bg-red-900/40 border border-red-700 text-red-200 ml-1"))
    elif status == "Running":
        buttons.append(btn("Pause", "pause", "bg-amber-900/40 border border-amber-700 text-amber-200"))
        buttons.append(btn("Stop", "quit", "bg-red-900/40 border border-red-700 text-red-200 ml-1"))
    elif status == "Paused":
        buttons.append(btn("Resume", "resume", "bg-emerald-900/40 border border-emerald-700 text-emerald-200"))
        buttons.append(btn("Stop", "quit", "bg-red-900/40 border border-red-700 text-red-200 ml-1"))
    else:
        buttons.append(btn("Start", "start", "bg-emerald-900/40 border border-emerald-700 text-emerald-200"))
        buttons.append(btn("Remove", "remove", "bg-red-900/40 border border-red-700 text-red-200 ml-1"))

    return "<div class='flex justify-end gap-1'>%s</div>" % "".join(buttons)


def _render_cluster_buttons(status: str, cluster_id: str) -> str:
    def btn(label, action, style):
        return (
            f"<button type='button' class='px-2 py-1 text-xs rounded {style}' "
            f"data-cluster='{cluster_id}' data-action='{action}' "
            f"onClick='cluster_action(\"{cluster_id}\", \"{action}\")'>{label}</button>"
        )

    buttons = []
    if status == "Not started":
        buttons.append(btn("Start all", "start", "bg-emerald-900/40 border border-emerald-700 text-emerald-200"))
        buttons.append(btn("Remove all", "remove", "bg-red-900/40 border border-red-700 text-red-200 ml-1"))
    elif status == "Running":
        buttons.append(btn("Pause all", "pause", "bg-amber-900/40 border border-amber-700 text-amber-200"))
        buttons.append(btn("Stop all", "quit", "bg-red-900/40 border border-red-700 text-red-200 ml-1"))
    elif status == "Paused":
        buttons.append(btn("Resume all", "resume", "bg-emerald-900/40 border border-emerald-700 text-emerald-200"))
        buttons.append(btn("Stop all", "quit", "bg-red-900/40 border border-red-700 text-red-200 ml-1"))
    else:
        buttons.append(btn("Start all", "start", "bg-emerald-900/40 border border-emerald-700 text-emerald-200"))
        buttons.append(btn("Remove all", "remove", "bg-red-900/40 border border-red-700 text-red-200 ml-1"))

    return "<div class='flex justify-end gap-1'>%s</div>" % "".join(buttons)
