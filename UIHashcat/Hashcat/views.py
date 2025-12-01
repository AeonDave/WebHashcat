import csv
import json
import os.path
import random
import string
from datetime import datetime
from operator import itemgetter

import humanize
from Nodes.models import Node
from Utils.hashcat import Hashcat, HashcatExecutionError
from Utils.hashcatAPI import HashcatAPI, HashcatAPIError
from Utils.hashcat_cache import HashcatSnapshotCache
from Utils.node_capabilities import summarize_capabilities
from Utils.session_snapshot import SessionSnapshot
from Utils.tasks import import_hashfile_task, run_search_task
from Utils.utils import Echo
from Utils.utils import init_hashfile_locks
from Utils.hashcat import HashcatExecutionError
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.db.models import Sum
from django.http import FileResponse
from django.http import Http404
from django.http import HttpResponse
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.shortcuts import redirect
from django.template import loader

from .models import Hashfile, Session, Hash, Search


def _available_hash_types():
    for node in Node.objects.all():
        try:
            api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            info = api.get_hashcat_info()
            if info and info.get("response") == "ok" and info.get("hash_types"):
                return sorted(info["hash_types"], key=itemgetter("name"))
        except HashcatAPIError:
            continue
    return sorted(list(Hashcat.get_hash_types().values()), key=itemgetter('name'))


@login_required
def dashboard(request):
    context = {"Section": "Dashboard"}

    # Prefetch stats and snapshots to avoid empty dashboard on first load
    if request.user.is_staff:
        count_lines = Hashfile.objects.aggregate(Sum('line_count'))["line_count__sum"]
        count_cracked = Hashfile.objects.aggregate(Sum('cracked_count'))["cracked_count__sum"]
        session_list = Session.objects.select_related("hashfile", "node").all()
    else:
        count_lines = Hashfile.objects.filter(owner=request.user).aggregate(Sum('line_count'))["line_count__sum"]
        count_cracked = Hashfile.objects.filter(owner=request.user).aggregate(Sum('cracked_count'))["cracked_count__sum"]
        session_list = Session.objects.select_related("hashfile", "node").filter(hashfile__owner=request.user)

    count_cracked = count_cracked or 0
    stats_rows = []
    if count_lines is None:
        stats_rows.append({"label": "<b>Lines</b>", "value": humanize.intcomma(0)})
        stats_rows.append({"label": "<b>Cracked</b>", "value": "%s (%.2f%%)" % (humanize.intcomma(count_cracked), 0)})
    else:
        stats_rows.append({"label": "<b>Lines</b>", "value": humanize.intcomma(count_lines)})
        stats_rows.append({"label": "<b>Cracked</b>", "value": "%s (%.2f%%)" % (humanize.intcomma(count_cracked),
                                                              count_cracked / count_lines * 100.0 if count_lines != 0 else 0.0)})
    stats_rows.append({"label": "<b>Hashfiles</b>", "value": Hashfile.objects.count()})
    stats_rows.append({"label": "<b>Nodes</b>", "value": Node.objects.count()})

    cracked_data = []
    if count_lines:
        cracked_data = [
            ["Cracked", count_cracked],
            ["Uncracked", count_lines - count_cracked],
        ]

    cache = HashcatSnapshotCache()
    snapshot = cache.get_snapshot()
    metadata = cache.get_metadata(snapshot)
    node_snapshots = snapshot.get("nodes", {}) if snapshot else {}
    session_snapshots = snapshot.get("sessions", {}) if snapshot else {}

    nodes_prefetch = []
    for node_id, node_data in node_snapshots.items():
        nodes_prefetch.append({
            "name": node_data.get("name") or node_id,
            "status": node_data.get("status") or "",
        })

    running_prefetch = []
    error_prefetch = []
    healthy_statuses = {"Not started", "Running", "Paused", "Done"}
    for session in session_list:
        cached = session_snapshots.get(session.name)
        node_name = cached.get("node_name") if cached else session.node.name

        if cached is None:
            # Node data unavailable
            error_prefetch.append({
                "hashfile": session.hashfile.name,
                "node": session.node.name,
                "type": "",
                "rule_mask": "",
                "wordlist": "",
                "status": "Node data unavailable",
                "reason": "",
            })
            continue

        if cached.get("response") == "error":
            snapshot_obj = SessionSnapshot.from_error(session.name, node_name, session.node.id,
                                                      cached.get("reason") or cached.get("error") or "")
            error_prefetch.append(snapshot_obj.as_error_row(session.hashfile.name,
                                                            status_override="Inexistant session on node"))
            continue

        status_value = cached.get("status")
        snapshot_obj = SessionSnapshot.from_api_response(session.name, node_name, session.node.id, cached)
        if status_value == "Running":
            running_prefetch.append(snapshot_obj.as_running_row(session.hashfile.name))
        elif status_value not in healthy_statuses:
            error_prefetch.append(snapshot_obj.as_error_row(session.hashfile.name,
                                                            status_override=status_value or "Unknown"))

    context["prefetch"] = {
        "stats": stats_rows,
        "cracked": cracked_data,
        "nodes": nodes_prefetch,
        "running": running_prefetch,
        "errors": error_prefetch,
        "metadata": metadata,
    }
    # Serialize prefetch to JSON so it can be injected safely into JavaScript
    context["prefetch_json"] = json.dumps(context["prefetch"])
    template = loader.get_template('Hashcat/dashboard.html')
    return HttpResponse(template.render(context, request))


@login_required
def hashfiles(request):
    context = {}
    context["Section"] = "Hashes"

    if request.method == 'POST':
        if request.POST["action"] == "add":
            hash_type = int(request.POST["hash_type"])

            hashfile_name = ''.join(
                random.choice(string.ascii_uppercase + string.digits) for _ in range(12)) + ".hashfile"
            hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile_name)

            hashes = request.POST["hashes"]
            f = open(hashfile_path, 'w')
            if len(hashes) == 0 and "hashfile" in request.FILES:
                for chunk in request.FILES['hashfile'].chunks():
                    f.write(chunk.decode('UTF-8', 'backslashreplace'))
            else:
                f.write(hashes.strip())
            f.close()

            username_included = "username_included" in request.POST

            hashfile = Hashfile(
                owner=request.user,
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

            if hash_type != -1:  # if != plaintext
                messages.success(request, "Hashfile successfully added")
            else:
                messages.success(request, "Plaintext file successfully added")

    context["node_list"] = Node.objects.all()
    hash_types = _available_hash_types()
    # Autodetect in hashcat still requires choosing among suggested modes; we require explicit selection to avoid ambiguity.
    context["hash_type_list"] = [{'id': -1, 'name': 'Plaintext'}] + hash_types
    context["rule_list"] = [{'name': None}] + sorted(Hashcat.get_rules(detailed=False), key=itemgetter('name'))
    context["mask_list"] = sorted(Hashcat.get_masks(detailed=False), key=itemgetter('name'))
    context["wordlist_list"] = sorted(Hashcat.get_wordlists(detailed=False), key=itemgetter('name'))
    node_capabilities = {}
    node_options = []
    for node in context["node_list"]:
        info = None
        try:
            api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            info = api.get_hashcat_info()
            if info and info.get("response") == "error":
                info = None
        except HashcatAPIError:
            info = None
        caps = summarize_capabilities(info)
        node_capabilities[node.name] = caps
        label = caps.get("short_label") or "unknown"
        option_label = f"{node.name} ({label})" if label != "unknown" else f"{node.name} (unknown device)"
        node_options.append({"name": node.name, "label": option_label})
    context["node_options"] = node_options
    context["node_capabilities"] = node_capabilities

    template = loader.get_template('Hashcat/hashes.html')
    return HttpResponse(template.render(context, request))


@login_required
def search(request):
    context = {}
    context["Section"] = "Search"

    context["hashfile_list"] = Hashfile.objects.order_by('name')
    if request.method == 'POST':
        search_info = {}
        if len(request.POST["search_pattern"]) != 0:
            search_info["pattern"] = request.POST["search_pattern"]

        hashfile_list = []
        if "all_hashfiles" in request.POST:
            for hashfile in Hashfile.objects.all():
                if hashfile.owner == request.user or request.user.is_staff:
                    hashfile_list.append(hashfile.id)
        else:
            for hashfile_id in request.POST.getlist("hashfile_search[]"):
                hashfile = Hashfile.objects.get(id=int(hashfile_id))

                if hashfile != None:
                    if hashfile.owner == request.user or request.user.is_staff:
                        hashfile_list.append(int(hashfile_id))
        search_info["hashfiles"] = hashfile_list

        if "ignore_uncracked" in request.POST:
            search_info["ignore_uncracked"] = True

        print(search_info)

        search_filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12)) + ".csv"
        output_file = os.path.join(os.path.dirname(__file__), "..", "Files", "Searches", search_filename)

        search = Search(
            owner=request.user,
            name=request.POST['search_name'],
            status="Starting",
            output_lines=None,
            output_file=output_file,
            json_search_info=json.dumps(search_info),
        )
        search.save()

        run_search_task.delay(search.id)

    template = loader.get_template('Hashcat/search.html')
    return HttpResponse(template.render(context, request))


@login_required
@staff_member_required
def files(request):
    context = {}
    context["Section"] = "Files"

    if request.method == 'POST':
        if request.POST["action"] == "remove":
            if request.POST["filetype"] == "rule":
                Hashcat.remove_rule(request.POST["filename"])
            elif request.POST["filetype"] == "mask":
                Hashcat.remove_mask(request.POST["filename"])
            elif request.POST["filetype"] == "wordlist":
                Hashcat.remove_wordlist(request.POST["filename"])

    # Detailed listings rely on cached metadata and are inexpensive after first run
    context["rule_list"] = Hashcat.get_rules(detailed=True)
    context["mask_list"] = Hashcat.get_masks(detailed=True)
    context["wordlist_list"] = Hashcat.get_wordlists(detailed=True)

    template = loader.get_template('Hashcat/files.html')
    return HttpResponse(template.render(context, request))


@login_required
def new_session(request):
    if request.method == 'POST':
        hashfile = get_object_or_404(Hashfile, id=request.POST['hashfile_id'])

        # Check if the user owns the Hashfile or Staff
        if request.user != hashfile.owner and not request.user.is_staff:
            raise Http404("You do not have permission to view this object")

        crack_type = request.POST["crack_type"]
        if crack_type == "dictionary":
            selected_rules = request.POST.getlist("rule")
            rule = selected_rules if selected_rules else None
            wordlist = request.POST["wordlist"]
        elif crack_type == "mask":
            mask = request.POST["mask"]

        if request.POST["end_datetime"]:
            end_timestamp = int(datetime.strptime(request.POST["end_datetime"], "%m/%d/%Y %I:%M %p").timestamp())
        else:
            end_timestamp = None

        # Identificatore base usato per i nomi di sessione e, se necessario, per il cluster.
        base_id = ("%s-%s" % (hashfile.name, ''.join(
            random.choice(string.ascii_uppercase + string.digits) for _ in range(12)))).replace(" ", "_")

        if "debug" in request.POST:
            hashcat_debug_file = True
        else:
            hashcat_debug_file = False
        kernel_optimized = "kernel_optimized" in request.POST

        try:
            Hashcat.ensure_hashfile_exists(hashfile)
        except FileNotFoundError:
            messages.error(request, "Hashfile content is missing on disk; please re-import the hashfile before starting a session.")
            return redirect('Hashcat:hashfiles')
        node_name = request.POST["node"]

        def _brain_mode_for_hash(hash_type_id: int) -> int:
            # Hash veloci (id < 1000) usano solo la feature "attacks" per evitare saturazione del brain.
            if hash_type_id is not None and hash_type_id >= 0 and hash_type_id < 1000:
                return 2
            return 3

        def _resolve_asset_path(items, name):
            for itm in items:
                if itm.get("name") == name:
                    return itm.get("path")
            return None

        def _line_count(items, name):
            for itm in items:
                if itm.get("name") == name:
                    return itm.get("line_count")
            return None

        def _compute_keyspace_dictionary_meta(wl_name, rules_list, wl_meta, rule_meta):
            wl_count = _line_count(wl_meta, wl_name)
            # Non ricalcoliamo per evitare blocchi su dizionari grandi: se manca la metrica,
            # meglio segnalare errore e chiedere di ri‑sincronizzare il file.
            if wl_count is None:
                return None
            # Le rules non influiscono sullo split: vengono applicate dopo la distribuzione del dizionario.
            return wl_count

        def _node_weight(capabilities: dict) -> int:
            dtype = capabilities.get("device_type")
            if dtype == 2:
                return 4  # GPU peso maggiore
            if dtype == 3:
                return 3
            return 1  # CPU default

        def _compute_keyspace_mask(mask_name, mask_meta, hash_type_id):
            mask_path = _resolve_asset_path(mask_meta, mask_name)
            if not mask_path or not os.path.exists(mask_path):
                return None
            # Pre-carica le mask valide (senza commenti) per poter decidere rapidamente se usare hashcat --keyspace.
            try:
                with open(mask_path, encoding="utf-8", errors="backslashreplace") as fh:
                    mask_lines = [line.strip() for line in fh if line.strip() and not line.lstrip().startswith("#")]
            except Exception:
                return None
            if not mask_lines:
                return None
            # Evita di bloccare la UI: se il file contiene molte righe, usiamo il semplice conteggio delle mask.
            # Per file piccoli manteniamo il calcolo accurato tramite hashcat --keyspace (per base loop).
            if len(mask_lines) > 200:
                return len(mask_lines)
            total = 0
            bin_path = Hashcat.get_binary()
            for mask_line in mask_lines:
                cmd = [bin_path, "--keyspace", "-a", "3"]
                if hash_type_id is not None and hash_type_id != -1:
                    cmd += ["-m", str(hash_type_id)]
                cmd.append(mask_line)
                try:
                    res = Hashcat.run_hashcat(cmd)
                    if res.stdout:
                        total += int(res.stdout.strip())
                except HashcatExecutionError:
                    return len(mask_lines)  # fallback: distribuisci per numero di righe
                except Exception:
                    return len(mask_lines)
            return total if total > 0 else len(mask_lines)

        # Modalità standard: un singolo nodo, nessun Brain esplicito dalla UI.
        if node_name not in ("__brain_cluster__", "__distributed_split__"):
            node = get_object_or_404(Node, name=node_name)
            session_name = base_id
            brain_mode = 0  # Brain disabilitato quando si sceglie un singolo nodo

            try:
                hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
                node_info = hashcat_api.get_hashcat_info()
                if not node_info or node_info.get("response") == "error":
                    msg = node_info.get("message") if node_info else "Node did not return hashcat info"
                    messages.error(request, f"Unable to read node capabilities from {node_name}: {msg}")
                    return redirect('Hashcat:hashfiles')
                capabilities = summarize_capabilities(node_info)
                device_type = capabilities.get("device_type")
                if device_type is None:
                    messages.error(request, f"Unable to detect device type for node {node_name}; synchronize the node and try again.")
                    return redirect('Hashcat:hashfiles')
                if crack_type == "dictionary":
                    res = hashcat_api.create_dictionary_session(
                        session_name,
                        hashfile,
                        rule,
                        wordlist,
                        device_type,
                        brain_mode,
                        end_timestamp,
                        hashcat_debug_file,
                        kernel_optimized,
                    )
                elif crack_type == "mask":
                    res = hashcat_api.create_mask_session(
                        session_name,
                        hashfile,
                        mask,
                        device_type,
                        brain_mode,
                        end_timestamp,
                        hashcat_debug_file,
                        kernel_optimized,
                    )
                else:
                    res = {"response": "error", "message": "Unsupported cracking type"}
            except HashcatAPIError as exc:
                detail = ""
                if hasattr(exc, "body") and exc.body:
                    detail = f" (details: {exc.body[:200]})"
                messages.error(request, f"Node {node_name} not accessible: {exc}{detail}")
                return redirect('Hashcat:hashfiles')

            if not res or res.get("response") == "error":
                messages.error(request, res.get("message", "Node rejected session"))
                return redirect('Hashcat:hashfiles')

            session = Session(
                name=session_name,
                hashfile=hashfile,
                node=node,
                potfile_line_retrieved=0,
            )
            session.save()

            messages.success(request, "Session successfully created")

        # Modalità Brain cluster: crea una sessione per ogni nodo con Brain attivo.
        elif node_name == "__brain_cluster__":
            brain_mode = _brain_mode_for_hash(hashfile.hash_type)
            created = 0
            errors = []

            for node in Node.objects.all():
                try:
                    hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
                    info = hashcat_api.get_hashcat_info()
                except HashcatAPIError as exc:
                    errors.append(f"Node {node.name} not accessible: {exc}")
                    continue

                if not info or info.get("response") != "ok":
                    errors.append(f"Node {node.name} did not return hashcat info")
                    continue

                if not info.get("brain_enabled"):
                    # Nodo non configurato per Brain: viene ignorato in questo cluster.
                    continue

                if not info.get("brain_host_set"):
                    errors.append(f"Node {node.name} has Brain enabled but no host detected; retry after WebHashcat has contacted it or set [Brain].host")
                    continue

                capabilities = summarize_capabilities(info)
                device_type = capabilities.get("device_type")
                if device_type is None:
                    errors.append(f"Node {node.name} did not report a usable device type")
                    continue

                session_name = f"{base_id}-{node.name}"

                try:
                    if crack_type == "dictionary":
                        res = hashcat_api.create_dictionary_session(
                            session_name,
                            hashfile,
                            rule,
                            wordlist,
                            device_type,
                            brain_mode,
                            end_timestamp,
                            hashcat_debug_file,
                            kernel_optimized,
                        )
                    elif crack_type == "mask":
                        res = hashcat_api.create_mask_session(
                            session_name,
                            hashfile,
                            mask,
                            device_type,
                            brain_mode,
                            end_timestamp,
                            hashcat_debug_file,
                            kernel_optimized,
                        )
                    else:
                        res = {"response": "error", "message": "Unsupported cracking type"}
                except HashcatAPIError as exc:
                    errors.append(f"Node {node.name} rejected cluster session: {exc}")
                    continue

                if not res or res.get("response") == "error":
                    errors.append(res.get("message", f"Node {node.name} rejected session"))
                    continue

                db_session = Session(
                    name=session_name,
                    hashfile=hashfile,
                    node=node,
                    potfile_line_retrieved=0,
                    cluster=base_id,
                )
                db_session.save()
                created += 1

            if created == 0:
                # Nessun nodo con Brain attivo ha accettato la sessione.
                if errors:
                    messages.error(request, "Unable to create Brain cluster: " + "; ".join(errors[:3]))
                else:
                    messages.error(request, "Unable to create Brain cluster: no Brain-enabled nodes available.")
                return redirect('Hashcat:hashfiles')

            if errors:
                messages.warning(request, f"Brain cluster created on {created} node(s); some nodes were skipped: " + "; ".join(errors[:3]))
            else:
                messages.success(request, f"Brain cluster created on {created} node(s)")

        # Modalità distributed split: divide il keyspace tra i nodi con Brain attivo (senza usare Brain client).
        else:
            nodes = []
            wordlists_meta = Hashcat.get_wordlists(detailed=True)
            rules_meta = Hashcat.get_rules(detailed=True)
            masks_meta = Hashcat.get_masks(detailed=True)
            for node in Node.objects.all():
                try:
                    api = HashcatAPI(node.hostname, node.port, node.username, node.password)
                    info = api.get_hashcat_info()
                except HashcatAPIError:
                    continue
                if info and info.get("brain_enabled"):
                    nodes.append((node, info))
            if not nodes:
                messages.error(request, "No Brain-enabled nodes available for distributed split.")
                return redirect('Hashcat:hashfiles')
            if crack_type == "dictionary":
                keyspace = _compute_keyspace_dictionary_meta(wordlist, selected_rules or [], wordlists_meta, rules_meta)
            else:
                keyspace = _compute_keyspace_mask(mask, masks_meta, hashfile.hash_type)
            if not keyspace or keyspace <= 0:
                messages.error(request, "Unable to compute keyspace for distributed split; aborting.")
                return redirect('Hashcat:hashfiles')
            weighted_nodes = []
            total_weight = 0
            for node, info in nodes:
                caps = summarize_capabilities(info)
                w = _node_weight(caps)
                if w <= 0:
                    w = 1
                total_weight += w
                weighted_nodes.append((node, info, w))
            if total_weight <= 0:
                messages.error(request, "Unable to compute weights for split nodes.")
                return redirect('Hashcat:hashfiles')
            base_chunk = keyspace // total_weight
            remainder = keyspace - (base_chunk * total_weight)
            created = 0
            errors = []
            brain_mode = 0
            skip_value = 0
            for idx, (node, info, weight) in enumerate(weighted_nodes):
                limit_value = base_chunk * weight
                if idx == len(weighted_nodes) - 1:
                    limit_value += remainder
                session_name = f"{base_id}-{node.name}"
                try:
                    hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
                    if crack_type == "dictionary":
                        res = hashcat_api.create_dictionary_session(
                            session_name,
                            hashfile,
                            rule,
                            wordlist,
                            info.get("device_type"),
                            brain_mode,
                            end_timestamp,
                            hashcat_debug_file,
                            kernel_optimized,
                            skip=skip_value,
                            limit=limit_value,
                        )
                    else:
                        res = hashcat_api.create_mask_session(
                            session_name,
                            hashfile,
                            mask,
                            info.get("device_type"),
                            brain_mode,
                            end_timestamp,
                            hashcat_debug_file,
                            kernel_optimized,
                            skip=skip_value,
                            limit=limit_value,
                        )
                except HashcatAPIError as exc:
                    errors.append(f"Node {node.name} rejected split session: {exc}")
                    continue
                if not res or res.get("response") == "error":
                    errors.append(res.get("message", f"Node {node.name} rejected session"))
                    continue
                db_session = Session(
                    name=session_name,
                    hashfile=hashfile,
                    node=node,
                    potfile_line_retrieved=0,
                    cluster=base_id,
                )
                db_session.save()
                created += 1
                skip_value += limit_value
            if created == 0:
                messages.error(request, "Unable to create distributed split cluster: " + "; ".join(errors[:3]))
                return redirect('Hashcat:hashfiles')
            if errors:
                messages.warning(request, f"Distributed split created on {created} node(s); some nodes were skipped: " + "; ".join(errors[:3]))
            else:
                messages.success(request, f"Distributed split created on {created} node(s)")

    return redirect('Hashcat:hashfiles')


@login_required
@staff_member_required
def upload_rule(request):
    if request.method == 'POST':
        files = request.FILES.getlist("file")
        for f in files:
            name = f.name
            lower = name.lower()
            if not lower.endswith((".rule", ".txt")):
                messages.error(request, f"Invalid rule extension for {name}. Allowed: .rule, .txt")
                continue
            Hashcat.upload_rule(name, f.read())
    return redirect('Hashcat:files')


@login_required
@staff_member_required
def upload_mask(request):
    if request.method == 'POST':
        files = request.FILES.getlist("file")
        for f in files:
            name = f.name
            lower = name.lower()
            if not lower.endswith((".hcmask", ".txt")):
                messages.error(request, f"Invalid mask extension for {name}. Allowed: .hcmask, .txt")
                continue
            Hashcat.upload_mask(name, f.read())
    return redirect('Hashcat:files')


@login_required
@staff_member_required
def upload_wordlist(request):
    if request.method == 'POST':
        files = request.FILES.getlist("file")
        allowed_ext = (".gz", ".zip", ".wordlist", ".txt", ".list")
        ext_candidates = [".gz", ".zip"]
        for f in files:
            name = f.name.replace(" ", "_")
            lower = name.lower()
            if not lower.endswith(allowed_ext):
                messages.error(request, f"Invalid wordlist extension for {name}. Allowed: .txt, .list, .wordlist, .zip, .gz")
                continue
            base = name
            ext = ""
            for cand in ext_candidates:
                if name.endswith(cand):
                    base = name[: -len(cand)]
                    ext = cand
                    break
            else:
                base, _ = os.path.splitext(name)

            if not base.endswith(".wordlist"):
                base = f"{base}.wordlist"
            final_name = base + ext
            Hashcat.upload_wordlist(final_name, f.read())
    return redirect('Hashcat:files')


@login_required
def hashfile(request, hashfile_id, error_msg=''):
    context = {}
    context["Section"] = "Hashfile"

    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    # Check if the user owns the Hashfile or Staff
    if request.user != hashfile.owner and not request.user.is_staff:
        raise Http404("You do not have permission to view this object")

    context['hashfile'] = hashfile
    context['lines'] = humanize.intcomma(hashfile.line_count)
    context['recovered'] = "%s (%.2f%%)" % (humanize.intcomma(hashfile.cracked_count),
                                            hashfile.cracked_count / hashfile.line_count * 100) if hashfile.line_count != 0 else "0"
    context['hash_type'] = "Plaintext" if hashfile.hash_type == -1 else Hashcat.get_hash_types()[hashfile.hash_type][
        "name"]

    template = loader.get_template('Hashcat/hashfile.html')
    return HttpResponse(template.render(context, request))


@login_required
def export_cracked(request, hashfile_id):
    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    # Check if the user owns the Hashfile or Staff
    if request.user != hashfile.owner and not request.user.is_staff:
        raise Http404("You do not have permission to view this object")

    cracked_hashes = Hash.objects.filter(hashfile_id=hashfile.id, password__isnull=False)

    if hashfile.username_included:
        response = StreamingHttpResponse(("%s:%s\n" % (item.username, item.password) for item in cracked_hashes),
                                         content_type="text/txt")
    else:
        response = StreamingHttpResponse(("%s:%s\n" % (item.hash, item.password) for item in cracked_hashes),
                                         content_type="text/txt")

    response['Content-Disposition'] = 'attachment; filename="cracked.txt"'
    return response


@login_required
def export_uncracked(request, hashfile_id):
    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    # Check if the user owns the Hashfile or Staff
    if request.user != hashfile.owner and not request.user.is_staff:
        raise Http404("You do not have permission to view this object")

    uncracked_hashes = Hash.objects.filter(hashfile_id=hashfile.id, password__isnull=True)

    if hashfile.username_included:
        response = StreamingHttpResponse(("%s:%s\n" % (item.username, item.hash) for item in uncracked_hashes),
                                         content_type="text/txt")
    else:
        response = StreamingHttpResponse(("%s\n" % (item.hash,) for item in uncracked_hashes), content_type="text/txt")

    response['Content-Disposition'] = 'attachment; filename="uncracked.txt"'
    return response


@login_required
def csv_masks(request, hashfile_id):
    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    # Check if the user owns the Hashfile or Staff
    if request.user != hashfile.owner and not request.user.is_staff:
        raise Http404("You do not have permission to view this object")

    # didn't found the correct way in pure django...
    rows = Hash.objects.raw(
        "SELECT 1 AS id, MAX(password_mask) AS password_mask, COUNT(*) AS count FROM Hashcat_hash WHERE hashfile_id=%s AND password_mask IS NOT NULL GROUP BY password_mask ORDER BY count DESC",
        [hashfile.id])

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)

    response = StreamingHttpResponse((writer.writerow([item.password_mask, item.count]) for item in rows),
                                     content_type="text/csv")

    response['Content-Disposition'] = 'attachment; filename="masks.csv"'
    return response


@login_required
def export_search(request, search_id):
    search = get_object_or_404(Search, id=search_id)

    # Check if the user owns the Hashfile or Staff
    if request.user != search.owner and not request.user.is_staff:
        raise Http404("You do not have permission to view this object")

    response = FileResponse(open(search.output_file, 'rb'), content_type="text/csv")

    response['Content-Disposition'] = 'attachment; filename="search.csv"'
    return response
