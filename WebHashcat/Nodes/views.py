from operator import itemgetter

from Utils.hashcat import Hashcat
from Utils.hashcatAPI import HashcatAPI, HashcatAPIError
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.shortcuts import redirect
from django.template import loader

from .models import Node

@login_required
@staff_member_required
def nodes(request, error_msg=""):
    context = {}
    context["Section"] = "Nodes"

    if len(error_msg) != 0:
        context["error_message"] = error_msg

    node_rows = []
    local_rules = Hashcat.get_rules()
    local_masks = Hashcat.get_masks()
    local_wordlists = Hashcat.get_wordlists()

    def _is_synced(remote, local_items):
        for item in local_items:
            name = item["name"]
            remote_item = remote.get(name)
            if not remote_item:
                return False
            if remote_item.get("md5") != item.get("md5"):
                return False
        return True

    for node in Node.objects.all():
        status = {"state": "unknown", "label": "Unknown"}
        try:
            api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            info = api.get_hashcat_info()
            if info.get("response") == "ok":
                rules_ok = _is_synced(info.get("rules", {}), local_rules)
                masks_ok = _is_synced(info.get("masks", {}), local_masks)
                wordlists_ok = _is_synced(info.get("wordlists", {}), local_wordlists)
                if rules_ok and masks_ok and wordlists_ok:
                    status = {"state": "ok", "label": "Synced"}
                else:
                    status = {"state": "stale", "label": "Needs sync"}
            else:
                status = {"state": "error", "label": info.get("message", "Error")}
        except HashcatAPIError:
            status = {"state": "error", "label": "Unreachable"}
        node_rows.append({
            "obj": node,
            "status": status,
        })

    context["node_rows"] = node_rows

    template = loader.get_template('Nodes/nodes.html')
    return HttpResponse(template.render(context, request))


@login_required
@staff_member_required
def node(request, node_name, error_msg=""):
    context = {}
    context["Section"] = "Nodes"

    if len(error_msg) != 0:
        context["error_message"] = error_msg

        template = loader.get_template('Nodes/node.html')
        return HttpResponse(template.render(context, request))

    node_item = get_object_or_404(Node, name=node_name)

    context["node_name"] = node_item.name
    context["hostname"] = node_item.hostname
    context["port"] = node_item.port

    if request.method == 'POST':
        if request.POST["action"] == "synchronize":

            try:
                hashcat_api = HashcatAPI(node_item.hostname, node_item.port, node_item.username, node_item.password)
                # Build manifest of local assets and let node compare/delete extras
                rule_list = Hashcat.get_rules()
                mask_list = Hashcat.get_masks()
                wordlist_list = Hashcat.get_wordlists()
                manifest = {
                    "rules": {r["name"]: r.get("md5") for r in rule_list},
                    "masks": {m["name"]: m.get("md5") for m in mask_list},
                    "wordlists": {w["name"]: w.get("md5") for w in wordlist_list},
                }
                compare_res = hashcat_api.compare_assets(manifest)
            except HashcatAPIError as exc:
                return node(request, node_name, error_msg=f"Unable to synchronize node: {exc}")

            if compare_res.get("response") != "ok":
                return node(request, node_name, error_msg=compare_res.get("message", "Node returned an error"))

            missing = compare_res.get("missing", {"rules": [], "masks": [], "wordlists": []})

            for rule in rule_list:
                if rule["name"] in missing.get("rules", []):
                    with open(rule["path"], 'rb') as fh:
                        hashcat_api.upload_rule(rule["name"], fh.read())

            for mask in mask_list:
                if mask["name"] in missing.get("masks", []):
                    with open(mask["path"], 'rb') as fh:
                        hashcat_api.upload_mask(mask["name"], fh.read())

            for wordlist in wordlist_list:
                if wordlist["name"] in missing.get("wordlists", []):
                    with open(wordlist["path"], 'rb') as fh:
                        hashcat_api.upload_wordlist(wordlist["name"], fh)
            # After sync, redirect to GET to avoid stale context and show fresh data
            return redirect('Nodes:node', node_name)

    try:
        hashcat_api = HashcatAPI(node_item.hostname, node_item.port, node_item.username, node_item.password)
        node_data = hashcat_api.get_hashcat_info()
        if node_data.get("response") == "error":
            return node(request, node_name, error_msg=node_data.get("message", "Unknown node error"))
    except HashcatAPIError as exc:
        return nodes(request,
                     error_msg=f"Unable to connect to node {node_item.name} at: {node_item.hostname}:{node_item.port} ({exc})")

    rule_list = Hashcat.get_rules()
    mask_list = Hashcat.get_masks()
    wordlist_list = Hashcat.get_wordlists()

    for rule in rule_list:
        if not rule["name"] in node_data["rules"]:
            rule["synchro"] = False
        elif node_data["rules"][rule["name"]]["md5"] != rule["md5"]:
            rule["synchro"] = False
        else:
            rule["synchro"] = True

    for mask in mask_list:
        if not mask["name"] in node_data["masks"]:
            mask["synchro"] = False
        elif node_data["masks"][mask["name"]]["md5"] != mask["md5"]:
            mask["synchro"] = False
        else:
            mask["synchro"] = True

    for wordlist in wordlist_list:
        if not wordlist["name"] in node_data["wordlists"]:
            wordlist["synchro"] = False
        elif node_data["wordlists"][wordlist["name"]]["md5"] != wordlist["md5"]:
            wordlist["synchro"] = False
        else:
            wordlist["synchro"] = True

    hash_type_list = sorted(node_data["hash_types"], key=itemgetter('id'))

    context["version"] = node_data["version"]
    context["system"] = node_data.get("system", {})
    context["rule_list"] = rule_list
    context["mask_list"] = mask_list
    context["wordlist_list"] = wordlist_list
    context["hash_type_list"] = hash_type_list

    template = loader.get_template('Nodes/node.html')
    return HttpResponse(template.render(context, request))


@login_required
@staff_member_required
def new_node(request):
    if request.method == 'POST':
        node_name = request.POST["name"]
        hostname = request.POST["hostname"]
        port = request.POST["port"]
        username = request.POST["username"]
        password = request.POST["password"]

        try:
            port = int(port)
        except ValueError:
            port = -1

        if port > 0 and port < 65636:
            Node.objects.update_or_create(name=node_name,
                                          defaults={
                                              'name': node_name,
                                              'hostname': hostname,
                                              'port': port,
                                              'username': username,
                                              'password': password,
                                          }
                                          )
        return redirect('Nodes:nodes')


@login_required
@staff_member_required
def delete_node(request, node_name):
    try:
        obj = Node.objects.get(name=node_name)
        obj.delete()
    except Node.DoesNotExist:
        pass

    return redirect('Nodes:nodes')
