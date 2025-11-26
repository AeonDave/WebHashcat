import base64
import hashlib
import json
import logging
import os
import random
import string
import traceback
from pathlib import Path

from flask import Flask, request, make_response, jsonify
from flask_compress import Compress
from flask_httpauth import HTTPBasicAuth

try:  # Support package-relative imports when HashcatNode is a module
    from .hashcat import Hashcat  # type: ignore
except ImportError:  # pragma: no cover - fallback for direct execution
    try:
        from HashcatNode.hashcat import Hashcat  # type: ignore
    except ImportError:
        from hashcat import Hashcat

auth = HTTPBasicAuth()
LOGGER = logging.getLogger(__name__)


@auth.verify_password
def verify_password(username, password):
    global httpauth_user
    global httpauth_hash
    if username == httpauth_user and httpauth_hash == hashlib.sha256(password.encode()).hexdigest():
        return username
    return None


class Server:

    def __init__(self, host, port, auth_user, auth_hash, hash_directory, cert_path, key_path):
        self._host = host
        self._port = int(port)
        self._app = Flask(__name__)
        Compress(self._app)
        self._route()

        global httpauth_user
        global httpauth_hash
        httpauth_user = auth_user
        httpauth_hash = auth_hash

        self.hash_directory = hash_directory
        self._cert_path = cert_path
        self._key_path = key_path

    def _update_brain_host_from_request(self) -> None:
        """Auto-detect Brain host from the caller when Brain is enabled.

        If [Brain].enabled is true and no host has been configured yet,
        we treat the remote address of the incoming WebHashcat request as
        the Brain server host. This keeps node configuration minimal: only
        ``enabled``, ``port`` and ``password`` are required in settings.ini.
        """

        try:
            brain_cfg = getattr(Hashcat, "brain", None)
        except Exception:  # pragma: no cover - extremely defensive
            return

        if not isinstance(brain_cfg, dict):
            return

        enabled = str(brain_cfg.get("enabled", "false")).lower() == "true"
        if not enabled:
            return

        current_host = str(brain_cfg.get("host", "") or "").strip()
        if current_host:
            # Respect an explicit host (from settings.ini or previous detection).
            return

        hinted_host = str(request.headers.get("X-Hashcat-Brain-Host", "") or "").strip()
        if hinted_host:
            brain_cfg["host"] = hinted_host
            Hashcat.brain = brain_cfg
            LOGGER.info("Auto-detected Brain host from header: %s", hinted_host)
            return

        # Prefer an explicit X-Forwarded-For header if present (behind proxies),
        # otherwise fall back to the direct remote address.
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else request.remote_addr

        if not client_ip:
            return

        brain_cfg["host"] = client_ip
        Hashcat.brain = brain_cfg
        LOGGER.info("Auto-detected Brain host from incoming request: %s", client_ip)

    def _route(self):
        self._app.add_url_rule("/hashcatInfo", "hashcatInfo", self._hashcatInfo, methods=["GET"])
        self._app.add_url_rule("/sessionInfo/<session_name>", "sessionInfo", self._sessionInfo, methods=["GET"])
        self._app.add_url_rule("/hashcatOutput/<session_name>", "hashcatOutput", self._hashcatOutput, methods=["GET"])
        self._app.add_url_rule("/hashes/<session_name>", "hashes", self._hashes, methods=["GET"])
        self._app.add_url_rule("/getPotfile/<session_name>/<from_line>", "getPotfile", self._get_potfile,
                               methods=["GET"])
        self._app.add_url_rule("/cracked/<session_name>", "cracked", self._cracked, methods=["GET"])
        self._app.add_url_rule("/createSession", "createSession", self._createSession, methods=["POST"])
        self._app.add_url_rule("/removeSession/<session_name>", "removeSession", self._removeSession, methods=["GET"])
        self._app.add_url_rule("/action", "action", self._action, methods=["POST"])
        self._app.add_url_rule("/uploadRule", "uploadRule", self._upload_rule, methods=["POST"])
        self._app.add_url_rule("/uploadMask", "uploadMask", self._upload_mask, methods=["POST"])
        self._app.add_url_rule("/uploadWordlist", "uploadWordlist", self._upload_wordlist, methods=["POST"])
        self._app.add_url_rule("/deleteRule", "deleteRule", self._delete_rule, methods=["POST"])
        self._app.add_url_rule("/deleteMask", "deleteMask", self._delete_mask, methods=["POST"])
        self._app.add_url_rule("/deleteWordlist", "deleteWordlist", self._delete_wordlist, methods=["POST"])
        self._app.add_url_rule("/deleteHashfile", "deleteHashfile", self._delete_hashfile, methods=["POST"])
        self._app.add_url_rule("/compareAssets", "compareAssets", self._compare_assets, methods=["POST"])

    def start_server(self):
        context = (self._cert_path, self._key_path)
        LOGGER.info("Starting HTTPS server on %s:%s using cert=%s key=%s", self._host, self._port, self._cert_path,
                    self._key_path)
        self._app.run(host=self._host, port=self._port, ssl_context=context, threaded=True)

    """
        Returns a json containing the following informations about the running hashcat process:
            - Version
            - Hash types supported
            - Available rules
            - Available masks
            - Available wordlists
            - Sessions :
                - Name
                - Status
                - Cracking type (rules, mask)
                - % cracked
                - % progress
    """

    @auth.login_required
    def _hashcatInfo(self):
        try:
            # Learn Brain host from the first authenticated call, if needed.
            self._update_brain_host_from_request()

            hash_types = [Hashcat.hash_modes[idx] for idx in sorted(Hashcat.hash_modes.keys())]
            rules = Hashcat.rules
            masks = Hashcat.masks
            wordlists = Hashcat.wordlists
            sessions = []
            for session in Hashcat.sessions.values():
                sessions.append({
                    "name": session.name,
                    "status": session.session_status,
                    "crack_type": session.crack_type,
                    "progress": session.progress,
                })

            brain_enabled = str(Hashcat.brain.get("enabled", "false")).lower() == "true"
            brain_host = str(Hashcat.brain.get("host", "") or "").strip()

            result = {
                "response": "ok",
                "version": Hashcat.version,
                "system": Hashcat.get_system_info(),
                "hash_types": hash_types,
                "rules": rules,
                "masks": masks,
                "sessions": sessions,
                "wordlists": wordlists,
                "device_type": Hashcat.default_device_type,
                # Expose Brain enablement so the Web UI can build Brain clusters.
                "brain_enabled": brain_enabled,
                "brain_host_set": brain_enabled and bool(brain_host),
            }

            return json.dumps(result)
        except Exception as e:
            traceback.print_exc()

            return json.dumps({
                "response": "error",
                "message": str(e),
            })

    """
        Returns information about a specific session :
            - Name
            - Cracking type (rule, mask)
            - Status
            - Time started
            - Estimated time (rule based attack only)
            - Speed
            - Recovered
            - Progress (%)
            - Cracked hashes (results)
            - Top 10 passwords cracked
            - Password lengths
            - Password charsets
    """

    @auth.login_required
    def _sessionInfo(self, session_name):
        try:

            result = Hashcat.sessions[session_name].details()
            result["response"] = "ok"

            return json.dumps(result)
        except Exception as e:
            traceback.print_exc()

            return json.dumps({
                "response": "error",
                "message": str(e),
            })

    """
        Returns session hashcat output
    """

    @auth.login_required
    def _hashcatOutput(self, session_name):
        try:
            result = {}

            result["hashcat_output"] = Hashcat.sessions[session_name].hashcat_output()
            result["response"] = "ok"

            return json.dumps(result)
        except Exception as e:
            traceback.print_exc()

            return json.dumps({
                "response": "error",
                "message": str(e),
            })

    """
        Returns session hashes
    """

    @auth.login_required
    def _hashes(self, session_name):
        try:
            result = {}

            result["hashes"] = Hashcat.sessions[session_name].hashes()
            result["response"] = "ok"

            return json.dumps(result)
        except Exception as e:
            traceback.print_exc()

            return json.dumps({
                "response": "error",
                "message": str(e),
            })

    """
        Returns the potfile starting from a specific line
    """

    @auth.login_required
    def _get_potfile(self, session_name, from_line):
        from_line = int(from_line)
        try:
            result = Hashcat.sessions[session_name].get_potfile(from_line)
            result["response"] = "ok"

            return json.dumps(result)
        except Exception as e:
            traceback.print_exc()

            return json.dumps({
                "response": "error",
                "message": str(e),
            })

    """
        Returns the cracked passwords
    """

    @auth.login_required
    def _cracked(self, session_name):
        try:
            cracked = Hashcat.sessions[session_name].cracked()

            return json.dumps({
                "response": "ok",
                "cracked": cracked,
            })
        except Exception as e:
            traceback.print_exc()

            return json.dumps({
                "response": "error",
                "message": str(e),
            })

    """
        Create a new session, the input should be the following :
            - name: name of the session
            - crack_type: rule or mask
            - hashes: hashes to crack
            - hash_mode_id: hash type
            - wordlist: wordlist file to use (if rule-based attack)
            - rule: rule file to use (if rule-based attack)
            - mask: mask file to use (if mask-based attack)
            - username_included: is the username before the hashes ? (True/False)
    """

    @auth.login_required
    def _createSession(self):
        try:
            # Ensure Brain host is initialised before we schedule a new session.
            self._update_brain_host_from_request()

            data = json.loads(request.form.get('json'))

            random_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))
            hash_dir = Path(self.hash_directory)
            hash_file = hash_dir / f"{data['name']}_{random_name}.list"

            file = request.files['file']
            file.save(str(hash_file))

            Hashcat.create_session(
                data["name"],
                data["crack_type"],
                hash_file,
                int(data["hash_mode_id"]),
                data["wordlist"] if "wordlist" in data else None,
                data["rule"] if "rule" in data else None,
                data["mask"] if "mask" in data else None,
                data["username_included"],
                Hashcat.default_device_type,
                int(data["brain_mode"]),
                int(data["end_timestamp"]) if data["end_timestamp"] != None else None,
                data["hashcat_debug_file"],
                str(data.get("kernel_optimized", "")).lower() in {"true", "1", "on", "yes"},
            )

            res = {"response": "ok"}

            return json.dumps(res)
        except Exception as e:
            traceback.print_exc()

            return json.dumps({
                "response": "error",
                "message": str(e),
            })

    """
        Delete a session
    """

    @auth.login_required
    def _removeSession(self, session_name):
        try:
            Hashcat.remove_session(session_name)

            res = {"response": "ok"}

            return json.dumps(res)
        except Exception as e:
            traceback.print_exc()

            return json.dumps({
                "response": "error",
                "message": str(e),
            })

    """
        Send an action to a session:
        Parameters are :
            - session: session name
            - action: start, update, pause, resume, quit or remove
    """

    @auth.login_required
    def _action(self):
        try:
            # Sessions may be started by this endpoint; make sure Brain host is set.
            self._update_brain_host_from_request()

            data = json.loads(request.data.decode())

            if data["action"] == "start":
                Hashcat.sessions[data["session"]].start()
            if data["action"] == "update":
                Hashcat.sessions[data["session"]].update()
            if data["action"] == "pause":
                Hashcat.sessions[data["session"]].pause()
            if data["action"] == "resume":
                Hashcat.sessions[data["session"]].resume()
            if data["action"] == "quit":
                Hashcat.sessions[data["session"]].quit()
            if data["action"] == "remove":
                Hashcat.remove_session(data["session"])

            res = {"response": "ok"}

            return json.dumps(res)
        except Exception as e:
            traceback.print_exc()

            return json.dumps({
                "response": "error",
                "message": str(e),
            })

    """
        Upload a new rule file
        Parameters are:
            - name: rule file name
            - rules: content of the file
    """

    @auth.login_required
    def _upload_rule(self):
        try:
            data = json.loads(request.data.decode())

            Hashcat.upload_rule(data["name"], base64.b64decode(data["rules"]))

            res = {"response": "ok"}

            return json.dumps(res)
        except Exception as e:
            traceback.print_exc()

            return json.dumps({
                "response": "error",
                "message": str(e),
            })

    """
        Upload a new mask file
        Parameters are:
            - name: mask file name
            - masks: content of the file
    """

    @auth.login_required
    def _upload_mask(self):
        try:
            data = json.loads(request.data.decode())

            Hashcat.upload_mask(data["name"], base64.b64decode(data["masks"]))

            res = {"response": "ok"}

            return json.dumps(res)
        except Exception as e:
            traceback.print_exc()

            return json.dumps({
                "response": "error",
                "message": str(e),
            })

    @auth.login_required
    def _delete_rule(self):
        try:
            data = request.get_json(force=True, silent=True) or request.form
            name = data.get("name")
            if not name:
                raise ValueError("Missing rule name")
            Hashcat.remove_rule(name)
            return json.dumps({"response": "ok"})
        except Exception as e:
            traceback.print_exc()
            return json.dumps({"response": "error", "message": str(e)})

    @auth.login_required
    def _delete_mask(self):
        try:
            data = request.get_json(force=True, silent=True) or request.form
            name = data.get("name")
            if not name:
                raise ValueError("Missing mask name")
            Hashcat.remove_mask(name)
            return json.dumps({"response": "ok"})
        except Exception as e:
            traceback.print_exc()
            return json.dumps({"response": "error", "message": str(e)})

    @auth.login_required
    def _delete_wordlist(self):
        try:
            data = request.get_json(force=True, silent=True) or request.form
            name = data.get("name")
            if not name:
                raise ValueError("Missing wordlist name")
            Hashcat.remove_wordlist(name)
            return json.dumps({"response": "ok"})
        except Exception as e:
            traceback.print_exc()
            return json.dumps({"response": "error", "message": str(e)})

    @auth.login_required
    def _delete_hashfile(self):
        try:
            data = request.get_json(force=True, silent=True) or request.form
            name = data.get("name")
            if not name:
                raise ValueError("Missing hashfile name")
            Hashcat.remove_hashfile(name)
            return json.dumps({"response": "ok"})
        except Exception as e:
            traceback.print_exc()
            return json.dumps({"response": "error", "message": str(e)})

    @auth.login_required
    def _compare_assets(self):
        """
        Compare provided manifest {rules:{name:md5}, masks:{...}, wordlists:{...}, hashfiles:[...]}
        Deletes remote assets not present in the manifest.
        Returns lists of items needing upload (missing or md5 mismatch).
        """
        try:
            manifest = request.get_json(force=True, silent=True) or {}
            missing = {"rules": [], "masks": [], "wordlists": [], "hashfiles": []}

            # Rules
            remote_rules = Hashcat.rules
            local_rules = manifest.get("rules", {})
            for name, md5 in local_rules.items():
                if name not in remote_rules or remote_rules[name].get("md5") != md5:
                    missing["rules"].append(name)
            for extra in set(remote_rules.keys()) - set(local_rules.keys()):
                Hashcat.remove_rule(extra)

            # Masks
            remote_masks = Hashcat.masks
            local_masks = manifest.get("masks", {})
            for name, md5 in local_masks.items():
                if name not in remote_masks or remote_masks[name].get("md5") != md5:
                    missing["masks"].append(name)
            remote_mask_names = set(remote_masks.keys())
            for extra in set(os.listdir(Hashcat.mask_dir)) - set(local_masks.keys()):
                if extra == ".gitkeep":
                    continue
                Hashcat.remove_mask(extra)

            # Wordlists
            remote_wordlists = Hashcat.wordlists
            local_wordlists = manifest.get("wordlists", {})
            for name, md5 in local_wordlists.items():
                if name not in remote_wordlists or remote_wordlists[name].get("md5") != md5:
                    missing["wordlists"].append(name)
            for extra in set(os.listdir(Hashcat.wordlist_dir)) - set(local_wordlists.keys()):
                if extra == ".gitkeep":
                    continue
                Hashcat.remove_wordlist(extra)

            # Hashfiles: do not prune here because session-specific copies have
            # randomised names (hashcat creates a new .list per session). Just
            # report which manifest entries are missing, leaving all existing
            # files untouched.
            local_hashfiles = set(manifest.get("hashfiles", []))
            try:
                remote_hashfiles = set(os.listdir(Hashcat.hash_dir))
            except Exception:
                remote_hashfiles = set()
            for name in local_hashfiles:
                if name not in remote_hashfiles:
                    missing["hashfiles"].append(name)

            return json.dumps({"response": "ok", "missing": missing})
        except Exception as e:
            traceback.print_exc()
            return json.dumps({"response": "error", "message": str(e)})

    """
        Upload a new wordlist file
        Parameters are:
            - name: wordlist file name
            - wordlists: content of the file
    """

    @auth.login_required
    def _upload_wordlist(self):
        try:
            allowed_ext = (".wordlist", ".gz", ".zip", ".txt", ".list")
            # Raw stream upload (preferred for very large files)
            if request.mimetype == "application/octet-stream":
                name = request.args.get("name") or request.form.get("name")
                if not name:
                    raise ValueError("Missing name for raw upload")
                if not name.lower().endswith(allowed_ext):
                    raise ValueError("Invalid wordlist extension")
                Hashcat.upload_wordlist_stream(name, request.stream)
            else:
                payload = self._parse_upload_payload(request, "wordlists")
                if isinstance(payload, tuple) and hasattr(payload[1], "read"):
                    name, file_obj = payload
                    if not name.lower().endswith(allowed_ext):
                        raise ValueError("Invalid wordlist extension")
                    Hashcat.upload_wordlist_stream(name, file_obj)
                elif isinstance(payload, tuple):
                    name, raw_bytes = payload
                    if not name.lower().endswith(allowed_ext):
                        raise ValueError("Invalid wordlist extension")
                    Hashcat.upload_wordlist(name, raw_bytes)
                else:
                    raise ValueError("Invalid payload for wordlist upload")

            res = {"response": "ok"}
            response = make_response(jsonify(res))
            if name.endswith((".gz", ".zip", ".7z")):
                response.headers["Content-Encoding"] = "identity"
            return response
        except Exception as e:
            traceback.print_exc()

            response = make_response(json.dumps({
                "response": "error",
                "message": str(e),
            }))
            response.headers["Content-Encoding"] = "identity"
            return response

    def _parse_upload_payload(self, request_obj, field_name: str):
        """
        Accept both JSON (base64 encoded) and multipart form uploads.
        Returns (name, bytes_payload) or (name, file_obj).
        """
        try:
            data = request_obj.get_json(silent=True)
        except Exception:
            data = None

        if data and field_name in data:
            name = data.get("name")
            payload_b64 = data.get(field_name)
            return name, base64.b64decode(payload_b64)

        # multipart/form-data
        try:
            if field_name in request_obj.files:
                file_obj = request_obj.files[field_name]
                name = request_obj.form.get("name", file_obj.filename)
                file_obj.stream.seek(0)
                return name, file_obj
        except Exception as exc:
            raise exc

        # Fallback to raw body decoding
        if request_obj.data:
            raw = json.loads(request_obj.data.decode())
            name = raw.get("name")
            return name, base64.b64decode(raw[field_name])

        raise ValueError("No upload payload provided")
