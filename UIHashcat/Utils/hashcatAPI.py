import base64
import json
import os
from typing import Optional, Tuple, Union

import requests
import urllib3
from django.db import transaction
from requests_toolbelt.multipart import encoder

from Utils.models import Lock

timeout_connection = float(os.environ.get("HASHCAT_API_CONNECT_TIMEOUT", 1))
timeout_read = float(os.environ.get("HASHCAT_API_READ_TIMEOUT", 60 * 10))
TIMEOUT: Tuple[float, float] = (timeout_connection, timeout_read)
TRUST_BUNDLE_ENV = "HASHCAT_TRUST_BUNDLE"
BRAIN_HOST_HINT = os.environ.get("HASHCAT_BRAIN_HOST", "").strip()


class HashcatAPIError(Exception):
    """Base exception for HashcatAPI failures."""


class HashcatAPINetworkError(HashcatAPIError):
    """Raised when the node cannot be reached or TLS setup fails."""


class HashcatAPIAuthError(HashcatAPIError):
    """Raised when the node rejects provided credentials."""


class HashcatAPIResponseError(HashcatAPIError):
    """Raised when the node returns an unexpected payload."""

    def __init__(self, message: str, *, status_code: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class HashcatAPI(object):

    def __init__(
            self,
            ip,
            port,
            username,
            password,
            *,
            verify: Optional[Union[str, bool]] = None,
            timeout: Optional[Tuple[float, float]] = None,
    ):
        self.ip = ip
        self.port = port
        self.key = base64.b64encode(("%s:%s" % (username, password)).encode("ascii")).decode("ascii")
        trust_bundle = os.environ.get(TRUST_BUNDLE_ENV)
        if verify is None:
            verify = trust_bundle if trust_bundle else False
        self.verify = verify
        self.timeout = timeout or TIMEOUT
        if self.verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get_hashcat_info(self):
        return self.send("/hashcatInfo")

    def create_dictionary_session(self, session_name, hashfile, rules, wordlist, device_type, brain_mode, end_timestamp,
                                  hashcat_debug_file, kernel_optimized=False):
        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)

        with transaction.atomic():

            hashfile_lock = Lock.objects.select_for_update().filter(hashfile_id=hashfile.id, lock_ressource="hashfile")[0]

            payload = {
                "name": session_name,
                "crack_type": "dictionary",
                "hash_mode_id": hashfile.hash_type,
                "rule": rules,
                "wordlist": wordlist,
                "username_included": False,
                "device_type": device_type,
                "brain_mode": brain_mode,
                "end_timestamp": end_timestamp,
                "hashcat_debug_file": hashcat_debug_file,
                "kernel_optimized": kernel_optimized,
            }

            res = self.post_file("/createSession", payload, hashfile_path)

            del hashfile_lock

        return res

    def create_mask_session(self, session_name, hashfile, mask, device_type, brain_mode, end_timestamp,
                            hashcat_debug_file, kernel_optimized=False):
        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)

        # lock
        with transaction.atomic():
            # Prevent hashfile from being modified while read 
            hashfile_lock = Lock.objects.select_for_update().filter(hashfile_id=hashfile.id, lock_ressource="hashfile")[
                0]

            payload = {
                "name": session_name,
                "crack_type": "mask",
                "hash_mode_id": hashfile.hash_type,
                "mask": mask,
                "username_included": False,
                "device_type": device_type,
                "brain_mode": brain_mode,
                "end_timestamp": end_timestamp,
                "hashcat_debug_file": hashcat_debug_file,
                "kernel_optimized": kernel_optimized,
            }

            res = self.post_file("/createSession", payload, hashfile_path)

            del hashfile_lock

        return res

    def action(self, session_name, action):
        payload = {
            "session": session_name,
            "action": action,
        }

        return self.send("/action", data=payload)

    def get_session_info(self, session_name):
        return self.send("/sessionInfo/%s" % session_name)

    def remove(self, session_name):
        return self.send("/removeSession/%s" % session_name)

    def get_cracked_file(self, session_name):
        return self.send("/cracked/%s" % session_name)

    def get_hashcat_output(self, session_name):
        return self.send("/hashcatOutput/%s" % session_name)

    def get_hashes(self, session_name):
        return self.send("/hashes/%s" % session_name)

    def get_potfile(self, session_name, from_line):
        return self.send("/getPotfile/%s/%d" % (session_name, from_line))

    def upload_rule(self, name, rule_file):
        payload = {
            "name": name,
            "rules": base64.b64encode(rule_file).decode(),
        }

        return self.send("/uploadRule", data=payload)

    def delete_rule(self, name):
        return self.send("/deleteRule", data={"name": name})

    def upload_mask(self, name, mask_file):
        payload = {
            "name": name,
            "masks": base64.b64encode(mask_file).decode(),
        }

        return self.send("/uploadMask", data=payload)

    def delete_mask(self, name):
        return self.send("/deleteMask", data={"name": name})

    def upload_wordlist(self, name, wordlist_file):
        headers = self._headers()
        # If a file-like is provided, stream as raw octet-stream with query param (no multipart parsing server-side).
        if hasattr(wordlist_file, "read"):
            headers["Content-Type"] = "application/octet-stream"
            response = self._perform_request(
                "POST",
                "/uploadWordlist",
                headers=headers,
                params={"name": name},
                data=wordlist_file,
                timeout=(5, None),
            )
            return self._parse_json(response)
        # If a path is provided, open and stream
        if isinstance(wordlist_file, str):
            with open(wordlist_file, "rb") as fh:
                headers["Content-Type"] = "application/octet-stream"
                response = self._perform_request(
                    "POST",
                    "/uploadWordlist",
                    headers=headers,
                    params={"name": name},
                    data=fh,
                    timeout=(5, None),
                )
                return self._parse_json(response)
        # Fallback to base64 for raw bytes
        payload = {
            "name": name,
            "wordlists": base64.b64encode(wordlist_file).decode(),
        }
        return self.send("/uploadWordlist", data=payload)

    def delete_wordlist(self, name):
        return self.send("/deleteWordlist", data={"name": name})

    def delete_hashfile(self, name):
        return self.send("/deleteHashfile", data={"name": name})

    def compare_assets(self, manifest: dict):
        return self.send("/compareAssets", data=manifest)

    def _build_url(self, path: str) -> str:
        return "https://%s:%d%s" % (self.ip, self.port, path)

    def _headers(self):
        headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Accept-Encoding": "text/plain",
            "Authorization": "Basic %s" % self.key,
        }
        # Hint Brain host only when explicitly configured (avoid leaking Docker-only hostnames to LAN nodes)
        if BRAIN_HOST_HINT and BRAIN_HOST_HINT.lower() not in {"webhashcat-brain", "brain"}:
            headers["X-Hashcat-Brain-Host"] = BRAIN_HOST_HINT
        return headers

    def _perform_request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = self._build_url(path)
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        try:
            response = requests.request(method, url, **kwargs)
        except requests.exceptions.SSLError as exc:
            raise HashcatAPINetworkError(f"TLS handshake failed for {url}: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            raise HashcatAPINetworkError(f"Unable to reach {url}: {exc}") from exc

        if response.status_code == 401:
            raise HashcatAPIAuthError("Node rejected supplied credentials")
        if response.status_code == 403:
            raise HashcatAPIAuthError("Access to node denied (HTTP 403)")
        if not response.ok:
            raise HashcatAPIResponseError(
                f"Node returned unexpected status {response.status_code}",
                status_code=response.status_code,
                body=response.text,
            )

        return response

    def _parse_json(self, response: requests.Response):
        try:
            return response.json()
        except ValueError as exc:
            raise HashcatAPIResponseError("Invalid JSON payload from node", body=response.text) from exc

    def send(self, url, data=None):
        headers = self._headers()
        if data is None:
            response = self._perform_request("GET", url, headers=headers)
        else:
            response = self._perform_request("POST", url, headers=headers, data=json.dumps(data))
        return self._parse_json(response)

    def post_file(self, url, data, filepath):
        headers = self._headers()
        with open(filepath, 'rb') as file_handle:
            form = encoder.MultipartEncoder({
                'json': (None, json.dumps(data), 'application/json'),
                'file': ("file", file_handle, 'application/octet-stream')
            })

            headers['Content-Type'] = form.content_type
            response = self._perform_request("POST", url, headers=headers, data=form)
        return self._parse_json(response)
