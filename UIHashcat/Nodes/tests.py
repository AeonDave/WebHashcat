import base64
import hashlib
import io
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests
from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.http import HttpResponse
from django.test import TestCase
from django.urls import reverse

from Nodes.models import Node
from Utils.hashcatAPI import (
    HashcatAPI,
    HashcatAPIAuthError,
    HashcatAPINetworkError,
    HashcatAPIResponseError,
)


class NodeRegistrationTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("admin", password="pw123", is_staff=True)
        self.client.force_login(self.staff)

    def test_new_node_creates_record_with_expected_fields(self):
        payload = {
            "name": "gpu-1",
            "hostname": "hashcatnode",
            "port": "9999",
            "username": "node_user",
            "password": "secret",
        }

        response = self.client.post(reverse("Nodes:new_node"), payload)
        self.assertEqual(response.status_code, 302)

        node = Node.objects.get(name="gpu-1")
        self.assertEqual(node.hostname, "hashcatnode")
        self.assertEqual(node.port, 9999)
        self.assertEqual(node.username, "node_user")
        self.assertEqual(node.password, "secret")

    def test_invalid_port_rejected(self):
        payload = {
            "name": "gpu-2",
            "hostname": "hashcatnode",
            "port": "abc",
            "username": "node_user",
            "password": "secret",
        }

        self.client.post(reverse("Nodes:new_node"), payload)
        self.assertFalse(Node.objects.filter(name="gpu-2").exists())


class NodeSyncTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("admin", password="pw123", is_staff=True)
        self.client.force_login(self.staff)
        self.node = Node.objects.create(
            name="gpu-1",
            hostname="hashcatnode",
            port=9999,
            username="node_user",
            password="secret",
        )
        self._temp_files = []
        self.addCleanup(self._cleanup_temp_files)

    def _cleanup_temp_files(self):
        for path in self._temp_files:
            try:
                Path(path).unlink()
            except FileNotFoundError:
                pass

    def _write_temp_file(self, contents="data"):
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.write(contents.encode("utf-8"))
        handle.flush()
        handle.close()
        self._temp_files.append(handle.name)
        return handle.name

    def _asset_lists(self):
        rule_file = self._write_temp_file("rule-data")
        mask_file = self._write_temp_file("?u?l")
        wordlist_file = self._write_temp_file("password")
        return (
            [{"name": "common.rule", "md5": "md5-r", "path": rule_file}],
            [{"name": "basic.hcmask", "md5": "md5-m", "path": mask_file}],
            [{"name": "list.wordlist", "md5": "md5-w", "path": wordlist_file}],
        )

    @patch("Nodes.views.HashcatAPI")
    @patch("Nodes.views.Hashcat.get_wordlists")
    @patch("Nodes.views.Hashcat.get_masks")
    @patch("Nodes.views.Hashcat.get_rules")
    def test_synchronize_uploads_missing_assets(self, mock_rules, mock_masks, mock_wordlists, mock_api_cls):
        rule_list, mask_list, wordlist_list = self._asset_lists()
        mock_rules.return_value = rule_list
        mock_masks.return_value = mask_list
        mock_wordlists.return_value = wordlist_list

        node_data = {
            "response": "ok",
            "rules": {},
            "masks": {},
            "wordlists": {},
            "hash_types": [],
            "version": "1.0",
        }

        mock_api = MagicMock()
        mock_api.get_hashcat_info.return_value = node_data
        mock_api.compare_assets.return_value = {
            "response": "ok",
            "missing": {
                "rules": ["common.rule"],
                "masks": ["basic.hcmask"],
                "wordlists": ["list.wordlist"],
                "hashfiles": [],
            },
        }
        mock_api_cls.return_value = mock_api

        url = reverse("Nodes:node", args=[self.node.name])
        response = self.client.post(url, {"action": "synchronize"})
        self.assertEqual(response.status_code, 302)

        mock_api.upload_rule.assert_called_once()
        mock_api.upload_mask.assert_called_once()
        mock_api.upload_wordlist.assert_called_once()

    @patch("Nodes.views.nodes")
    @patch("Nodes.views.HashcatAPI")
    def test_connection_error_bubbles_up_as_nodes_error(self, mock_api_cls, mock_nodes_view):
        mock_api = MagicMock()
        mock_api.get_hashcat_info.side_effect = HashcatAPINetworkError("dial failed")
        mock_api_cls.return_value = mock_api

        mock_nodes_view.return_value = HttpResponse("nodes")

        response = self.client.get(reverse("Nodes:node", args=[self.node.name]))
        self.assertEqual(response.content, b"nodes")
        mock_nodes_view.assert_called_once()
        _, kwargs = mock_nodes_view.call_args
        self.assertIn("dial failed", kwargs["error_msg"])


class _FakeResponse:
    def __init__(self, *, status_code=200, text='{"response": "ok"}', ok=True, json_data=None):
        self.status_code = status_code
        self.text = text
        self.ok = ok
        self._json_data = json_data if json_data is not None else json.loads(text)

    def json(self):
        if isinstance(self._json_data, Exception):
            raise self._json_data
        return self._json_data


class HashcatAPITests(TestCase):
    def setUp(self):
        self.api = HashcatAPI("host", 9999, "user", "pass")

    @patch("Utils.hashcatAPI.requests.request")
    def test_send_get_uses_basic_auth_and_tls_disabled(self, mock_request):
        mock_request.return_value = _FakeResponse()

        self.api.send("/hashcatInfo")

        args, kwargs = mock_request.call_args
        self.assertEqual(args[0], "GET")
        self.assertEqual(args[1], "https://host:9999/hashcatInfo")
        self.assertFalse(kwargs["verify"])
        self.assertEqual(kwargs["timeout"], (1.0, 600.0))
        expected_key = base64.b64encode(b"user:pass").decode("ascii")
        self.assertEqual(kwargs["headers"]["Authorization"], f"Basic {expected_key}")

    @patch("Utils.hashcatAPI.requests.request")
    def test_send_post_passes_payload_json(self, mock_request):
        mock_request.return_value = _FakeResponse()
        payload = {"foo": "bar"}

        self.api.send("/action", data=payload)

        args, kwargs = mock_request.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], "https://host:9999/action")
        self.assertEqual(kwargs["data"], '{"foo": "bar"}')
        self.assertFalse(kwargs["verify"])
        self.assertEqual(kwargs["timeout"], (1.0, 600.0))
        self.assertIn("Authorization", kwargs["headers"])

    @patch("Utils.hashcatAPI.requests.request", side_effect=requests.exceptions.ConnectionError("boom"))
    def test_send_raises_network_error_on_connection_error(self, mock_request):
        with self.assertRaises(HashcatAPINetworkError):
            self.api.send("/hashcatInfo")

    @patch("Utils.hashcatAPI.requests.request")
    def test_send_raises_auth_error_on_unauthorized(self, mock_request):
        mock_request.return_value = _FakeResponse(status_code=401, ok=False)

        with self.assertRaises(HashcatAPIAuthError):
            self.api.send("/hashcatInfo")

    @patch("Utils.hashcatAPI.requests.request")
    def test_send_raises_response_error_on_bad_json(self, mock_request):
        mock_request.return_value = _FakeResponse(json_data=ValueError("not json"))

        with self.assertRaises(HashcatAPIResponseError):
            self.api.send("/hashcatInfo")

    @patch("Utils.hashcatAPI.requests.request")
    def test_post_file_uses_timeout_and_verify(self, mock_request):
        mock_request.return_value = _FakeResponse()

        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(b"hashes")
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))

        self.api.post_file("/create", {"name": "sess"}, tmp.name)

        args, kwargs = mock_request.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(kwargs["timeout"], (1.0, 600.0))
        self.assertFalse(kwargs["verify"])

    @patch("Utils.hashcatAPI.requests.request")
    def test_send_honors_trust_bundle_env(self, mock_request):
        mock_request.return_value = _FakeResponse()
        with patch.dict(os.environ, {"HASHCAT_TRUST_BUNDLE": "/tmp/bundle.pem"}):
            api = HashcatAPI("host", 9999, "user", "pass")
            api.send("/hashcatInfo")

        args, kwargs = mock_request.call_args
        self.assertEqual(kwargs["verify"], "/tmp/bundle.pem")


class RotateNodePasswordCommandTests(TestCase):
    def setUp(self):
        self.node = Node.objects.create(
            name="gpu-cred",
            hostname="hashcatnode",
            port=9999,
            username="node_user",
            password="old",
        )

    def test_rotate_by_name_updates_password_and_outputs_hash(self):
        output = io.StringIO()
        call_command(
            "rotate_node_passwords",
            "--node-name",
            self.node.name,
            "--password",
            "new-pass",
            stdout=output,
        )

        self.node.refresh_from_db()
        self.assertEqual(self.node.password, "new-pass")
        expected_hash = hashlib.sha256(b"new-pass").hexdigest()
        self.assertIn(expected_hash, output.getvalue())

    def test_rotate_missing_node_raises_error(self):
        with self.assertRaises(CommandError):
            call_command("rotate_node_passwords", "--node-id", "999")
