import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from HashcatNode import hashcatnode


class EnsureTlsMaterialTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.cert_path = Path(self.temp_dir.name) / "server.crt"
        self.key_path = Path(self.temp_dir.name) / "server.key"

    def test_returns_existing_cert_and_key_without_generating(self):
        self.cert_path.write_text("cert")
        self.key_path.write_text("key")

        with mock.patch("HashcatNode.hashcatnode.subprocess.run") as mock_run:
            cert, key = hashcatnode._ensure_tls_material(self.cert_path, self.key_path)

        self.assertEqual(cert, str(self.cert_path))
        self.assertEqual(key, str(self.key_path))
        mock_run.assert_not_called()

    def test_generates_cert_and_key_when_missing(self):
        def _fake_openssl(cmd, check):
            self.cert_path.write_text("generated cert")
            self.key_path.write_text("generated key")
            return mock.Mock()

        with mock.patch("HashcatNode.hashcatnode.subprocess.run", side_effect=_fake_openssl) as mock_run, \
                mock.patch("HashcatNode.hashcatnode.os.chmod") as mock_chmod:
            cert, key = hashcatnode._ensure_tls_material(self.cert_path, self.key_path)

        self.assertEqual(cert, str(self.cert_path))
        self.assertEqual(key, str(self.key_path))
        mock_run.assert_called_once()
        self.assertTrue(self.cert_path.exists())
        self.assertTrue(self.key_path.exists())
        mock_chmod.assert_called_once_with(self.key_path, 0o600)

    def test_tls_days_env_is_used(self):
        def _fake_openssl(cmd, check):
            self.cert_path.write_text("generated cert")
            self.key_path.write_text("generated key")
            return mock.Mock()

        with mock.patch("HashcatNode.hashcatnode.subprocess.run", side_effect=_fake_openssl) as mock_run, \
                mock.patch.dict(os.environ, {"HASHCATNODE_TLS_DAYS": "10"}, clear=False):
            hashcatnode._ensure_tls_material(self.cert_path, self.key_path)
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("10", called_cmd)


class MainEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base_dir = Path(self.tmp.name)
        self.cert_dir = self.base_dir / "certs"
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.cert_file = self.cert_dir / "server.crt"
        self.key_file = self.cert_dir / "server.key"

        self.env_common = {
            "HASHCATNODE_USERNAME": "envuser",
            "HASHCATNODE_PASSWORD": "envpass",
            "HASHCATNODE_CERT_PATH": str(self.cert_file),
            "HASHCATNODE_KEY_PATH": str(self.key_file),
            "HASHCATNODE_HASHES_DIR": str(self.base_dir / "hashes"),
            "HASHCATNODE_RULES_DIR": str(self.base_dir / "rules"),
            "HASHCATNODE_MASKS_DIR": str(self.base_dir / "masks"),
            "HASHCATNODE_WORDLISTS_DIR": str(self.base_dir / "wordlists"),
            "HASHCATNODE_OUTPUTS_DIR": str(self.base_dir / "outputs"),
            "HASHCATNODE_POTFILES_DIR": str(self.base_dir / "potfiles"),
            "HASHCATNODE_DB_PATH": str(self.base_dir / "data" / "hashcatnode.db"),
            "HASHCATNODE_BIND": "0.0.0.0",
            "HASHCATNODE_PORT": "9999",
            "HASHCATNODE_BINARY": "/bin/true",
        }

    def test_main_reads_env_overrides(self):
        with mock.patch.dict(os.environ, self.env_common, clear=False), \
                mock.patch("HashcatNode.hashcatnode._ensure_tls_material",
                           return_value=(str(self.cert_file), str(self.key_file))), \
                mock.patch("HashcatNode.hashcatnode.Server") as mock_server, \
                mock.patch("HashcatNode.hashcatnode.Hashcat") as mock_hashcat:
            mock_hashcat.return_value = mock.Mock()
            hashcatnode.main(run_server=True)

        mock_server.assert_called_once()
        args, kwargs = mock_server.call_args
        self.assertIn("envuser", args)
        # args: bind, port, username, password_hash, hashes_dir, cert_file, key_file
        self.assertEqual(args[5], str(self.cert_file))
        self.assertEqual(args[6], str(self.key_file))

    def test_build_settings_constructs_dataclass(self):
        env = dict(self.env_common)
        env["HASHCATNODE_PASSWORD"] = "pw"
        env["HASHCATNODE_BRAIN_ENABLED"] = "true"
        env["HASHCATNODE_BRAIN_PASSWORD"] = "brainpw"
        env["HASHCATNODE_BRAIN_PORT"] = "13743"
        with mock.patch.dict(os.environ, env, clear=False), \
                mock.patch("HashcatNode.hashcatnode._ensure_tls_material",
                        return_value=(str(self.cert_file), str(self.key_file))):
            settings = hashcatnode._build_settings()

        self.assertEqual(settings.bind_address, "0.0.0.0")
        self.assertEqual(settings.bind_port, 9999)
        self.assertEqual(settings.username, "envuser")
        self.assertEqual(settings.binary, "/bin/true")
        self.assertEqual(settings.cert_file, str(self.cert_file))
        self.assertEqual(settings.brain_host, "")
        self.assertEqual(settings.brain_enabled, "true")

    def test_apply_to_hashcat_sets_attributes(self):
        settings = hashcatnode.NodeSettings(
            bind_address="0.0.0.0",
            bind_port=9999,
            username="user",
            password_hash="hash",
            binary="/bin/true",
            hashes_dir="/tmp/hashes",
            rules_dir="/tmp/rules",
            mask_dir="/tmp/masks",
            wordlist_dir="/tmp/wordlists",
            workload_profile="2",
            cert_file="/tmp/cert",
            key_file="/tmp/key",
            brain_enabled="true",
            brain_host="host",
            brain_port="1234",
            brain_password="pw",
        )

        settings.apply_to_hashcat()
        self.assertEqual(hashcatnode.Hashcat.binary, "/bin/true")
        self.assertEqual(hashcatnode.Hashcat.rules_dir, "/tmp/rules")
        self.assertEqual(hashcatnode.Hashcat.brain["host"], "host")
