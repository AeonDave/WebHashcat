import py_compile
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "HashcatNode") not in sys.path:
    sys.path.insert(0, str(ROOT / "HashcatNode"))

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from NodeHashcat.hashcat import Session
from Utils.hashcat import HashcatExecutionError, PotfileManager
from Utils.models import Lock
from Utils.tasks import *


class HashcatRunHashcatTests(SimpleTestCase):
    def setUp(self):
        patcher = mock.patch("Utils.hashcat.Hashcat.get_binary", return_value="/opt/hashcat/hashcat")
        self.addCleanup(patcher.stop)
        patcher.start()

    @mock.patch("Utils.hashcat.subprocess.run")
    def test_run_hashcat_success_returns_completed_process(self, mock_run):
        expected = subprocess.CompletedProcess(["hashcat", "-V"], 0, stdout="7.1.2", stderr="")
        mock_run.return_value = expected

        result = Hashcat.run_hashcat(["hashcat", "-V"])

        self.assertEqual(result, expected)
        mock_run.assert_called_once()
        called_kwargs = mock_run.call_args.kwargs
        self.assertTrue(called_kwargs["capture_output"])
        self.assertEqual(called_kwargs["cwd"], "/opt/hashcat")

    @mock.patch("Utils.hashcat.subprocess.run")
    def test_run_hashcat_raises_error_on_non_zero_exit(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(["hashcat"], 2, stdout="", stderr="boom")

        with self.assertRaises(HashcatExecutionError) as ctx:
            Hashcat.run_hashcat(["hashcat", "--help"], check=True)

        self.assertEqual(ctx.exception.returncode, 2)
        self.assertIn("hashcat", ctx.exception.cmd[0])

    def test_run_hashcat_rejects_empty_command(self):
        with self.assertRaises(ValueError):
            Hashcat.run_hashcat([])

    @mock.patch("Utils.hashcat.subprocess.run")
    def test_run_hashcat_handles_oserror(self, mock_run):
        mock_run.side_effect = OSError("permission denied")

        with self.assertRaises(HashcatExecutionError) as ctx:
            Hashcat.run_hashcat(["hashcat", "--version"])

        self.assertEqual(ctx.exception.returncode, -1)
        self.assertIn("permission denied", ctx.exception.stderr)

    @mock.patch("Utils.hashcat.subprocess.run")
    def test_run_hashcat_without_capture_output_uses_custom_streams(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(["hashcat"], 0)

        stdout_sentinel = object()
        stderr_sentinel = object()
        Hashcat.run_hashcat(
            ["hashcat", "--help"],
            capture_output=False,
            stdout=stdout_sentinel,
            stderr=stderr_sentinel,
        )

        called_kwargs = mock_run.call_args.kwargs
        self.assertNotIn("capture_output", called_kwargs)
        self.assertIs(called_kwargs["stdout"], stdout_sentinel)
        self.assertIs(called_kwargs["stderr"], stderr_sentinel)


class _FakeRedisClient:
    def __init__(self):
        self.storage = {}
        self.last_setex = None

    def setex(self, key, ttl, value):
        self.storage[key] = value
        self.last_setex = (key, ttl, value)

    def set(self, key, value):
        self.storage[key] = value

    def get(self, key):
        return self.storage.get(key)


class _SequencedLock:
    def __init__(self, sequence):
        self.sequence = list(sequence)

    def acquire(self, blocking=False):
        if not self.sequence:
            return False
        return self.sequence.pop(0)

    def release(self):
        pass


class _SequencedRedis:
    def __init__(self, sequence):
        self.lock_instance = _SequencedLock(sequence)
        self.last_key = None
        self.last_timeout = None

    def lock(self, key, timeout=None):
        self.last_key = key
        self.last_timeout = timeout
        return self.lock_instance


class _FakeTempFile:
    def __init__(self, path):
        self.name = path

    def close(self):
        pass


HASHFILES_DIR = Path(__file__).resolve().parent.parent / "Files" / "Hashfiles"
HASHFILES_DIR.mkdir(parents=True, exist_ok=True)


class HashcatSnapshotCacheTests(SimpleTestCase):
    def setUp(self):
        self.fake_client = _FakeRedisClient()
        patcher = mock.patch(
            "Utils.hashcat_cache.redis.Redis.from_url",
            return_value=self.fake_client,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_store_and_get_snapshot_roundtrip(self):
        cache = HashcatSnapshotCache(cache_key="test:snapshot")
        snapshot = {"nodes": {"1": {}}, "generated_at": "now"}

        cache.store_snapshot(snapshot)

        stored = json.loads(self.fake_client.storage["test:snapshot"])
        self.assertEqual(stored, snapshot)
        self.assertEqual(cache.get_snapshot(), snapshot)
        self.assertEqual(self.fake_client.last_setex[1], cache._ttl)

    def test_get_snapshot_returns_none_for_invalid_payload(self):
        cache = HashcatSnapshotCache(cache_key="invalid")
        self.fake_client.storage["invalid"] = "not-json"

        self.assertIsNone(cache.get_snapshot())

    def test_get_node_and_session_snapshot_helpers(self):
        cache = HashcatSnapshotCache(cache_key="helpers")
        snapshot = {
            "nodes": {"4": {"name": "node-4"}},
            "sessions": {"sess": {"status": "Running"}},
        }

        self.fake_client.storage["helpers"] = json.dumps(snapshot)

        self.assertEqual(cache.get_node_snapshot(4)["name"], "node-4")
        self.assertEqual(cache.get_session_snapshot("sess")["status"], "Running")

    @mock.patch("Utils.hashcat_cache.time.time", return_value=200.0)
    def test_metadata_marks_stale_state(self, mock_time):
        cache = HashcatSnapshotCache(cache_key="meta")
        cache._stale_after = 50
        snapshot = {"generated_at": "ts", "generated_at_epoch": 120}

        meta = cache.get_metadata(snapshot)

        self.assertTrue(meta["available"])
        self.assertAlmostEqual(meta["age_seconds"], 80.0)
        self.assertTrue(meta["is_stale"])

    def test_metadata_for_missing_snapshot(self):
        cache = HashcatSnapshotCache(cache_key="meta-missing")
        meta = cache.get_metadata(None)

        self.assertFalse(meta["available"])
        self.assertTrue(meta["is_stale"])


class SettingsSampleCompileTests(SimpleTestCase):
    def test_settings_sample_compiles(self):
        root = Path(__file__).resolve().parents[2]
        sample_path = root / "WebHashcat" / "WebHashcat" / "settings.py.sample"
        py_compile.compile(str(sample_path), doraise=True)


class OptimizePotfileTests(TestCase):
    def setUp(self):
        super().setUp()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.potfile_path = Path(self.temp_dir.name) / "hashcat.potfile"
        self.potfile_path.write_text("a\nb\na\n", encoding="utf-8")
        # ensure backup cleanup
        self.addCleanup(lambda: Path(str(self.potfile_path) + ".bkp").unlink(missing_ok=True))

    @mock.patch("Utils.hashcat.Lock.objects.select_for_update")
    @mock.patch("Utils.hashcat.Hashcat.run_hashcat")
    def test_optimize_potfile_sorts_and_deduplicates_with_wrapper(self, mock_run, mock_select_for_update):
        mock_select_for_update.return_value.filter.return_value = []
        mock_run.return_value = subprocess.CompletedProcess(
            ["sort", "-u", str(self.potfile_path)],
            0,
            stdout="a\nb\n",
            stderr="",
        )
        with mock.patch("Utils.hashcat.Hashcat.get_potfile", return_value=str(self.potfile_path)):
            Hashcat.optimize_potfile()

        mock_run.assert_called_once_with(["sort", "-u", str(self.potfile_path)])
        self.assertEqual(self.potfile_path.read_text(encoding="utf-8"), "a\nb\n")


class PotfileManagerTests(TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.potfile_path = Path(self.temp_dir.name) / "potfile"
        self.backup_path = Path(str(self.potfile_path) + ".bkp")
        self.potfile_path.write_text("a\nb\n", encoding="utf-8")

    def test_backup_creates_backup_when_newer(self):
        manager = PotfileManager(str(self.potfile_path))
        manager.backup()
        self.assertTrue(self.backup_path.exists())
        self.assertEqual(self.backup_path.read_text(encoding="utf-8"), "a\nb\n")

    def test_restore_if_corrupt_replaces_potfile(self):
        manager = PotfileManager(str(self.potfile_path))
        manager.backup()
        self.potfile_path.write_text("a\n", encoding="utf-8")
        self.assertTrue(manager.restore_if_corrupt())
        self.assertEqual(self.potfile_path.read_text(encoding="utf-8"), "a\nb\n")

    @mock.patch("Utils.hashcat.Lock.objects.select_for_update")
    def test_manager_optimize_uses_runner(self, mock_select_for_update):
        mock_select_for_update.return_value.filter.return_value = []

        def fake_runner(cmd):
            return subprocess.CompletedProcess(cmd, 0, stdout="a\n", stderr="")

        manager = PotfileManager(str(self.potfile_path), runner=fake_runner)
        manager.optimize()
        self.assertEqual(self.potfile_path.read_text(encoding="utf-8"), "a\n")


class Md5ListingTests(SimpleTestCase):
    @mock.patch("Utils.hashcat.Hashcat.run_hashcat")
    def test_get_rules_uses_wrapper(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(["md5sum"], 0, stdout="abcd  /tmp/rule.rule\n", stderr="")
        with mock.patch("Utils.hashcat.listdir", return_value=["rule.rule"]), \
                mock.patch("Utils.hashcat.isfile", return_value=True):
            res = Hashcat.get_rules(detailed=True)
        mock_run.assert_called_once()
        self.assertEqual(res[0]["md5"], "abcd")

    @mock.patch("Utils.hashcat.Hashcat.run_hashcat")
    def test_get_masks_uses_wrapper(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(["md5sum"], 0, stdout="ffff  /tmp/mask.hcmask\n", stderr="")
        with mock.patch("Utils.hashcat.listdir", return_value=["mask.hcmask"]), \
                mock.patch("Utils.hashcat.isfile", return_value=True):
            res = Hashcat.get_masks(detailed=True)
        self.assertEqual(res[0]["md5"], "ffff")
        mock_run.assert_called_once()

    @mock.patch("Utils.hashcat.Hashcat.run_hashcat")
    def test_get_wordlists_uses_wrapper(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(["md5sum"], 0, stdout="bbbb  /tmp/list.wordlist\n",
                                                            stderr="")
        with mock.patch("Utils.hashcat.listdir", return_value=["list.wordlist"]), \
                mock.patch("Utils.hashcat.isfile", return_value=True), \
                mock.patch("builtins.open", mock.mock_open(read_data="x\n")):
            res = Hashcat.get_wordlists(detailed=True)
        self.assertEqual(res[0]["md5"], "bbbb")
        mock_run.assert_called_once()


class SetupPeriodicTasksTests(SimpleTestCase):
    def test_registers_expected_intervals(self):
        sender = SimpleNamespace(add_periodic_task=mock.Mock())
        setup_periodic_tasks(sender)

        intervals = sorted(call.args[0] for call in sender.add_periodic_task.call_args_list)
        self.assertEqual(
            intervals,
            sorted([60, 2 * 60 * 60, 3 * 60 * 60, NODE_CACHE_REFRESH_SECONDS]),
        )


class RefreshNodeCacheTaskTests(TestCase):
    def _patch_lock(self, sequence):
        patcher = mock.patch("Utils.utils.REDIS_CLIENT", _SequencedRedis(sequence))
        patcher.start()
        self.addCleanup(patcher.stop)
        return patcher

    @mock.patch("Utils.tasks.HashcatSnapshotCache")
    @mock.patch("Utils.tasks.HashcatAPI")
    @mock.patch("Utils.tasks.Node.objects.all")
    @mock.patch("Utils.tasks.timezone.now")
    def test_refresh_task_updates_cache(self, mock_now, mock_nodes, mock_api_cls, mock_cache_cls):
        self._patch_lock([True])
        mock_now.return_value = timezone.make_aware(datetime(2025, 1, 1, 12, 0, 0))
        node = SimpleNamespace(id=1, name="node-a", hostname="host", port=9999, username="u", password="p")
        mock_nodes.return_value = [node]

        mock_api = mock_api_cls.return_value
        mock_api.get_hashcat_info.return_value = {
            "response": "ok",
            "version": "7.1.2",
            "sessions": [{"name": "sess-1", "status": "Running"}],
        }
        mock_api.get_session_info.return_value = {
            "response": "ok",
            "status": "Running",
            "crack_type": "dictionary",
            "rule": "best64",
            "wordlist": "wl",
        }

        result = refresh_node_cache_task()
        self.assertEqual(result, {"nodes": 1, "sessions": 1})

        stored_snapshot = mock_cache_cls.return_value.store_snapshot.call_args[0][0]
        self.assertEqual(stored_snapshot["nodes"]["1"]["status"], "Running")
        self.assertIn("sess-1", stored_snapshot["sessions"])
        self.assertIsNotNone(stored_snapshot.get("generated_at"))

    @mock.patch("Utils.tasks.HashcatSnapshotCache")
    @mock.patch("Utils.tasks.HashcatAPI")
    @mock.patch("Utils.tasks.Node.objects.all")
    def test_refresh_task_aborts_when_lock_active(self, mock_nodes, mock_api_cls, mock_cache_cls):
        self._patch_lock([True, False])
        node = SimpleNamespace(id=1, name="node-b", hostname="host", port=9999, username="u", password="p")
        mock_nodes.return_value = [node]

        mock_api = mock_api_cls.return_value
        mock_api.get_hashcat_info.return_value = {
            "response": "ok",
            "version": "7.1.2",
            "sessions": [],
        }

        first = refresh_node_cache_task()
        second = refresh_node_cache_task()

        self.assertEqual(first["nodes"], 1)
        self.assertIsNone(second)
        self.assertEqual(mock_cache_cls.return_value.store_snapshot.call_count, 1)
        self.assertEqual(mock_api.get_hashcat_info.call_count, 1)


class UpdatePotfileTaskTests(TestCase):
    def _patch_lock(self, sequence):
        fake = _SequencedRedis(sequence)
        patcher = mock.patch("Utils.utils.REDIS_CLIENT", fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        return fake

    @mock.patch("Utils.tasks.Hashcat.update_hashfiles")
    def test_update_task_runs_once_and_cleans_tasks(self, mock_update):
        fake = self._patch_lock([True])
        update_potfile_task()

        self.assertEqual(Task.objects.count(), 0)
        self.assertEqual(fake.last_key, "update_potfile_task")
        mock_update.assert_called_once()

    @mock.patch("Utils.tasks.Hashcat.update_hashfiles")
    def test_update_task_skips_when_lock_missing(self, mock_update):
        self._patch_lock([False])
        result = update_potfile_task()

        self.assertIsNone(result)
        self.assertEqual(Task.objects.count(), 0)
        mock_update.assert_not_called()

    @mock.patch("Utils.tasks.Hashcat.update_hashfiles", side_effect=RuntimeError("boom"))
    def test_update_task_deletes_log_even_on_error(self, mock_update):
        self._patch_lock([True])
        with self.assertRaises(RuntimeError):
            update_potfile_task()

        self.assertEqual(Task.objects.count(), 0)
        mock_update.assert_called_once()

    @mock.patch("Utils.tasks.Hashcat.update_hashfiles")
    def test_update_task_prunes_stale_logs(self, mock_update):
        self._patch_lock([True])
        stale = Task.objects.create(time=timezone.now() - timedelta(hours=2), message="old")
        update_potfile_task()
        self.assertFalse(Task.objects.filter(id=stale.id).exists())


class OptimizePotfileTaskTests(TestCase):
    def _patch_lock(self, sequence):
        fake = _SequencedRedis(sequence)
        patcher = mock.patch("Utils.utils.REDIS_CLIENT", fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        return fake

    @mock.patch("Utils.tasks.Hashcat.optimize_potfile")
    def test_optimize_task_runs_once(self, mock_optimize):
        fake = self._patch_lock([True])
        result = optimize_potfile()
        self.assertEqual(fake.last_key, "optimize_potfile")
        self.assertTrue(result["optimized"])
        mock_optimize.assert_called_once()
        self.assertEqual(Task.objects.count(), 0)

    @mock.patch("Utils.tasks.Hashcat.optimize_potfile")
    def test_optimize_task_skips_when_lock_unavailable(self, mock_optimize):
        self._patch_lock([False])
        result = optimize_potfile()
        self.assertIsNone(result)
        mock_optimize.assert_not_called()
        self.assertEqual(Task.objects.count(), 0)


class UpdateCrackedCountTaskTests(TestCase):
    def _patch_lock(self, sequence):
        fake = _SequencedRedis(sequence)
        patcher = mock.patch("Utils.utils.REDIS_CLIENT", fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        return fake

    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user(username="owner-cc")
        self.hashfile = Hashfile.objects.create(
            owner=self.owner,
            name="hf",
            hashfile="hf.hash",
            hash_type=0,
            line_count=0,
            cracked_count=0,
            username_included=False,
        )
        Hash.objects.create(hashfile=self.hashfile, hash_type=0, username="u", password="pw", hash="hash")

    def test_updates_counts_when_lock_available(self):
        fake = self._patch_lock([True])
        result = update_cracked_count()
        self.hashfile.refresh_from_db()
        self.assertEqual(self.hashfile.cracked_count, 1)
        self.assertEqual(result["updated"], 1)
        self.assertEqual(fake.last_key, "update_cracked_count")

    def test_skips_when_lock_missing(self):
        self._patch_lock([False])
        self.hashfile.cracked_count = 0
        self.hashfile.save()
        result = update_cracked_count()
        self.assertIsNone(result)
        self.hashfile.refresh_from_db()
        self.assertEqual(self.hashfile.cracked_count, 0)


class HashInsertBatchingTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user(username="batch-owner")
        self.hashfile_name = "batchtest.hashfile"
        self.hashfile_path = HASHFILES_DIR / self.hashfile_name
        self.hashfile_path.write_text("hash\\n", encoding="utf-8")
        self.addCleanup(lambda: self.hashfile_path.unlink(missing_ok=True))

        self.hashfile = Hashfile.objects.create(
            owner=self.owner,
            name="BatchTest",
            hashfile=self.hashfile_name,
            hash_type=0,
            line_count=0,
            cracked_count=0,
            username_included=False,
        )
        Lock.objects.create(hashfile=self.hashfile, lock_ressource="hashfile")

    @mock.patch("Utils.hashcat.Hashcat.run_hashcat")
    @mock.patch("Utils.hashcat.Hashcat.get_binary", return_value="/opt/hashcat/hashcat")
    @mock.patch("Utils.hashcat.tempfile.NamedTemporaryFile")
    def test_insert_hashes_batches_bulk_inserts(self, mock_tmp, mock_get_binary, mock_run):
        fd, sanitized_path = tempfile.mkstemp()
        with os.fdopen(fd, "w", encoding="utf-8") as sanitized:
            for idx in range(1200):
                sanitized.write(f"hash{idx}\n")
        self.addCleanup(lambda: Path(sanitized_path).unlink(missing_ok=True))
        mock_tmp.return_value = _FakeTempFile(sanitized_path)

        def fake_run(cmd, **kwargs):
            Path(sanitized_path).write_text("\n".join(f"hash{idx}" for idx in range(1200)), encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        mock_run.side_effect = fake_run

        with mock.patch.object(Hash.objects, "bulk_create", wraps=Hash.objects.bulk_create) as mock_bulk:
            Hashcat.insert_hashes(self.hashfile)

        call_sizes = [len(call.args[0]) for call in mock_bulk.call_args_list]
        self.assertEqual(call_sizes, [1000, 200])
        self.assertEqual(Hash.objects.filter(hashfile=self.hashfile).count(), 1200)
        self.hashfile.refresh_from_db()
        self.assertEqual(self.hashfile.line_count, 1200)


class HashcatSessionFinalizationTests(SimpleTestCase):
    def setUp(self):
        self.session = Session.__new__(Session)
        self.session.__data__ = {}
        self.session._dirty = set()
        self.session.session_status = ""
        self.session.reason = ""
        self.session.time_estimated = ""
        self.session.speed = ""
        self.session.save = mock.Mock()

    def test_watchdog_code_sets_reason(self):
        self.session._finalize_process_result(254, "")
        self.assertEqual(self.session.session_status, "Error")
        self.assertEqual(self.session.reason, "GPU-watchdog alarm")
        self.session.save.assert_called_once()

    def test_generic_error_uses_sanitized_stderr(self):
        stderr = "\x1b[31mFatal GPU error\x1b[0m"
        self.session._finalize_process_result(255, stderr)
        self.assertEqual(self.session.session_status, "Error")
        self.assertEqual(self.session.reason, "Fatal GPU error")

    def test_aborted_and_success_codes_clear_reason(self):
        self.session._finalize_process_result(2, "ignored")
        self.assertEqual(self.session.session_status, "Aborted")
        self.assertEqual(self.session.reason, "")
        self.session._finalize_process_result(0, "")
        self.assertEqual(self.session.session_status, "Done")
        self.assertEqual(self.session.reason, "")
