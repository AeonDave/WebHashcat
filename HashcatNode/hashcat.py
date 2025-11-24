#!/usr/bin/python3
from __future__ import annotations

import hashlib
import logging
import os
import random
import re
import shlex
import string
import subprocess
import tempfile
import threading
import time

try:
    from datetime import UTC, datetime
except ImportError:  # pragma: no cover - Python <3.11 lacks datetime.UTC
    from datetime import datetime, timezone as _timezone

    UTC = _timezone.utc
from os import listdir
from os.path import isfile, join
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

if os.name == 'nt':
    try:  # pragma: no cover - Windows only dependency
        import win32console  # type: ignore
    except ImportError:  # pragma: no cover - allow running without pywin32
        win32console = None  # type: ignore
else:  # pragma: no cover - non-Windows platforms never use win32console
    win32console = None  # type: ignore

from peewee import (
    BooleanField,
    CharField,
    DateTimeField,
    FloatField,
    IntegerField,
    Model,
    SqliteDatabase,
    TextField,
)

DB_PATH = os.environ.get("HASHCATNODE_DB_PATH", os.path.dirname(os.path.abspath(__file__)) + os.sep + "hashcatnode.db")
database = SqliteDatabase(DB_PATH)
LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


class HashcatExecutionError(RuntimeError):
    """Raised when a hashcat subprocess fails."""

    def __init__(self, cmd: List[str], returncode: int, stdout: Optional[str], stderr: Optional[str]):
        super().__init__(f"Hashcat command failed with exit code {returncode}: {shlex.join(cmd)}")
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Hashcat(object):
    binary: str = ""
    rules_dir: str = ""
    mask_dir: str = ""
    wordlist_dir: str = ""
    version: str = ""
    hash_modes: Dict[int, Dict[str, str]] = {}
    rules: Dict[str, Dict[str, str]] = {}
    masks: Dict[str, Dict[str, str]] = {}
    wordlists: Dict[str, Dict[str, str]] = {}
    sessions: Dict[str, "Session"] = {}
    workload_profile: int = 3  # default hashcat value
    brain: Dict[str, str] = {"enabled": "false", "host": "", "port": "", "password": ""}
    default_device_type: int = 1

    if TYPE_CHECKING:
        commandline_path: str
        rules_dir: str
        mask_dir: str
        wordlist_dir: str
        potfile_path: str
        output_directory: str
        log_file: str
        hashcat_debug_file: bool
        session_process: Optional[subprocess.Popen]
        win_stdin: Any
        thread: threading.Thread
        hash_modes: Dict[int, Dict[str, str]]
        rules: Dict[str, Dict[str, str]]
        masks: Dict[str, Dict[str, str]]
        wordlists: Dict[str, Dict[str, str]]
        sessions: Dict[str, "Session"]

    @classmethod
    def _load_assets(cls, directory: str, extension: str) -> Dict[str, Dict[str, str]]:
        assets: Dict[str, Dict[str, str]] = {}
        file_list = [join(directory, f) for f in listdir(directory) if isfile(join(directory, f)) and f != ".gitkeep"]

        for file in file_list:
            if extension and not file.endswith(extension):
                continue
            assets[os.path.basename(file)] = {
                "name": os.path.basename(file),
                "md5": cls._md5_for_file(file),
                "path": file,
            }
        return assets

    @staticmethod
    def run_hashcat(
            cmd: List[str],
            *,
            check: bool = True,
            capture_output: bool = True,
            text: bool = True,
            env: Optional[Dict[str, str]] = None,
            cwd: Optional[str] = None,
            input_data: Optional[Union[str, bytes]] = None,
            timeout: Optional[float] = None,
            stdout: Optional[int] = None,
            stderr: Optional[int] = None,
    ) -> subprocess.CompletedProcess:
        if not cmd:
            raise ValueError("Command list must not be empty")

        exec_cwd = cwd or (os.path.dirname(Hashcat.binary) if Hashcat.binary else None)
        log_cmd = shlex.join(cmd)
        LOGGER.debug("Executing hashcat command: %s", log_cmd)

        run_kwargs: Dict[str, Any] = {
            "check": False,
            "text": text,
            "cwd": exec_cwd,
            "env": env,
            "input": input_data,
            "timeout": timeout,
        }
        if capture_output:
            run_kwargs["capture_output"] = True
        else:
            if stdout is not None:
                run_kwargs["stdout"] = stdout
            if stderr is not None:
                run_kwargs["stderr"] = stderr

        try:
            completed = subprocess.run(cmd, **run_kwargs)
        except OSError as exc:
            LOGGER.exception("Failed to invoke hashcat command: %s", log_cmd)
            raise HashcatExecutionError(cmd, -1, None, str(exc)) from exc

        if check and completed.returncode != 0:
            LOGGER.error(
                "Hashcat command failed (%s): rc=%s stderr=%s",
                log_cmd,
                completed.returncode,
                (completed.stderr or "").strip(),
            )
            raise HashcatExecutionError(cmd, completed.returncode, completed.stdout, completed.stderr)

        return completed

    @staticmethod
    def _md5_for_file(path: str) -> str:
        if os.name != 'nt':
            try:
                result = Hashcat.run_hashcat(["md5sum", path])
                stdout = (result.stdout or "").strip()
                if stdout:
                    return stdout.split()[0]
            except HashcatExecutionError:
                LOGGER.warning("md5sum failed for %s, falling back to hashlib", path)

        file_hash = hashlib.md5()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                file_hash.update(chunk)
        return file_hash.hexdigest()

    """
        Parse hashcat version
    """

    @classmethod
    def parse_version(self):

        # cwd needs to be added for Windows version of hashcat
        result = self.run_hashcat([self.binary, '-V'])
        self.version = (result.stdout or "").strip()

    """
        Parse hashcat help
    """

    @classmethod
    def parse_help(self):
        self.hash_modes = {}

        help_section_regex = re.compile(r"^- \[ (?P<section_name>.*) ] -$", re.IGNORECASE)
        hash_mode_regex = re.compile(r"^\s*(?P<id>\d+)\s+\|\s+(?P<name>.+?)\s+\|\s+(?P<description>.+)\s*$")

        def parse_from_args(args):
            help_section = None
            hashcat_help = self.run_hashcat(args)
            for line in (hashcat_help.stdout or "").splitlines():
                line = line.rstrip()

                if not line:
                    continue

                section_match = help_section_regex.match(line)
                if section_match:
                    help_section = section_match.group("section_name").strip()
                    continue

                if help_section and help_section.lower() == "hash modes":
                    hash_mode_match = hash_mode_regex.match(line)
                    if hash_mode_match:
                        hash_mode_id = int(hash_mode_match.group("id"))
                        self.hash_modes[hash_mode_id] = {
                            "id": hash_mode_id,
                            "name": hash_mode_match.group("name").strip(),
                            "description": hash_mode_match.group("description").strip(),
                        }

        # Prefer legacy --help output, but fall back to -hh which prints hash modes on >=7.x
        parse_from_args([self.binary, '--help'])
        if not self.hash_modes:
            parse_from_args([self.binary, '-hh'])

        if not self.hash_modes:
            raise Exception(
                "Unable to parse hash modes from hashcat help output. Ensure the configured binary supports -hh or update the parser.")

    """
        Parse rule directory
    """

    @classmethod
    def parse_rules(self):
        self.rules = self._load_assets(self.rules_dir, ".rule")

        # Not comptatible with windows, lets make a pure python version

    """
        Parse wordlist directory
    """

    @classmethod
    def parse_wordlists(self):
        self.wordlists = self._load_assets(self.wordlist_dir, "")

        # Not comptatible with windows, lets make a pure python version

    """
        Parse mask directory
    """

    @classmethod
    def parse_masks(self):
        self.masks = self._load_assets(self.mask_dir, ".hcmask")

        # Not comptatible with windows, lets make a pure python version

    """
        Create a new session
    """

    @classmethod
    def create_session(self, name, crack_type, hash_file, hash_mode_id, wordlist, rule, mask, username_included,
                       device_type, brain_mode, end_timestamp, hashcat_debug_file):

        if name in self.sessions:
            raise Exception("This session name has already been used")

        if hash_mode_id != -2 and hash_mode_id not in self.hash_modes:
            raise Exception("Inexistant hash mode, did you upgraded hashcat ?")

        if not crack_type in ["dictionary", "mask"]:
            raise Exception("Unsupported cracking type: %s" % crack_type)

        # Always rely on the node's configured/auto-detected device type to avoid user supplied mismatch.
        device_type = self.default_device_type
        if device_type not in [1, 2, 3]:
            raise Exception("Unsupported device type: %d" % device_type)

        if not brain_mode in [0, 1, 2, 3]:
            raise Exception("Unsupported brain mode: %d" % brain_mode)

        rule_path: Optional[str] = None
        wordlist_path: Optional[str] = None
        mask_path: Optional[str] = None

        if crack_type == "dictionary":
            if rule != None and not rule in self.rules:
                raise Exception("Inexistant rule, did you synchronise the files on your node ?")
            elif rule == None:
                rule_path = None
            else:
                rule_path = self.rules[rule]["path"]

            if wordlist == None or not wordlist in self.wordlists:
                raise Exception("Inexistant wordlist, did you synchronise the files on your node ?")
            wordlist_path = self.wordlists[wordlist]["path"]

            mask_path = None
        elif crack_type == "mask":
            if mask == None or not mask in self.masks:
                raise Exception("Inexistant mask, did you synchronise the files on your node ?")
            mask_path = self.masks[mask]["path"]
            rule_path = None
            wordlist_path = None
        else:
            raise Exception("Unsupported cracking type: %s" % crack_type)

        pot_file = os.path.join(os.path.dirname(__file__), "potfiles", ''.join(
            random.choice(string.ascii_uppercase + string.digits) for _ in range(12)) + ".potfile")

        if hashcat_debug_file:
            output_file = os.path.join(os.path.dirname(__file__), "outputs", ''.join(
                random.choice(string.ascii_uppercase + string.digits) for _ in range(12)) + ".output")
        else:
            output_file = None

        session = Session(
            name=name,
            crack_type=crack_type,
            hash_file=hash_file,
            pot_file=pot_file,
            hash_mode_id=hash_mode_id,
            wordlist_file=wordlist_path,
            rule_file=rule_path,
            mask_file=mask_path,
            username_included=username_included,
            device_type=device_type,
            brain_mode=brain_mode,
            end_timestamp=end_timestamp,
            output_file=output_file,
            session_status="Not started",
            time_started=None,
            progress=0,
            reason="",
        )
        self.sessions[session.name] = session
        session.setup()
        session.save()

        logging.info("Session %s created" % name)

        return session

    """
        Remove a session
    """

    @classmethod
    def remove_session(self, name):

        if not name in self.sessions:
            raise Exception("This session name doesn't exists")

        self.sessions[name].remove()
        self.sessions[name].delete_instance()

        del self.sessions[name]

        logging.info("Session %s removed" % name)

    """
        Reload sessions
    """

    @classmethod
    def reload_sessions(self):

        for session in Session.select():
            if session.session_status in ["Running", "Paused"]:
                session.session_status = "Aborted"
                session.reason = ""
                session.save()
            self.sessions[session.name] = session
            session.setup()

    """
        Upload a new rule file
    """

    @classmethod
    def upload_rule(self, name, rules):

        name = name.split("/")[-1]

        if not name.endswith(".rule"):
            name += ".rule"

        path = os.path.join(self.rules_dir, name)

        if name in self.rules:
            try:
                os.remove(path)
            except Exception as e:
                pass

        f = open(path, "wb")
        f.write(rules)
        f.close()

        self.parse_rules()

        logging.info("Rule file %s uploaded" % name)

    """
        Upload a new mask file
    """

    @classmethod
    def upload_mask(self, name, masks):

        name = name.split("/")[-1]

        if not name.endswith(".hcmask"):
            name += ".hcmask"

        path = os.path.join(self.mask_dir, name)

        if name in self.masks:
            try:
                os.remove(path)
            except Exception as e:
                pass

        f = open(path, "wb")
        f.write(masks)
        f.close()

        self.parse_masks()

        logging.info("Mask file %s uploaded" % name)

    """
        Upload a new wordlist file
    """

    @classmethod
    def upload_wordlist(self, name, wordlists):

        name = name.split("/")[-1]

        if not name.endswith((".wordlist", ".gz", ".zip")):
            name += ".wordlist"

        path = os.path.join(self.wordlist_dir, name)

        if name in self.wordlists:
            try:
                os.remove(path)
            except Exception as e:
                pass

        f = open(path, "wb")
        f.write(wordlists)
        f.close()

        self.parse_wordlists()

        logging.info("Wordlist file %s uploaded" % name)

    """
        Returns the number of running/paused hashcat sessions
    """

    @classmethod
    def number_ongoing_sessions(self):
        number = 0

        for session_name, session in self.sessions.items():
            if session.session_status in ["Paused", "Running"]:
                number += 1

        return number


class Session(Model):
    name = CharField(unique=True)
    crack_type = CharField()
    hash_file = CharField()
    pot_file = CharField()
    hash_mode_id = IntegerField()
    rule_file = CharField(null=True)
    wordlist_file = CharField(null=True)
    mask_file = CharField(null=True)
    username_included = BooleanField()
    device_type = IntegerField()
    brain_mode = IntegerField()
    end_timestamp = IntegerField(null=True)
    output_file = CharField(null=True)
    session_status = CharField()
    time_started = DateTimeField(null=True)
    progress = FloatField()
    reason = TextField()

    class Meta:
        database = database

    if TYPE_CHECKING:
        name: str
        crack_type: str
        hash_file: str
        pot_file: str
        hash_mode_id: int
        rule_file: Optional[str]
        wordlist_file: Optional[str]
        mask_file: Optional[str]
        username_included: bool
        device_type: int
        brain_mode: int
        end_timestamp: Optional[int]
        output_file: Optional[str]
        session_status: str
        time_started: Optional[datetime]
        progress: float
        reason: str

    @staticmethod
    def _require_win32console() -> Any:
        if win32console is None:
            raise RuntimeError("win32console support is unavailable on this platform")
        return win32console

    def setup(self):
        # File to store the processes output
        random_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        self.result_file = os.path.join(tempfile.gettempdir(), random_name + ".cracked")

        # File to store the hashcat output
        random_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        self.hashcat_output_file = os.path.join(tempfile.gettempdir(), random_name + ".hashcat")
        open(self.hashcat_output_file, 'a').close()

        self.hash_type = "N/A"
        self.time_estimated = "N/A"
        self.speed = "N/A"
        self.recovered = "N/A"

    def start(self):
        if os.name == 'nt':
            if Hashcat.number_ongoing_sessions() > 0:
                raise Exception("Windows version of Hashcatnode only supports 1 running hashcat at a time")

        self.thread = threading.Thread(target=self.session_thread)
        self.thread.start()

        # Little delay to ensure the process if properly launched
        time.sleep(1)

        # TO UNCOMMENT
        self.status()

    def session_thread(self):
        # Prepare regex to parse the main hashcat process output
        regex_list = [
            ("hash_type", re.compile(r"^Hash\.Type\.+: +(.*)\s*$")),
            ("speed", re.compile(r"^Speed\.#1\.+: +(.*)\s*$")),
        ]
        if self.crack_type == "dictionary":
            regex_list.append(("progress", re.compile(r"^Progress\.+: +\d+/\d+ \((\S+)%\)\s*$")))
            regex_list.append(("time_estimated", re.compile(r"^Time\.Estimated\.+: +(.*)\s*$")))
        elif self.crack_type == "mask":
            regex_list.append(("progress", re.compile(r"^Input\.Mode\.+: +Mask\s+\(\S+\)\s+\[\d+]\s+\((\S+)%\)\s*$")))

        self.time_started = datetime.now(UTC)

        cmd_line: List[str]
        if not self.session_status in ["Aborted"]:
            # Command lines used to crack the passwords
            if self.crack_type == "dictionary":
                cmd_line = [Hashcat.binary, '--session', self.name, '--status', '-a', '0']
                if self.hash_mode_id != -2:
                    cmd_line += ['-m', str(self.hash_mode_id)]
                cmd_line += [str(self.hash_file), str(self.wordlist_file)]
                if self.rule_file is not None:
                    cmd_line += ['-r', str(self.rule_file)]
            elif self.crack_type == "mask":
                cmd_line = [Hashcat.binary, '--session', self.name, '--status', '-a', '3']
                if self.hash_mode_id != -2:
                    cmd_line += ['-m', str(self.hash_mode_id)]
                cmd_line += [str(self.hash_file), str(self.mask_file)]
            else:
                raise ValueError(f"Unsupported crack type: {self.crack_type}")
            if self.username_included:
                cmd_line += ["--username"]
            if self.device_type:
                cmd_line += ["-D", str(self.device_type)]
            # workload profile
            cmd_line += ["--workload-profile", str(Hashcat.workload_profile)]
            # set pot file
            cmd_line += ["--potfile-path", self.pot_file]
        else:
            # resume previous session
            cmd_line = [Hashcat.binary, '--session', self.name, '--restore']

        if Hashcat.brain['enabled'] == 'true' and self.brain_mode != 0:
            cmd_line += ['-z']
            cmd_line += ['--brain-client-features', str(self.brain_mode)]
            cmd_line += ['--brain-host', Hashcat.brain['host']]
            cmd_line += ['--brain-port', Hashcat.brain['port']]
            cmd_line += ['--brain-password', Hashcat.brain['password']]

        cmd_line = [str(item) for item in cmd_line]
        flattened_cmd = " ".join(cmd_line)
        LOGGER.info("Session %s startup command: %s", self.name, flattened_cmd)
        LOGGER.debug("Session %s startup command: %s", self.name, flattened_cmd)
        with open(self.hashcat_output_file, "a") as f:
            f.write("Command: %s\n" % " ".join(map(str, cmd_line)))

        self.session_status = "Running"
        self.time_started = datetime.now(UTC)
        self.save()

        if os.name == 'nt':
            console = self._require_win32console()
            # To controlhashcat on Windows, very different implementation than on linux
            # Look at:
            # https://github.com/hashcat/hashcat/blob/9dffc69089d6c52e6f3f1a26440dbef140338191/src/terminal.c#L477
            free_console = True
            try:
                console.AllocConsole()
            except console.error as exc:
                if exc.winerror != 5:
                    raise
                ## only free console if one was created successfully
                free_console = False

            self.win_stdin = console.GetStdHandle(console.STD_INPUT_HANDLE)

        # cwd needs to be added for Windows version of hashcat
        popen_kwargs = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "cwd": os.path.dirname(Hashcat.binary),
        }
        if os.name != 'nt':
            popen_kwargs["stdin"] = subprocess.PIPE

        if not os.path.exists(Hashcat.binary):
            raise FileNotFoundError(f"Hashcat binary not found: {Hashcat.binary}")

        if not os.path.exists(self.hash_file):
            raise FileNotFoundError(f"Hash file not found: {self.hash_file}")

        if self.wordlist_file and not os.path.exists(self.wordlist_file):
            raise FileNotFoundError(f"Wordlist not found: {self.wordlist_file}")

        LOGGER.info("Starting hashcat with command: %s", " ".join(cmd_line))

        try:
            self.session_process = subprocess.Popen(cmd_line, **popen_kwargs)
        except OSError as exc:
            LOGGER.exception("Unable to launch hashcat process for session %s", self.name)
            raise HashcatExecutionError(cmd_line, -1, None, str(exc)) from exc

        self.update_session()

        for line in self.session_process.stdout:
            with open(self.hashcat_output_file, "ab") as f:
                f.write(line)

            line = line.decode()
            line = line.rstrip()

            if line == "Resumed":
                self.session_status = "Running"
                self.save()

            if line == "Paused":
                self.session_status = "Paused"
                self.save()

            for var_regex in regex_list:
                var = var_regex[0]
                regex = var_regex[1]

                m = regex.match(line)
                if m:
                    setattr(self, var, m.group(1))

            # check timestamp
            if self.end_timestamp:
                current_timestamp = int(datetime.now(UTC).timestamp())

                if current_timestamp > self.end_timestamp:
                    self.quit()
                    break

        return_code = self.session_process.wait()
        stderr_output = ""
        if self.session_process.stderr:
            try:
                stderr_output = self.session_process.stderr.read().decode(errors="ignore")
            except Exception:  # pragma: no cover - defensive path
                stderr_output = ""
        self._finalize_process_result(return_code, stderr_output)

    def details(self):
        def _serialize_dt(value):
            if not value:
                return None
            return value.isoformat() if hasattr(value, "isoformat") else str(value)

        return {
            "name": self.name,
            "crack_type": self.crack_type,
            "device_type": self.device_type,
            "rule": os.path.basename(self.rule_file)[:-5] if self.rule_file else None,
            "mask": os.path.basename(self.mask_file)[:-7] if self.mask_file else None,
            "wordlist": os.path.basename(self.wordlist_file)[:-1 * len(".wordlist")] if self.wordlist_file else None,
            "status": self.session_status,
            "time_started": _serialize_dt(self.time_started),
            "time_estimated": self.time_estimated,
            "speed": self.speed,
            "progress": self.progress,
            "reason": self.reason,
        }

    """
        Returns the first 100000 lines from the potfile starting from a specific line
    """

    def get_potfile(self, from_line):
        line_count = 0
        selected_line_count = 0
        potfile_data = ""
        complete = True
        if os.path.exists(self.pot_file):
            for line in open(self.pot_file, encoding="utf-8"):
                if not line.endswith("\n"):
                    complete = True
                    break

                if line_count >= from_line:
                    potfile_data += line
                    selected_line_count += 1

                if selected_line_count >= 100000:
                    complete = False
                    break

                line_count += 1

            return {
                "line_count": selected_line_count,
                "remaining_data": not complete,
                "potfile_data": potfile_data,
            }
        else:
            return {
                "line_count": 0,
                "remaining_data": False,
                "potfile_data": "",
            }

    """
        Returns hashcat output file
    """

    def hashcat_output(self):
        return open(self.hashcat_output_file).read()

    """
        Returns hashes file
    """

    def hashes(self):
        return open(self.hash_file).read()

    """
        Cleanup the session before deleting it
    """

    def remove(self):
        self.quit()

        try:
            os.remove(self.result_file)
        except:
            pass
        try:
            os.remove(self.pot_file)
        except:
            pass
        try:
            os.remove(self.hash_file)
        except:
            pass

    def _strip_ansi(self, value: Optional[str]) -> str:
        return ANSI_ESCAPE_RE.sub('', value or '').strip()

    def _finalize_process_result(self, return_code: int, stderr_output: str) -> None:
        if return_code in [255, 254]:
            self.session_status = "Error"
            if return_code == 254:
                reason = "GPU-watchdog alarm"
            else:
                reason = self._strip_ansi(stderr_output) or "Hashcat exited with code 255"
        elif return_code in [2, 3, 4]:
            self.session_status = "Aborted"
            reason = ""
        else:
            self.session_status = "Done"
            reason = ""

        self.reason = reason
        self.time_estimated = "N/A"
        self.speed = "N/A"
        self.save()
        try:
            os.remove(self.hashcat_output_file)
        except:
            pass

    """
        Return cracked passwords
    """

    def cracked(self):

        # gather cracked passwords
        cmd_line = [Hashcat.binary, '--show', '-m', str(self.hash_mode_id), self.hash_file, '-o', self.result_file]
        if self.username_included:
            cmd_line += ["--username", "--outfile-format", "2"]
        else:
            cmd_line += ["--outfile-format", "3"]
        cmd_line += ["--potfile-path", self.pot_file]
        Hashcat.run_hashcat(
            cmd_line,
            capture_output=False,
            text=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

        with open(self.result_file, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()

    """
        Update the session
    """

    def update_session(self):
        self.status()

    """
        Update the session
    """

    def status(self):
        if not self.session_status in ["Paused", "Running"]:
            return

        if os.name == 'nt':
            console = self._require_win32console()
            evt = console.PyINPUT_RECORDType(console.KEY_EVENT)
            evt.Char = 's'
            evt.RepeatCount = 1
            evt.KeyDown = True
            evt.VirtualKeyCode = 0x0
            self.win_stdin.WriteConsoleInput([evt])
        else:
            try:
                self.session_process.stdin.write(b's')
                self.session_process.stdin.flush()
            except BrokenPipeError:
                pass

    """
        Pause the session
    """

    def pause(self):
        if not self.session_status in ["Paused", "Running"]:
            return

        if os.name == 'nt':
            console = self._require_win32console()
            evt = console.PyINPUT_RECORDType(console.KEY_EVENT)
            evt.Char = 'p'
            evt.RepeatCount = 1
            evt.KeyDown = True
            evt.VirtualKeyCode = 0x0
            self.win_stdin.WriteConsoleInput([evt])
        else:
            try:
                self.session_process.stdin.write(b'p')
                self.session_process.stdin.flush()
            except BrokenPipeError:
                pass

        self.update_session()

    """
        Resume the session
    """

    def resume(self):
        if not self.session_status in ["Paused", "Running"]:
            return

        if os.name == 'nt':
            console = self._require_win32console()
            evt = console.PyINPUT_RECORDType(console.KEY_EVENT)
            evt.Char = 'r'
            evt.RepeatCount = 1
            evt.KeyDown = True
            evt.VirtualKeyCode = 0x0
            self.win_stdin.WriteConsoleInput([evt])
        else:
            try:
                self.session_process.stdin.write(b'r')
                self.session_process.stdin.flush()
            except BrokenPipeError:
                pass

        self.update_session()

    """
        Quit the session
    """

    def quit(self):
        if not self.session_status in ["Paused", "Running"]:
            return

        if os.name == 'nt':
            console = self._require_win32console()
            evt = console.PyINPUT_RECORDType(console.KEY_EVENT)
            evt.Char = 'q'
            evt.RepeatCount = 1
            evt.KeyDown = True
            evt.VirtualKeyCode = 0x0
            self.win_stdin.WriteConsoleInput([evt])
        else:
            try:
                self.session_process.stdin.write(b'q')
                self.session_process.stdin.flush()
            except BrokenPipeError:
                pass

        LOGGER.info("Waiting for session %s thread to finish", self.name)
        self.thread.join()
        LOGGER.info("Session %s thread finished", self.name)

        self.session_status = "Aborted"
        self.save()
