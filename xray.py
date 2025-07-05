import atexit
import json
import re
import subprocess
import threading
from collections import deque
from contextlib import contextmanager
from pathlib import Path

from config import (DEBUG, INBOUNDS, OUTBOUNDS, SSL_CERT_FILE, SSL_KEY_FILE,
                    XRAY_API_HOST, XRAY_API_PORT)
from logger import logger


class XRayConfig(dict):
    """
    Loads and modifies an Xray config JSON.
    This class injects the necessary API inbound and routing rules.
    """

    def __init__(self, config: str, peer_ip: str):
        config_dict = json.loads(config)

        # Save the raw, unfiltered configuration for debugging
        debug_config_path = Path("/var/lib/marzban-node/upstream-config.json")
        try:
            debug_config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(debug_config_path, 'w') as f:
                json.dump(config_dict, f, indent=4)
            logger.info(f"Saved incoming upstream config for debugging to {debug_config_path}")
        except (IOError, OSError) as e:
            logger.warning(f"Could not write debug config to {debug_config_path}: {e}")

        super().__init__(config_dict)

        self.api_host = XRAY_API_HOST
        self.api_port = XRAY_API_PORT
        self.ssl_cert = SSL_CERT_FILE
        self.ssl_key = SSL_KEY_FILE
        self.peer_ip = peer_ip

        self._apply_api()

    def to_json(self, **json_kwargs):
        """Serializes the config dictionary to a JSON string."""
        return json.dumps(self, **json_kwargs)

    def _apply_api(self):
        """Injects API configuration and filters inbounds/outbounds."""
        # --- MODIFIED: Preserve the full routing section from upstream ---
        # We start with the full routing config and just ensure our API rule is added.
        self.setdefault('routing', {}).setdefault('rules', [])

        # Filter inbounds based on INBOUNDS env var
        if 'inbounds' in self:
            # First, always remove any pre-existing API inbounds to avoid conflicts
            self['inbounds'] = [
                ib for ib in self.get('inbounds', [])
                if not (ib.get('protocol') == 'dokodemo-door' and ib.get('tag') == 'API_INBOUND')
            ]
            # If INBOUNDS is specified, perform the filtering
            if INBOUNDS:
                self['inbounds'] = [
                    ib for ib in self['inbounds'] if ib.get('tag') in INBOUNDS
                ]

        # --- NEW: Filter outbounds based on OUTBOUNDS env var ---
        if 'outbounds' in self and OUTBOUNDS:
            self['outbounds'] = [
                ob for ob in self.get('outbounds', [])
                if ob.get('tag') in OUTBOUNDS
            ]

        # Add API service definition, which is required for management
        self["api"] = {
            "services": ["HandlerService", "StatsService", "LoggerService"],
            "tag": "API"
        }
        self["stats"] = {}

        # Define the API inbound for management
        api_inbound = {
            "listen": self.api_host,
            "port": self.api_port,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {
                    "certificates": [{
                        "certificateFile": self.ssl_cert,
                        "keyFile": self.ssl_key
                    }]
                }
            },
            "tag": "API_INBOUND"
        }
        self.setdefault("inbounds", []).insert(0, api_inbound)

        # --- MODIFIED: Cleanly add the API routing rule ---
        # Remove any existing rule that points to the API to prevent duplicates
        self['routing']['rules'] = [
            rule for rule in self['routing']['rules']
            if rule.get('outboundTag') != 'API'
        ]

        # Define the routing rule for the API
        api_rule = {
            "type": "field",
            "inboundTag": ["API_INBOUND"],
            "source": ["127.0.0.1", self.peer_ip],
            "outboundTag": "API"
        }
        # Insert the API rule at the top of the list to give it priority
        self["routing"]["rules"].insert(0, api_rule)


class XRayCore:
    """Manages the lifecycle of the Xray subprocess."""
    def __init__(self,
                 executable_path: str = "/usr/bin/xray",
                 assets_path: str = "/usr/share/xray"):
        self.executable_path = executable_path
        self.assets_path = assets_path

        self.version = self.get_version()
        self.process = None
        self.restarting = False

        self._logs_buffer = deque(maxlen=100)
        self._temp_log_buffers = {}
        self._on_start_funcs = []
        self._on_stop_funcs = []
        self._env = {"XRAY_LOCATION_ASSET": assets_path}

        # Ensure Xray is stopped when the program exits
        atexit.register(lambda: self.stop() if self.started else None)

    def get_version(self):
        """Gets the version of the Xray executable."""
        cmd = [self.executable_path, "version"]
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8')
            m = re.match(r'^Xray (\d+\.\d+\.\d+)', output)
            if m:
                return m.groups()[0]
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Could not get Xray version: {e}")
            return None

    def __capture_process_logs(self):
        """Captures stdout from the Xray process in a separate thread."""
        def capture_logs(debug_mode):
            while self.process and self.process.poll() is None:
                output = self.process.stdout.readline()
                if not output:
                    break
                output = output.strip()
                self._logs_buffer.append(output)
                for buf in list(self._temp_log_buffers.values()):
                    buf.append(output)
                if debug_mode:
                    logger.debug(output)

        threading.Thread(target=capture_logs, args=(DEBUG,)).start()

    @contextmanager
    def get_logs(self):
        """A context manager to temporarily capture logs for a specific task."""
        buf = deque(self._logs_buffer, maxlen=100)
        buf_id = id(buf)
        try:
            self._temp_log_buffers[buf_id] = buf
            yield buf
        finally:
            if buf_id in self._temp_log_buffers:
                del self._temp_log_buffers[buf_id]
            del buf

    @property
    def started(self):
        """Checks if the Xray process is currently running."""
        return self.process and self.process.poll() is None

    def start(self, config: XRayConfig):
        """Starts the Xray process with a given configuration."""
        if self.started:
            raise RuntimeError("Xray is already started")

        if config.get('log', {}).get('logLevel') in ('none', 'error'):
            config['log']['logLevel'] = 'warning'

        config_path = Path("/var/lib/marzban-node/config.json")

        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as config_file:
                config_file.write(config.to_json())
        except (IOError, OSError) as e:
            logger.error(f"Error writing config file to {config_path}: {e}")
            raise RuntimeError(f"Could not write Xray configuration to {config_path}") from e

        cmd = [self.executable_path, "run", '-config', str(config_path)]

        self.process = subprocess.Popen(
            cmd,
            env=self._env,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True
        )

        self.__capture_process_logs()

        for func in self._on_start_funcs:
            threading.Thread(target=func).start()

        logger.info("Xray core started.")

    def stop(self):
        """Stops the Xray process."""
        if not self.started:
            return

        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.process = None
        logger.warning("Xray core stopped")

        for func in self._on_stop_funcs:
            threading.Thread(target=func).start()

    def restart(self, config: XRayConfig):
        """Restarts the Xray process with a new configuration."""
        if self.restarting:
            return

        self.restarting = True
        try:
            logger.warning("Restarting Xray core...")
            self.stop()
            self.start(config)
        finally:
            self.restarting = False

    def on_start(self, func: callable):
        """Decorator to register a function to run on start."""
        self._on_start_funcs.append(func)
        return func

    def on_stop(self, func: callable):
        """Decorator to register a function to run on stop."""
        self._on_stop_funcs.append(func)
        return func
