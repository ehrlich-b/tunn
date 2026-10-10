"""Shared offline configuration and private-file checks (Python 3.9+)."""

import json
import os
from pathlib import Path
import re
import stat


SERVICES = ("ssh", "wt", "dashboard")


def private_file(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError(f"{path}: require a regular, non-symlink file with mode 0600")
    if info.st_uid != os.getuid():
        raise ValueError(f"{path}: file must belong to the current user")
    return path


def private_directory(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir() or path.stat().st_uid != os.getuid():
        raise ValueError(f"{path}: require an owned directory, not a symlink")
    path.chmod(0o700)
    return path


def check_private_directory(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise ValueError(f"{path}: require an owned, non-symlink directory with mode 0700")
    return path


class Config:
    def __init__(self, path):
        self.path = private_file(Path(path).expanduser().absolute())
        self.data = json.loads(self.path.read_text())
        keys = {"host", "tunn_binary", "wt_binary", "work_dir",
                "dashboard_port", "dashboard_path", "allow_emails", "mcp_tools"}
        # Read old profiles in place. Adding a schema never rewrites an owner's
        # existing profile or silently substitutes a new machine name.
        if not isinstance(self.data, dict) or set(self.data) not in (keys, keys | {"version"}):
            raise ValueError("config keys must match host.json.example exactly")
        if "version" in self.data and (type(self.data["version"]) is not int or self.data["version"] != 1):
            raise ValueError("host.json version must be 1")
        self.host = self.data["host"]
        if self.host not in ("forge", "rig"):
            raise ValueError("host must be forge or rig")
        for key in ("tunn_binary", "wt_binary", "work_dir"):
            value = self.data[key]
            if not isinstance(value, str) or not Path(value).is_absolute() or "CHANGE_ME" in value:
                raise ValueError(f"{key}: supply an absolute Linux path")
        if not Path(self.data["work_dir"]).is_dir():
            raise ValueError("work_dir does not exist")
        port = self.data["dashboard_port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("dashboard_port must be between 1 and 65535")
        path = self.data["dashboard_path"]
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or any(c in path for c in "\r\n"):
            raise ValueError("dashboard_path must be a local absolute HTTP path")
        emails = self.data["allow_emails"]
        if not isinstance(emails, list) or not emails:
            raise ValueError("allow_emails must contain Bryan's verified account email")
        for email in emails:
            if not isinstance(email, str) or not re.fullmatch(r"[^\s,@]+@[^\s,@]+\.[^\s,@]+", email) or email.endswith(".invalid"):
                raise ValueError("allow_emails must contain exact real emails, without domain wildcards")
        tools = self.data["mcp_tools"]
        if not isinstance(tools, list) or not tools:
            raise ValueError("mcp_tools must be an explicitly reviewed nonempty tool allow-list")
        if any(not isinstance(t, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", t) or t.startswith("REPLACE_") for t in tools):
            raise ValueError("mcp_tools must contain reviewed exact wt tool names")

    def paths(self, home=None):
        home = Path(home) if home else Path.home()
        state = home / ".local/state/tunn-ai-hosts" / self.host
        return state, state / "credentials"

    def command(self, service):
        binary = self.data["tunn_binary"]
        name = f"{self.host}-{service}"
        if service == "ssh":
            return [binary, "--verbosity=error", "tcp", "--name", name, "127.0.0.1:22"]
        if service == "wt":
            return [binary, "--verbosity=error", "mcp", "--name", name,
                    "--tools", ",".join(self.data["mcp_tools"]), "--",
                    self.data["wt_binary"], "mcp", "stdio"]
        if service == "dashboard":
            # serve's parser requires --key=value for flags with values.
            return [binary, "--verbosity=error", "serve", f"--id={name}",
                    "--allow=" + ",".join(self.data["allow_emails"]),
                    f"http://127.0.0.1:{self.data['dashboard_port']}"]
        raise ValueError("unknown service")

    def environment(self, credentials):
        env = {k: v for k, v in os.environ.items() if not k.startswith("TUNN_")}
        env.update(TUNN_ENV="prod", TUNN_CONFIG_DIR=str(credentials),
                   TUNN_SERVER_ADDR="tunn.to:443", TUNN_DOMAIN="tunn.to",
                   TUNN_PUBLIC_MODE="false", TUNN_SECRET="")
        return env
