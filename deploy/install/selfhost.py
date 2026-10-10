#!/usr/bin/env python3
"""Version-1 standalone relay config and private SQLite/TLS export/import."""

import argparse
from contextlib import closing
import ipaddress
import os
from pathlib import Path
import re
import shutil
import sqlite3
import ssl
import sys
import tempfile
import time

from artifacts import digest, read_json, regular, sync_directory, write_json


KEYS = {"version", "domain", "http2_addr", "http3_addr", "internal_grpc_addr",
        "cert_file", "key_file", "db_path", "client_secret", "jwt_secret", "host_mode"}
ASSETS = {"cert_file": "cert.pem", "key_file": "key.pem", "db_path": "database.sqlite"}


def address(value):
    if not isinstance(value, str):
        raise ValueError("listen addresses must be literal IP:port strings")
    match = re.fullmatch(r"(?:\[([^\[\]]+)\]|([^:\[\]]+)):([0-9]+)", value)
    if match is None:
        raise ValueError("listen addresses require IPv4:port or [IPv6]:port")
    host, port = match.group(1) or match.group(2), match.group(3)
    if not 1 <= int(port) <= 65535:
        raise ValueError("listen port must be 1-65535")
    return ipaddress.ip_address(host), int(port)


def schema(data):
    if not isinstance(data, dict) or set(data) != KEYS or type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("standalone config must match version-1 schema exactly")
    domain = data["domain"]
    if not isinstance(domain, str) or len(domain) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")):
        raise ValueError("domain must be a lowercase DNS name")
    addresses = {key: address(data[key]) for key in ("http2_addr", "http3_addr", "internal_grpc_addr")}
    if not addresses["internal_grpc_addr"][0].is_loopback:
        raise ValueError("standalone internal gRPC must listen on loopback")
    if addresses["internal_grpc_addr"][1] == addresses["http2_addr"][1]:
        raise ValueError("internal gRPC must have its own TCP port")
    for key in ASSETS:
        if not isinstance(data[key], str) or not Path(data[key]).is_absolute():
            raise ValueError(f"{key} must be an absolute path")
    for key in ("client_secret", "jwt_secret"):
        if not isinstance(data[key], str) or len(data[key]) < 32 or "CHANGE_ME" in data[key] or any(c in data[key] for c in "\x00\r\n"):
            raise ValueError(f"{key} requires an owner-supplied secret of at least 32 characters")
    if type(data["host_mode"]) is not bool:
        raise ValueError("host_mode must be boolean")
    return data


def database(path):
    regular(path, private=True)
    connection = sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ValueError("SQLite quick_check failed")
    except BaseException:
        connection.close()
        raise
    return connection


def load(path, require_database=False):
    data = schema(read_json(path))
    regular(data["cert_file"])
    regular(data["key_file"], private=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(data["cert_file"], data["key_file"])
    db_path = Path(data["db_path"])
    if db_path.exists() or db_path.is_symlink():
        connection = database(db_path)
        connection.close()
    elif require_database:
        raise ValueError("export requires an existing SQLite database")
    elif not db_path.parent.is_dir() or db_path.parent.is_symlink():
        raise ValueError("database parent must be an existing directory")
    return data


def environment(data):
    # This supported path deliberately has no peers, billing, OAuth or public mode.
    # Clear ambient deployment settings so a fixture cannot select a live database.
    env = {k: v for k, v in os.environ.items() if not k.startswith(("TUNN_", "FLY_"))}
    env.update(TUNN_ENV="prod", TUNN_LOGIN_NODE="true", TUNN_PUBLIC_MODE="false",
               TUNN_HOST_MODE=str(data["host_mode"]).lower(), TUNN_DOMAIN=data["domain"],
               TUNN_HTTP2_ADDR=data["http2_addr"], TUNN_HTTP3_ADDR=data["http3_addr"],
               TUNN_INTERNAL_GRPC_PORT=data["internal_grpc_addr"],
               TUNN_CERT_FILE=data["cert_file"], TUNN_KEY_FILE=data["key_file"],
               TUNN_DB_PATH=data["db_path"], TUNN_CLIENT_SECRET=data["client_secret"],
               TUNN_JWT_SECRET=data["jwt_secret"], TUNN_SECRET="")
    return env


def destination(path):
    path = Path(path)
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ValueError("destination must be a new absolute directory; profiles are never overwritten")
    if not path.parent.is_dir() or any(p.is_symlink() for p in path.parents):
        raise ValueError("destination parent must exist and must not traverse symlinks")
    return path


def export_config(config_path, output):
    data = load(config_path, require_database=True)
    output = destination(output)
    stage = Path(tempfile.mkdtemp(prefix=".tunn-export-", dir=output.parent))
    try:
        for key in ("cert_file", "key_file"):
            target = stage / ASSETS[key]
            shutil.copyfile(regular(data[key]), target)
            target.chmod(0o600)
        with closing(database(data["db_path"])) as source:
            target = stage / ASSETS["db_path"]
            # backup includes committed WAL content; copying the main file doesn't.
            started = time.monotonic()

            def progress(*_):
                if time.monotonic() - started > 30:
                    raise TimeoutError("SQLite backup exceeded 30 seconds; destination not published")

            with closing(sqlite3.connect(target)) as backup:
                source.backup(backup, pages=128, progress=progress, sleep=0.1)
            target.chmod(0o600)
        write_json(stage / "snapshot.json", {"version": 1, "config": data,
                   "sha256": {name: digest(stage / name) for name in ASSETS.values()}})
        # Publish only a complete bundle. The caller must keep the relay stopped
        # for a coherent config/certificate/DB cut, independent of SQLite backup.
        os.rename(stage, output)
        sync_directory(output.parent)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def import_config(bundle, output):
    bundle = Path(bundle)
    output = destination(output)
    snapshot = read_json(bundle / "snapshot.json")
    if not isinstance(snapshot, dict) or set(snapshot) != {"version", "config", "sha256"} or type(snapshot["version"]) is not int or snapshot["version"] != 1:
        raise ValueError("unsupported snapshot schema")
    data = dict(schema(snapshot["config"]))
    if not isinstance(snapshot["sha256"], dict) or set(snapshot["sha256"]) != set(ASSETS.values()):
        raise ValueError("snapshot must checksum exactly the supported assets")
    for name, checksum in snapshot["sha256"].items():
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum) or digest(bundle / name) != checksum:
            raise ValueError("snapshot checksum mismatch; import refused")
    stage = Path(tempfile.mkdtemp(prefix=".tunn-import-", dir=output.parent))
    try:
        staged_data = dict(data)
        for key, name in ASSETS.items():
            target = stage / name
            shutil.copyfile(regular(bundle / name), target)
            target.chmod(0o600)
            if digest(target) != snapshot["sha256"][name]:
                raise ValueError("snapshot changed while being imported")
            data[key], staged_data[key] = str(output / name), str(target)
        write_json(stage / "relay.json", staged_data)
        load(stage / "relay.json", require_database=True)
        write_json(stage / "relay.json", data)
        os.rename(stage, output)
        sync_directory(output.parent)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run", "export", "import"))
    parser.add_argument("--config")
    parser.add_argument("--binary")
    parser.add_argument("--bundle")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.action == "import":
        if not args.bundle or not args.output:
            parser.error("import requires --bundle and --output")
        import_config(args.bundle, args.output)
    else:
        if not args.config:
            parser.error("require --config")
        data = load(args.config)
        if args.action == "export":
            if not args.output:
                parser.error("export requires --output")
            export_config(args.config, args.output)
        elif args.action == "run":
            if not args.binary or not Path(args.binary).is_absolute():
                parser.error("run requires an absolute --binary")
            binary = str(regular(args.binary))
            working = Path(args.config).absolute().parent
            if (working / ".env").exists():
                raise ValueError("remove ambient .env from the relay manifest directory before running")
            os.chdir(working)
            os.execve(binary, [binary, "--verbosity=error", "--mode=host"], environment(data))
    print("PASS local standalone config/TLS/SQLite operation; no service manager or hosted state touched.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, sqlite3.Error, ssl.SSLError) as error:
        # Do not include JSON input or secret values in diagnostic output.
        print(f"selfhost: {error}", file=sys.stderr)
        sys.exit(1)
