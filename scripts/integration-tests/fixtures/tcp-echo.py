#!/usr/bin/env python3
"""TCP echo server/client fixture for the local tunnel-anything E2E test."""

import argparse
import concurrent.futures
import socket
import sys
import threading


def handle(connection):
    with connection:
        chunks = []
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        connection.sendall(b"tunn-e2e:" + b"".join(chunks))


def serve(host, port):
    with socket.create_server((host, port), reuse_port=False) as listener:
        print("ready", flush=True)
        while True:
            connection, _ = listener.accept()
            threading.Thread(target=handle, args=(connection,), daemon=True).start()


def exchange(host, port, message):
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.sendall(message.encode())
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode()


def call(host, port, message):
    response = exchange(host, port, message)
    expected = "tunn-e2e:" + message
    if response != expected:
        print(f"received {response!r}, expected {expected!r}", file=sys.stderr)
        return 1
    print(response)
    return 0


def burst(host, port, count):
    def one(index):
        message = f"concurrent-{index}"
        response = exchange(host, port, message)
        expected = "tunn-e2e:" + message
        if response != expected:
            raise RuntimeError(f"received {response!r}, expected {expected!r}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        list(executor.map(one, range(count)))
    print(f"{count} concurrent connections passed")
    return 0


parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="command", required=True)
server_parser = subparsers.add_parser("server")
server_parser.add_argument("host")
server_parser.add_argument("port", type=int)
client_parser = subparsers.add_parser("client")
client_parser.add_argument("host")
client_parser.add_argument("port", type=int)
client_parser.add_argument("message")
burst_parser = subparsers.add_parser("burst")
burst_parser.add_argument("host")
burst_parser.add_argument("port", type=int)
burst_parser.add_argument("count", type=int)
arguments = parser.parse_args()

if arguments.command == "server":
    serve(arguments.host, arguments.port)
elif arguments.command == "burst":
    raise SystemExit(burst(arguments.host, arguments.port, arguments.count))
else:
    raise SystemExit(call(arguments.host, arguments.port, arguments.message))
