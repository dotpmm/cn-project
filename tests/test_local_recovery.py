
#!/usr/bin/env python3
"""
Local UDP recovery test.

A UDP proxy sits between the client and server. It drops all traffic
for a configured blackout period, then forwards traffic normally.

Run from the project root:
    python3 tests/test_local_recovery.py

This test does not require Mininet or Ryu.
"""

import csv
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 0
PROXY_PORT = 0

BLACKOUT_SECONDS = 2.0
TEST_DURATION = 6.0
SEND_RATE = 50.0


class UDPBlackoutProxy:
    """Drops UDP packets during a blackout and forwards them otherwise."""

    def __init__(self, listen_port, server_address, blackout_seconds):
        self.server_address = server_address
        self.blackout_seconds = blackout_seconds
        self.start_time = None
        self.stop_event = threading.Event()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", listen_port))
        self.socket.settimeout(0.1)

        self.port = self.socket.getsockname()[1]
        self.client_address = None
        self.lock = threading.Lock()

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind(("127.0.0.1", 0))
        self.server_socket.settimeout(0.1)

        self.dropped_packets = 0
        self.forwarded_packets = 0

        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.start_time = time.monotonic()
        self.thread.start()

    def is_blackout(self):
        return (
            time.monotonic() - self.start_time
            < self.blackout_seconds
        )

    def run(self):
        while not self.stop_event.is_set():
            # Receive client packets.
            try:
                data, address = self.socket.recvfrom(65535)
                self.client_address = address

                if self.is_blackout():
                    self.dropped_packets += 1
                else:
                    self.server_socket.sendto(data, self.server_address)
                    self.forwarded_packets += 1
            except socket.timeout:
                pass
            except OSError:
                break

            # Receive server replies.
            try:
                data, address = self.server_socket.recvfrom(65535)

                if self.is_blackout():
                    self.dropped_packets += 1
                elif self.client_address is not None:
                    self.socket.sendto(data, self.client_address)
                    self.forwarded_packets += 1
            except socket.timeout:
                pass
            except OSError:
                break

    def close(self):
        self.stop_event.set()
        self.socket.close()
        self.server_socket.close()
        self.thread.join(timeout=1.0)


def start_server(log_path):
    """Start the project UDP server on an available UDP port."""
    server = subprocess.Popen(
        [
            sys.executable,
            str(SRC_DIR / "server.py"),
            "--host", "127.0.0.1",
            "--port", "0",
            "--log", str(log_path),
        ],
        cwd=str(SRC_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    # server.py supports port 0 but does not print the chosen port
    # in a machine-readable form, so this helper uses a reserved
    # test port instead in run_test().
    return server


def run_test(recovery_enabled):
    mode = "recovery_on" if recovery_enabled else "recovery_off"

    with tempfile.TemporaryDirectory(prefix="udp_recovery_") as temp:
        temp_dir = Path(temp)
        server_log = temp_dir / "server.csv"
        client_log = temp_dir / "client.csv"
        summary_path = temp_dir / "summary.json"

        # Reserve a local port for the server.
        reservation = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        reservation.bind(("127.0.0.1", 0))
        server_port = reservation.getsockname()[1]
        reservation.close()

        server = subprocess.Popen(
            [
                sys.executable,
                str(SRC_DIR / "server.py"),
                "--host", "127.0.0.1",
                "--port", str(server_port),
                "--log", str(server_log),
            ],
            cwd=str(SRC_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        proxy = None
        try:
            # Wait briefly for the server to bind.
            time.sleep(0.3)

            proxy = UDPBlackoutProxy(
                0,
                ("127.0.0.1", server_port),
                BLACKOUT_SECONDS,
            )
            proxy.start()

            command = [
                sys.executable,
                str(SRC_DIR / "client.py"),
                "--server", "127.0.0.1",
                "--port", str(proxy.port),
                "--duration", str(TEST_DURATION),
                "--rate", str(SEND_RATE),
                "--client-id", "1",
                "--recovery", "on" if recovery_enabled else "off",
                "--log", str(client_log),
                "--summary", str(summary_path),
            ]

            result = subprocess.run(
                command,
                cwd=str(SRC_DIR),
                timeout=TEST_DURATION + 10,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    f"Client failed in {mode}:\n{result.stdout}\n"
                    f"{result.stderr}"
                )

            # Give the server time to flush its log on shutdown.
            server.send_signal(__import__("signal").SIGINT)
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()

            received = 0
            if server_log.exists():
                with open(server_log, newline="", encoding="utf-8") as file:
                    received = sum(1 for _ in csv.DictReader(file))

            print(f"\nTest mode: {mode}")
            print(f"Server DATA arrivals (including retransmissions): {received}")
            print(f"Proxy forwarded packets: {proxy.forwarded_packets}")
            print(f"Proxy dropped packets: {proxy.dropped_packets}")
            print("Client output:")
            print(result.stdout.strip())

            return {
                "mode": mode,
                "server_arrivals": received,
                "proxy_forwarded": proxy.forwarded_packets,
                "proxy_dropped": proxy.dropped_packets,
            }

        finally:
            if proxy is not None:
                proxy.close()

            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


def main():
    if not (SRC_DIR / "server.py").exists():
        raise FileNotFoundError(f"Missing {SRC_DIR / 'server.py'}")
    if not (SRC_DIR / "client.py").exists():
        raise FileNotFoundError(f"Missing {SRC_DIR / 'client.py'}")

    print("Running UDP blackout recovery test...")
    print(f"Blackout: {BLACKOUT_SECONDS}s")
    print(f"Client duration: {TEST_DURATION}s")
    print(f"Send rate: {SEND_RATE} messages/s")

    recovery_on = run_test(True)
    recovery_off = run_test(False)

    print("\nComparison")
    print("Recovery ON server arrivals:", recovery_on["server_arrivals"])
    print("Recovery OFF server arrivals:", recovery_off["server_arrivals"])
    print(
        "\nNote: server arrivals count retransmitted duplicates as arrivals. "
        "Use unique (client_id, seq) values to calculate unique delivered "
        "messages."
    )


if __name__ == "__main__":
    main()