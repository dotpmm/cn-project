
import argparse
import csv
import json
import os
import queue
import signal
import socket
import threading
import time

from protocol import (
    ACK,
    DATA,
    PROBE,
    PROBE_ACK,
    HEADER_SIZE,
    encode_message,
    decode_message,
)

STOP = threading.Event()
PACKETS = queue.Queue()
SEEN = set()
SEEN_LOCK = threading.Lock()
LOG_LOCK = threading.Lock()
LOG_ROWS = []


def handle_packet(sock, packet, address):
    message = decode_message(packet)
    if message is None:
        return

    msg_type = message["type"]
    client_id = message["client_id"]
    seq = message["seq"]
    timestamp_ns = message["timestamp_ns"]

    if msg_type == DATA:
        key = (client_id, seq)

        with SEEN_LOCK:
            duplicate = key in SEEN
            SEEN.add(key)

        # ACK every valid DATA packet, including retransmissions.
        ack = encode_message(
            ACK,
            client_id,
            message["attempt"],
            seq,
            timestamp_ns,
        )
        sock.sendto(ack, address)

        with LOG_LOCK:
            LOG_ROWS.append({
                "arrival_time": time.time(),
                "client_id": client_id,
                "seq": seq,
                "attempt": message["attempt"],
                "duplicate": int(duplicate),
                "source_ip": address[0],
                "source_port": address[1],
            })

        print(
            f"DATA client={client_id} seq={seq} "
            f"attempt={message['attempt']} "
            f"{'(duplicate)' if duplicate else ''}"
        )

    elif msg_type == PROBE:
        response = encode_message(
            PROBE_ACK,
            client_id,
            message["attempt"],
            0,
            timestamp_ns,
        )
        sock.sendto(response, address)


def worker(sock):
    while not STOP.is_set():
        try:
            item = PACKETS.get(timeout=0.2)
        except queue.Empty:
            continue

        if item is None:
            PACKETS.task_done()
            break

        packet, address = item
        try:
            handle_packet(sock, packet, address)
        except OSError as exc:
            if not STOP.is_set():
                print(f"Socket error: {exc}")
        except Exception as exc:
            print(f"Packet processing error: {exc}")
        finally:
            PACKETS.task_done()


def save_logs(path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    with LOG_LOCK:
        rows = list(LOG_ROWS)

    with open(path, "w", newline="", encoding="utf-8") as file:
        columns = [
            "arrival_time", "client_id", "seq",
            "attempt", "duplicate", "source_ip", "source_port",
        ]
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} received DATA records to {path}")


def stop_server(signum, frame):
    STOP.set()


def main():
    parser = argparse.ArgumentParser(description="UDP reliability server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--log", default="server.csv")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, stop_server)
    signal.signal(signal.SIGTERM, stop_server)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    sock.settimeout(0.2)

    threads = [
        threading.Thread(target=worker, args=(sock,), daemon=True)
        for _ in range(max(1, args.workers))
    ]
    for thread in threads:
        thread.start()

    print(f"UDP server listening on {args.host}:{args.port}")

    try:
        while not STOP.is_set():
            try:
                packet, address = sock.recvfrom(65535)
            except socket.timeout:
                continue

            if len(packet) < HEADER_SIZE:
                continue

            PACKETS.put((packet, address))

    except OSError:
        if not STOP.is_set():
            raise
    finally:
        STOP.set()
        for _ in threads:
            PACKETS.put(None)
        for thread in threads:
            thread.join(timeout=1.0)
        sock.close()
        save_logs(args.log)


if __name__ == "__main__":
    main()