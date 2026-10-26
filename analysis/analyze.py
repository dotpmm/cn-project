
#!/usr/bin/env python3
"""
Analyze UDP + SDN experiment results.

Features:
- Reads client/server CSV logs recursively.
- Reads client_summary.json files when available.
- Calculates unique received messages, duplicate arrivals,
  packet delivery ratio, loss, retransmissions, and latency.
- Reads events.json for failure and restoration timestamps.
- Exports summary.csv, summary.md, and optional latency plots.

Run from the repository root:
    python3 analysis/analyze.py

Optional:
    python3 analysis/analyze.py --input results --output analysis/output
"""

import argparse
import csv
import json
import math
import re
import statistics
from pathlib import Path


def normalize(value):
    """Normalize a column name for flexible matching."""
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def find_column(fieldnames, candidates):
    """Find a CSV column using a list of possible names."""
    normalized = {normalize(name): name for name in fieldnames}

    for candidate in candidates:
        key = normalize(candidate)
        if key in normalized:
            return normalized[key]

    # Permit columns such as avg_rtt_ms or message_seq_number.
    for candidate in candidates:
        key = normalize(candidate)
        if len(key) >= 4:
            for normalized_name, original_name in normalized.items():
                if key in normalized_name:
                    return original_name

    return None


def to_number(value):
    """Convert a value to float, returning None when invalid."""
    if value is None:
        return None

    try:
        result = float(str(value).strip())
        return result if math.isfinite(result) else None
    except (TypeError, ValueError):
        return None


def read_csv(path):
    """Read a CSV file and return its headers and rows."""
    try:
        with path.open("r", newline="", encoding="utf-8-sig") as file:
            reader = csv.DictReader(file)
            if not reader.fieldnames:
                return [], []
            return reader.fieldnames, list(reader)
    except (OSError, csv.Error) as exc:
        print(f"WARNING: Could not read {path}: {exc}")
        return [], []


def read_json(path):
    """Read JSON safely."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def first_number(data, names):
    """Find a numeric field in a JSON dictionary."""
    if not isinstance(data, dict):
        return None

    normalized = {normalize(k): v for k, v in data.items()}

    for name in names:
        key = normalize(name)
        if key in normalized:
            number = to_number(normalized[key])
            if number is not None:
                return number

    return None


def summarize_client(path):
    """Summarize a client CSV using common logging conventions."""
    headers, rows = read_csv(path)

    if not headers:
        return {}

    seq_col = find_column(
        headers,
        ["seq", "sequence", "sequence_number", "seq_num", "message_id"],
    )
    type_col = find_column(
        headers,
        ["type", "event", "event_type", "message_type", "status", "action"],
    )
    latency_col = find_column(
        headers,
        [
            "rtt_ms",
            "latency_ms",
            "round_trip_time_ms",
            "rtt",
            "latency",
            "round_trip_ms",
        ],
    )
    retrans_col = find_column(
        headers,
        ["retransmissions", "retransmit_count", "retries", "retry_count"],
    )
    received_col = find_column(
        headers,
        ["ack_received", "acknowledged", "acked", "success"],
    )

    latencies = []
    sequence_ids = set()
    ack_sequences = set()
    retransmission_rows = 0
    total_rows = len(rows)

    for row in rows:
        event = str(row.get(type_col, "")).strip().upper() if type_col else ""

        # Prefer an explicit retransmission count when available.
        if retrans_col:
            number = to_number(row.get(retrans_col))
            if number is not None:
                retransmission_rows += int(number)
        elif any(word in event for word in ("RETRANSMIT", "RETRY")):
            retransmission_rows += 1

        if latency_col:
            latency = to_number(row.get(latency_col))
            if latency is not None and latency >= 0:
                latencies.append(latency)

        seq_value = row.get(seq_col) if seq_col else None
        seq_value = str(seq_value).strip() if seq_value is not None else ""

        if seq_value and seq_value.lower() not in ("none", "nan"):
            if any(word in event for word in ("SEND", "DATA", "MESSAGE")):
                sequence_ids.add(seq_value)

            if "ACK" in event and not any(
                word in event for word in ("SEND", "WAIT", "TIMEOUT")
            ):
                ack_sequences.add(seq_value)

        if received_col and seq_value:
            flag = str(row.get(received_col, "")).strip().lower()
            if flag in ("1", "true", "yes", "success", "acked"):
                ack_sequences.add(seq_value)

    return {
        "client_csv": str(path),
        "client_rows": total_rows,
        "client_unique_sequences": len(sequence_ids) or None,
        "client_ack_sequences": len(ack_sequences) or None,
        "client_retransmissions": retransmission_rows,
        "client_latency_samples": len(latencies),
        "client_avg_latency_ms": (
            statistics.mean(latencies) if latencies else None
        ),
        "client_median_latency_ms": (
            statistics.median(latencies) if latencies else None
        ),
        "client_max_latency_ms": max(latencies) if latencies else None,
        "_latencies": latencies,
    }


def summarize_server(path):
    """Summarize server arrivals and unique message identifiers."""
    headers, rows = read_csv(path)

    if not headers:
        return {}

    seq_col = find_column(
        headers,
        ["seq", "sequence", "sequence_number", "seq_num", "message_id"],
    )
    client_col = find_column(
        headers,
        ["client_id", "client", "source_client"],
    )
    type_col = find_column(
        headers,
        ["type", "event", "event_type", "message_type"],
    )
    duplicate_col = find_column(
        headers,
        ["duplicate", "is_duplicate", "duplicate_message"],
    )

    data_rows = []
    unique_ids = set()
    duplicate_count = 0

    for row in rows:
        event = str(row.get(type_col, "")).strip().upper() if type_col else ""

        if event and not any(word in event for word in ("DATA", "MESSAGE")):
            continue

        data_rows.append(row)

        seq = str(row.get(seq_col, "")).strip() if seq_col else ""
        client = str(row.get(client_col, "")).strip() if client_col else ""

        if seq and seq.lower() not in ("none", "nan"):
            unique_ids.add((client, seq))

        if duplicate_col:
            flag = str(row.get(duplicate_col, "")).strip().lower()
            if flag in ("1", "true", "yes"):
                duplicate_count += 1

    return {
        "server_csv": str(path),
        "server_data_arrivals": len(data_rows),
        "server_unique_messages": len(unique_ids) if seq_col else None,
        "server_duplicate_count": (
            duplicate_count if duplicate_col else None
        ),
    }


def summarize_events(path):
    """Extract failure and restoration times from events.json."""
    data = read_json(path)
    if not isinstance(data, list):
        return {}

    down_time = None
    up_time = None
    route_update_times = []

    for item in data:
        if not isinstance(item, dict):
            continue

        event = str(item.get("event", "")).lower()
        timestamp = to_number(item.get("time_seconds"))

        if timestamp is None:
            continue

        if "primary_link_down" in event or "link_down" in event:
            if down_time is None:
                down_time = timestamp

        if "primary_link_restored" in event or "link_up" in event:
            if up_time is None:
                up_time = timestamp

        if "routes_updated" in event:
            route_update_times.append(timestamp)

    return {
        "failure_time_seconds": down_time,
        "restoration_time_seconds": up_time,
        "recorded_route_update_count": len(route_update_times),
    }


def find_first(directory, filename):
    """Find the first matching file within a run directory."""
    matches = sorted(directory.rglob(filename))
    return matches[0] if matches else None


def analyze_run(run_dir):
    """Analyze one experiment directory."""
    result = {
        "run": run_dir.name,
        "run_directory": str(run_dir),
    }

    client_summary = find_first(run_dir, "client_summary.json")
    if client_summary:
        data = read_json(client_summary)
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (str, int, float, bool)) or value is None:
                    result["summary_" + str(key)] = value

    client_csv = find_first(run_dir, "client.csv")
    if client_csv:
        result.update(summarize_client(client_csv))

    server_csv = find_first(run_dir, "server.csv")
    if server_csv:
        result.update(summarize_server(server_csv))

    events_json = find_first(run_dir, "events.json")
    if events_json:
        result.update(summarize_events(events_json))

    # Derive a delivery ratio only when the denominator and numerator
    # are available and represent comparable unique messages.
    sent = first_number(
        result,
        [
            "summary_messages_sent",
            "summary_total_sent",
            "summary_sent",
            "summary_packets_sent",
        ],
    )
    acknowledged = first_number(
        result,
        [
            "summary_messages_acknowledged",
            "summary_acked",
            "summary_acknowledged",
            "summary_total_acked",
        ],
    )

    if sent is not None and acknowledged is not None and sent > 0:
        result["delivery_ratio_percent"] = min(
            100.0, acknowledged / sent * 100.0
        )
        result["reported_loss_percent"] = max(
            0.0, (sent - acknowledged) / sent * 100.0
        )

    down = to_number(result.get("failure_time_seconds"))
    updated = to_number(result.get("restoration_time_seconds"))

    if down is not None and updated is not None and updated >= down:
        result["link_down_duration_seconds"] = updated - down

    return result


def write_csv(path, rows):
    """Write result dictionaries with a combined set of columns."""
    columns = []
    for row in rows:
        for key in row:
            if key.startswith("_"):
                continue
            if key not in columns:
                columns.append(key)

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()

        for row in rows:
            writer.writerow({
                key: value
                for key, value in row.items()
                if not key.startswith("_")
            })


def write_markdown(path, rows):
    """Write a compact report of available metrics."""
    metrics = [
        ("Run", "run"),
        ("Delivery ratio (%)", "delivery_ratio_percent"),
        ("Reported loss (%)", "reported_loss_percent"),
        ("Server arrivals", "server_data_arrivals"),
        ("Unique server messages", "server_unique_messages"),
        ("Retransmissions", "client_retransmissions"),
        ("Average latency (ms)", "client_avg_latency_ms"),
        ("Maximum latency (ms)", "client_max_latency_ms"),
        ("Link-down time (s)", "failure_time_seconds"),
        ("Link-restored time (s)", "restoration_time_seconds"),
    ]

    with path.open("w", encoding="utf-8") as file:
        file.write("# UDP + SDN Experiment Analysis\n\n")
        file.write(
            "Missing values mean the required field was not available "
            "in the input logs. Do not interpret them as zero.\n\n"
        )
        file.write("| " + " | ".join(label for label, _ in metrics) + " |\n")
        file.write("|" + "|".join("---" for _ in metrics) + "|\n")

        for row in rows:
            values = []
            for _, key in metrics:
                value = row.get(key)
                if value is None or value == "":
                    values.append("N/A")
                elif isinstance(value, float):
                    values.append(f"{value:.3f}")
                else:
                    values.append(str(value))
            file.write("| " + " | ".join(values) + " |\n")


def make_latency_plot(output_dir, rows):
    """Create a latency plot when matplotlib is installed."""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is not installed; skipping latency plot.")
        return

    plotted = False
    plt.figure(figsize=(10, 5))

    for row in rows:
        values = row.get("_latencies", [])
        if values:
            plt.plot(
                range(1, len(values) + 1),
                values,
                label=row["run"],
                linewidth=1,
            )
            plotted = True

    if not plotted:
        plt.close()
        print("No recognized latency samples; skipping latency plot.")
        return

    plt.xlabel("Latency sample")
    plt.ylabel("Latency (ms)")
    plt.title("UDP Client Latency Across Experiments")
    plt.grid(True, alpha=0.3)
    plt.legend(fontsize="small")
    plt.tight_layout()
    output = output_dir / "latency_comparison.png"
    plt.savefig(output, dpi=150)
    plt.close()
    print(f"Latency plot: {output}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze UDP/SDN experiment logs."
    )
    parser.add_argument("--input", default="results")
    parser.add_argument("--output", default="analysis/output")
    parser.add_argument(
        "--no-plot",
        action="store_true",
        help="Do not generate the latency plot.",
    )
    args = parser.parse_args()

    input_dir = Path(args.input).resolve()
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_dir.exists():
        raise SystemExit(f"Input directory does not exist: {input_dir}")

    # Treat each immediate child directory as an experiment run.
    run_dirs = sorted(
        path for path in input_dir.iterdir() if path.is_dir()
    )

    if not run_dirs:
        # Also allow logs directly inside the input directory.
        run_dirs = [input_dir]

    rows = []
    for run_dir in run_dirs:
        row = analyze_run(run_dir)

        has_data = any(
            key in row
            for key in (
                "client_csv",
                "server_csv",
                "summary_messages_sent",
                "summary_total_sent",
                "summary_sent",
                "failure_time_seconds",
            )
        )

        if has_data:
            rows.append(row)
            print(f"Analyzed: {run_dir}")
        else:
            print(f"Skipped: {run_dir} (no recognized experiment logs)")

    if not rows:
        raise SystemExit(
            "No experiment logs found. Check the --input path and filenames."
        )

    csv_path = output_dir / "summary.csv"
    markdown_path = output_dir / "summary.md"

    write_csv(csv_path, rows)
    write_markdown(markdown_path, rows)

    if not args.no_plot:
        make_latency_plot(output_dir, rows)

    print("\nAnalysis complete.")
    print(f"CSV summary:      {csv_path}")
    print(f"Markdown summary: {markdown_path}")


if __name__ == "__main__":
    main()