import argparse
import glob
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from eventlog.schema import SecurityEvent
from eventlog.storage import EventStore

LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (.*)$"
)

MODBUS = re.compile(
    r"Modbus traffic from ([0-9a-fA-F:.]+): "
    r"\{'request': b'([0-9a-fA-F]*)'.*?"
    r"'function_code': (\d+).*?"
    r"'response': b'([0-9a-fA-F]*)'"
)


def load_state(path):
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise RuntimeError(
            f"Cannot read ingestion checkpoint {path}: {exc}. "
            "Preserve the file and inspect it before continuing."
        ) from exc


def save_state(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(state, indent=2), encoding="utf-8"
    )
    os.replace(temporary, path)


def parse_event(line, asset):
    match = LINE.match(line.rstrip("\n"))
    if not match:
        return None

    traffic = MODBUS.search(match.group(2))
    if not traffic:
        return None

    ip, request, fc_text, response = traffic.groups()
    fc = int(fc_text)

    if fc in {1, 2, 3, 4}:
        event_type, severity = "register_enumeration", 3
    elif fc in {5, 6, 15, 16, 21, 22, 23}:
        event_type, severity = "register_write_attempt", 5
    else:
        event_type, severity = "modbus_connection", 2

    timestamp = datetime.strptime(
        match.group(1), "%Y-%m-%d %H:%M:%S,%f"
    ).replace(tzinfo=timezone.utc).isoformat()

    return SecurityEvent(
        timestamp=timestamp,
        source_ip=ip,
        asset=asset,
        protocol="modbus",
        event_type=event_type,
        severity=severity,
        details={
            "function_code": fc,
            "request": request,
            "response": response,
        },
    )


def process_file(filename, store, state, state_path):
    path = Path(filename)
    asset = f"conpot-{path.parent.name}"
    stat = path.stat()
    key = str(path.resolve())

    previous = state.get(key, {})
    same_file = previous.get("device") == stat.st_dev and (
        previous.get("inode") == stat.st_ino
    )

    if same_file and stat.st_size >= previous.get("offset", 0):
        offset = previous.get("offset", 0)
    else:
        # New file or truncation: read this file from its beginning.
        offset = 0

    count = 0

    with path.open("r", encoding="utf-8", errors="replace") as log:
        log.seek(offset)

        while True:
            start = log.tell()
            line = log.readline()

            if not line:
                break

            # Do not advance past a partial line; it may still be written.
            if not line.endswith("\n"):
                log.seek(start)
                break

            event = parse_event(line, asset)

            if event is not None:
                store.append(event)
                count += 1
                print(
                    f"{event.timestamp} | {event.source_ip} | "
                    f"{event.asset} | {event.event_type} | "
                    f"FC={event.details['function_code']} | "
                    f"response={event.details['response']}",
                    flush=True,
                )

            # Save progress after each complete log line.
            state[key] = {
                "device": stat.st_dev,
                "inode": stat.st_ino,
                "offset": log.tell(),
            }
            save_state(state_path, state)

    return count


def main():
    parser = argparse.ArgumentParser(
        description="Incremental Conpot Modbus log ingestion"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Process currently available log data and exit",
    )
    parser.add_argument("--logs", default="logs")
    parser.add_argument("--store", default="data/events.jsonl")
    parser.add_argument(
        "--state", default="data/conpot_adapter_state.json"
    )
    parser.add_argument(
        "--interval", type=float, default=2.0,
        help="Seconds between scans in continuous mode",
    )
    args = parser.parse_args()

    if args.interval <= 0:
        parser.error("--interval must be greater than zero")

    store = EventStore(args.store)
    state_path = Path(args.state)
    state = load_state(state_path)

    print(
        f"Watching {args.logs} for Conpot Modbus logs. "
        f"Mode: {'once' if args.once else 'continuous'}",
        flush=True,
    )

    try:
        while True:
            files = sorted(
                glob.glob(f"{args.logs}/*/conpot.log")
            )

            if not files:
                print(
                    f"No Conpot logs found under {args.logs}/",
                    flush=True,
                )

            total = 0
            for filename in files:
                total += process_file(
                    filename, store, state, state_path
                )

            if total:
                print(
                    f"Ingested {total} new Modbus events.",
                    flush=True,
                )

            if args.once:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\nAdapter stopped.", flush=True)


if __name__ == "__main__":
    main()

