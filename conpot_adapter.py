import argparse
import glob
import re
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--logs", default="logs")
    parser.add_argument("--store", default="data/events.jsonl")
    args = parser.parse_args()

    store = EventStore(args.store)
    files = sorted(glob.glob(f"{args.logs}/*/conpot.log"))
    if not files:
        print(f"No Conpot logs found under {args.logs}/")
        return

    count = 0
    for filename in files:
        asset = f"conpot-{Path(filename).parent.name}"
        with open(filename, encoding="utf-8", errors="replace") as log:
            for line in log:
                match = LINE.match(line.rstrip("\n"))
                if not match:
                    continue

                traffic = MODBUS.search(match.group(2))
                if not traffic:
                    continue

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

                event = SecurityEvent(
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
                store.append(event)
                count += 1
                print(
                    f"{timestamp} | {ip} | {asset} | "
                    f"{event_type} | FC={fc} | response={response}"
                )

    print(f"Processed {count} real Modbus log records into {args.store}")

if __name__ == "__main__":
    main()
