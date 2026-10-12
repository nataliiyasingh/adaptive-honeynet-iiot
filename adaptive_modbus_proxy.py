import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from detection.behaviour import AttackerState, process_event
from deception.policy import select_policy
from eventlog.schema import SecurityEvent
from eventlog.storage import EventStore

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 1502
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 502

EVENT_STORE = EventStore("data/events.jsonl")
POLICY_LOG = Path("data/adaptive_actions.jsonl")
ATTACKER_STATE_FILE = Path("data/attacker_state.json")
ATTACKERS = {}


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def record_action(action):
    POLICY_LOG.parent.mkdir(parents=True, exist_ok=True)
    with POLICY_LOG.open("a", encoding="utf-8") as file:
        file.write(json.dumps(action) + "\n")


def load_attacker_states():
    if not ATTACKER_STATE_FILE.exists():
        return

    try:
        saved = json.loads(
            ATTACKER_STATE_FILE.read_text(encoding="utf-8")
        )
        for source_ip, item in saved.items():
            state = AttackerState(source_ip=source_ip)
            state.score = int(item.get("score", 0))
            state.observed_events = list(
                item.get("observed_events", [])
            )
            state.classification = item.get(
                "classification", "unknown"
            )
            state.deception_mode = item.get(
                "deception_mode", "baseline"
            )
            ATTACKERS[source_ip] = state

        print(
            f"Loaded persistent state for {len(ATTACKERS)} source(s)",
            flush=True,
        )
    except (OSError, ValueError, TypeError) as exc:
        print(f"Could not load attacker state: {exc}", flush=True)


def save_attacker_states():
    ATTACKER_STATE_FILE.parent.mkdir(
        parents=True, exist_ok=True
    )
    payload = {
        ip: {
            "score": state.score,
            "observed_events": state.observed_events,
            "classification": state.classification,
            "deception_mode": state.deception_mode,
        }
        for ip, state in ATTACKERS.items()
    }

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=ATTACKER_STATE_FILE.parent,
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            json.dump(payload, temp_file, indent=2)
            temp_file.write("\n")

        os.replace(temp_path, ATTACKER_STATE_FILE)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


async def read_frame(reader):
    header = await reader.readexactly(6)
    length = int.from_bytes(header[4:6], "big")
    if length < 2 or length > 254:
        raise ValueError(f"Invalid Modbus frame length: {length}")
    return header + await reader.readexactly(length)


async def handle_client(client_reader, client_writer):
    peer = client_writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"

    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            UPSTREAM_HOST, UPSTREAM_PORT
        )
    except OSError as exc:
        print(f"Cannot connect to Conpot: {exc}", flush=True)
        client_writer.close()
        await client_writer.wait_closed()
        return

    state = ATTACKERS.setdefault(
        source_ip, AttackerState(source_ip=source_ip)
    )
    print(f"Client {source_ip} connected", flush=True)

    try:
        while True:
            request = await read_frame(client_reader)
            if len(request) < 8:
                raise ValueError("Modbus request is too short")

            function_code = request[7]

            if function_code in {1, 2, 3, 4}:
                event_type, severity = "register_enumeration", 3
            elif function_code in {5, 6, 15, 16, 21, 22, 23}:
                event_type, severity = "register_write_attempt", 5
            else:
                event_type, severity = "modbus_connection", 2

            event = SecurityEvent(
                timestamp=now_utc(),
                source_ip=source_ip,
                asset="conpot-default-via-adaptive-proxy",
                protocol="modbus",
                event_type=event_type,
                severity=severity,
                details={
                    "function_code": function_code,
                    "request": request.hex(),
                },
            )
            EVENT_STORE.append(event)

            previous_mode = state.deception_mode
            process_event(state, {"event_type": event_type})
            policy = select_policy(state.score)
            state.classification = policy.classification
            state.deception_mode = policy.deception_mode
            save_attacker_states()

            if previous_mode != state.deception_mode:
                record_action({
                    "timestamp": now_utc(),
                    "source_ip": source_ip,
                    "score": state.score,
                    "classification": state.classification,
                    "mode": state.deception_mode,
                    "action": "policy_transition",
                    "previous_mode": previous_mode,
                    "reason": policy.reason,
                })

            print(
                f"{source_ip} | FC={function_code} | "
                f"score={state.score} | "
                f"classification={state.classification} | "
                f"mode={state.deception_mode}",
                flush=True,
            )

            upstream_writer.write(request)
            await upstream_writer.drain()
            response = await read_frame(upstream_reader)

            if (
                state.deception_mode == "high_deception"
                and function_code in {3, 4}
                and len(response) >= 9
                and response[7] == (function_code | 0x80)
                and response[8] == 2
            ):
                # Preserve Conpot's actual response; do not inject an
                # unvalidated synthetic register value.
                record_action({
                    "timestamp": now_utc(),
                    "source_ip": source_ip,
                    "score": state.score,
                    "classification": state.classification,
                    "mode": state.deception_mode,
                    "action": "upstream_exception_passed_through",
                    "upstream_response_hex": response.hex(),
                    "reason": (
                        "Synthetic response substitution disabled; "
                        "preserved the upstream Conpot response."
                    ),
                })
                print(
                    "ADAPTIVE ACTION: passed through Conpot exception; "
                    "synthetic substitution disabled",
                    flush=True,
                )

            client_writer.write(response)
            await client_writer.drain()

    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    except (ValueError, OSError) as exc:
        print(f"Connection error for {source_ip}: {exc}", flush=True)
    finally:
        upstream_writer.close()
        client_writer.close()
        await upstream_writer.wait_closed()
        await client_writer.wait_closed()
        print(f"Client {source_ip} disconnected", flush=True)


async def main():
    load_attacker_states()
    server = await asyncio.start_server(
        handle_client, LISTEN_HOST, LISTEN_PORT
    )
    print(
        f"Adaptive Modbus proxy listening on "
        f"{LISTEN_HOST}:{LISTEN_PORT}; upstream "
        f"{UPSTREAM_HOST}:{UPSTREAM_PORT}",
        flush=True,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAdaptive proxy stopped.", flush=True)
