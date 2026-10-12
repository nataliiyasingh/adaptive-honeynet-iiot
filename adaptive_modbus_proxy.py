import asyncio
import json
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
ATTACKERS = {}


def record_action(action):
    POLICY_LOG.parent.mkdir(parents=True, exist_ok=True)
    with POLICY_LOG.open("a", encoding="utf-8") as file:
        file.write(json.dumps(action) + "\n")


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

    state = ATTACKERS.setdefault(source_ip, AttackerState(source_ip=source_ip))
    print(f"Client {source_ip} connected", flush=True)

    try:
        while True:
            request = await read_frame(client_reader)
            function_code = request[7]

            if function_code in {1, 2, 3, 4}:
                event_type, severity = "register_enumeration", 3
            elif function_code in {5, 6, 15, 16, 21, 22, 23}:
                event_type, severity = "register_write_attempt", 5
            else:
                event_type, severity = "modbus_connection", 2

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
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
            process_event(state, {
                "event_type": event_type,
            })

            policy = select_policy(state.score)
            previous_mode = state.deception_mode
            state.classification = policy.classification
            state.deception_mode = policy.deception_mode

            print(
                f"{source_ip} | FC={function_code} | "
                f"score={state.score} | mode={policy.deception_mode}",
                flush=True,
            )

            upstream_writer.write(request)
            await upstream_writer.drain()
            response = await read_frame(upstream_reader)

            # Demonstrable adaptive intervention:
            # replace an illegal-address exception to an eligible read
            # with a plausible decoy register response at high risk.
            if (
                policy.deception_mode == "high_deception"
                and function_code in {3, 4}
                and len(response) >= 9
                and response[7] == (function_code | 0x80)
                and response[8] == 2
            ):
                response = (
                    response[:4]
                    + b"\x00\x05"
                    + response[6:7]
                    + bytes([function_code, 2, 0x01, 0xA4])
                )

                action = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_ip": source_ip,
                    "score": state.score,
                    "classification": policy.classification,
                    "mode": policy.deception_mode,
                    "action": "substituted_decoy_register_response",
                    "register_value_hex": "01a4",
                    "reason": policy.reason,
                }
                record_action(action)
                print(
                    "ADAPTIVE ACTION: substituted decoy register response",
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
