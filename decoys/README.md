# Decoy Layer — Conpot

## Image
`honeynet/conpot` (default template — Siemens S7-200 style device)

## Protocols enabled
Modbus, S7Comm, HTTP, SNMP, BACnet, IPMI, FTP, TFTP

## Known issue: internal port mismatch
This image runs with a `--force` flag that puts Conpot in "testing configuration,"
which binds services to non-default internal ports rather than their real ICS
defaults:

| Protocol | Expected port | Actual internal port |
|----------|---------------|----------------------|
| Modbus   | 502           | 5020                 |
| HTTP     | 80            | 8800                 |
| SNMP     | 161           | 16100                |

Fix: map host ports to the actual internal ports, not the ICS-standard ones:

    docker run -d --name conpot-default \
      -p 502:5020 \
      -p 80:8800 \
      -p 161:16100/udp \
      honeynet/conpot

## Verification (2026-10-05)
- `nc -zv 127.0.0.1 502` → open
- `nc -zv 127.0.0.1 80` → open
- `curl http://127.0.0.1:80` → HTTP 302, redirects to /index.html
  (consistent with a real embedded device's web interface behavior)
