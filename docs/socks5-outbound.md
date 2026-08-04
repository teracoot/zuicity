# SOCKS5 outbound for zuicity-server

Route all accepted client TCP/UDP destinations through one upstream SOCKS5
proxy (for example a local Hysteria/Xray/sing-box SOCKS5 exit).

## Operator model

```text
zuicity-client / dae
        |
        | juicity/zuicity
        v
zuicity-server
        |
        | SOCKS5 CONNECT / UDP ASSOCIATE
        v
upstream SOCKS5 VPN
        |
        v
final destination
```

Direct mode remains the default when neither `outbound` nor `dialer_link` is set.

## Recommended config

```json
{
  "listen": "0.0.0.0:61881",
  "users": {
    "00000000-0000-0000-0000-000000000000": "my_password"
  },
  "certificate": "/etc/zuicity/fullchain.pem",
  "private_key": "/etc/zuicity/private.key",
  "congestion_control": "bbr",
  "log_level": "info",
  "outbound": {
    "type": "socks5",
    "server": "127.0.0.1",
    "server_port": 10808
  }
}
```

Optional auth:

```json
"outbound": {
  "type": "socks5",
  "server": "127.0.0.1",
  "server_port": 10808,
  "username": "user",
  "password": "pass"
}
```

## Compatibility with dialer_link

The structured `outbound` block is normalized into the existing high-performance
`dialer_link` path:

```text
outbound socks5 127.0.0.1:10808
  -> dialer_link = "socks5://127.0.0.1:10808"
```

You may still set `dialer_link` directly:

```json
"dialer_link": "socks5://127.0.0.1:10808"
```

If both are present, they must resolve to the same link or validation fails.

## Environment overrides

Installer-friendly overrides:

```bash
ZUICITY_OUTBOUND_TYPE=socks5
ZUICITY_OUTBOUND_SERVER=127.0.0.1
ZUICITY_OUTBOUND_PORT=10808
ZUICITY_OUTBOUND_USERNAME=
ZUICITY_OUTBOUND_PASSWORD=
```

Non-empty JSON fields take precedence over environment values. Empty environment
values are ignored, and an invalid `ZUICITY_OUTBOUND_PORT` fails startup instead
of being treated as a missing setting.

## UDP behavior

When SOCKS5 outbound is configured, UDP destinations use SOCKS5 UDP ASSOCIATE
through the same upstream. There is no silent blackhole: dial/associate failures
surface as normal session errors and leave the server process running.

SOCKS5 DNS resolution, TCP connection, method selection, authentication, and
CONNECT/UDP ASSOCIATE negotiation share a 10-second setup deadline. A timeout
fails only that client session, closes its stalled proxy socket, and leaves the
server available for later sessions.

## Performance notes

- Direct mode is unchanged when outbound is absent.
- SOCKS5 mode only adds the CONNECT/ASSOCIATE setup hop.
- After setup, traffic reuses the existing bidirectional relay path.
