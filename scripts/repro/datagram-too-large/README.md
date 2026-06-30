# DATAGRAM frame-too-large repro harness

This harness reproduces the TUIC native-UDP failure where `dae` logs a local
send/write error while routing traffic to the skOracle test endpoint:

```text
Failed to write UDP packet request. Try to remove old UDP endpoint and retry.
err="DATAGRAM frame too large"
Application error 0xfffffff0 (local): DATAGRAM frame too large
```

The known failing route was `domain(suffix: skoracle.zivle.com) -> test`, with
router logs showing `outbound=test`, `dialer=aws15`, and traffic to
`134.185.121.128:55211`.

## skOracle helper ports

Run these helpers on skOracle, preserving the scripts after the run:

```bash
python3 udp_echo.py --port 55211 --seconds 3600
python3 tcp_echo.py --port 55212 --seconds 3600
python3 udp_reply_source.py --port 55213 --seconds 3600
python3 tcp_source.py --port 55214 --seconds 3600
```

The prior remote helper paths were:

- `/tmp/skoracle_udp_echo.py`
- `/tmp/skoracle_tcp_echo.py`
- `/tmp/skoracle_udp_reply_source.py`
- `/tmp/skoracle_tcp_source.py`

## Known repro

From a client routed through the router, run:

```bash
python3 bidirectional_repro.py --host skoracle.zivle.com --seconds 330
```

A successful stress run prints nonzero TCP churn/upload counters, UDP echo
packets, and UDP source requests. The original failure appeared during a
330-second run with high error counts and the router log signatures above.

## Read-only router check

The router is an observation target only. Do not change router config, install
packages, restart networking/firewall/routing, restart `dae`, or restart proxy
services while using this harness.

Use `router_probe.py` only for read-only log inspection. It shells out to your
local `ssh` client and requires explicit connection inputs:

```bash
python3 router_probe.py \
  --router-host 192.168.100.1 \
  --router-user root \
  --since '2026-06-30 04:43:22' \
  --until '2026-06-30 04:48:57'
```

If the router needs a key or custom SSH option, pass it explicitly with
`--identity-file` or repeated `--ssh-option`. The script intentionally does not
read local credential/profile files and must not print secrets.
