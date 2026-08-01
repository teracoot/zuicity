#!/usr/bin/env python3
"""Render the matched four-product benchmark chart from summary.json.

Zero third-party dependencies: emits a standalone SVG plus a Markdown summary.
Input is the summary.json produced by scripts/benchmark/tcp_gso_suite.py.

Usage:
  python3 scripts/render-benchmark-chart.py <summary.json> [--out-dir DIR] \
       [--title TITLE]
"""
import argparse
import json
from pathlib import Path

LABELS = [
    ("candidate", ("Zuicity", "v0.4.0")),
    ("go-stock", ("Stock Go", "v0.5.0")),
    ("go-repaired", ("Repaired Go", "v0.5.0")),
    ("juicity-rs", ("juicity-rs", "beta.8")),
]
COLORS = {
    "candidate": "#147d64",
    "go-stock": "#386cb0",
    "go-repaired": "#d28b26",
    "juicity-rs": "#b44d3a",
}

METRICS = [
    ("on", "tcp_connect_rtt_ms", "TCP connect + RTT", "GSO on, ms", "lower"),
    ("on", "tcp_persistent_rtt_ms", "TCP persistent RTT", "GSO on, ms", "lower"),
    ("on", "tcp_throughput_mbps", "TCP throughput", "GSO on, 512 KiB echo", "higher"),
    ("off", "tcp_throughput_mbps", "TCP throughput", "GSO off, 512 KiB echo", "higher"),
]


def load_summary(summary_path):
    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    arms = summary["arms"]
    medians = {}
    for tag, _ in LABELS:
        medians[tag] = {}
        for mode in ("on", "off"):
            for metric in (
                "tcp_connect_rtt_ms",
                "tcp_persistent_rtt_ms",
                "tcp_throughput_mbps",
            ):
                medians[tag][(mode, metric)] = float(
                    arms[tag][mode]["metrics"][metric]["median"]
                )
    rotations = int(
        arms["candidate"]["on"]["metrics"]["tcp_throughput_mbps"][
            "n_rotation_rows"
        ]
    )
    return medians, rotations


def esc(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def format_value(metric, value):
    if metric == "tcp_throughput_mbps":
        return f"{value:,.2f}"
    return f"{value:.3f}"


def panel_svg(x0, y0, w, h, title, context, direction, metric, data):
    vmax = max(value for _, _, value in data)
    pad_top, pad_bottom, pad_left = 62, 62, 12
    plot_h = h - pad_top - pad_bottom
    plot_w = w - 2 * pad_left
    n = len(data)
    slot = plot_w / n
    bar_w = min(78, slot * 0.58)
    parts = []
    better = "lower is better" if direction == "lower" else "higher is better"
    parts.append(
        f'<text x="{x0 + w / 2:.1f}" y="{y0 + 23:.1f}" text-anchor="middle" '
        f'font-size="20" font-weight="700" fill="#15181b">{esc(title)}</text>'
    )
    parts.append(
        f'<text x="{x0 + w / 2:.1f}" y="{y0 + 43:.1f}" text-anchor="middle" '
        f'font-size="12" fill="#697077">{esc(context)} | {better}</text>'
    )
    base_y = y0 + pad_top + plot_h
    parts.append(
        f'<line x1="{x0 + pad_left:.1f}" y1="{base_y:.1f}" '
        f'x2="{x0 + pad_left + plot_w:.1f}" y2="{base_y:.1f}" '
        'stroke="#c7ccd1" stroke-width="1.5"/>'
    )
    for i, (tag, label, v) in enumerate(data):
        cx = x0 + pad_left + slot * i + slot / 2
        bh = max(2.5, (v / vmax) * plot_h)
        by = base_y - bh
        parts.append(
            f'<rect x="{cx - bar_w / 2:.1f}" y="{by:.1f}" width="{bar_w:.1f}" '
            f'height="{bh:.1f}" rx="4" fill="{COLORS[tag]}"/>'
        )
        parts.append(
            f'<text x="{cx:.1f}" y="{max(y0 + 56, by - 8):.1f}" text-anchor="middle" '
            f'font-size="13" font-weight="700" fill="#202428">'
            f'{esc(format_value(metric, v))}</text>'
        )
        parts.append(
            f'<text x="{cx:.1f}" y="{base_y + 20:.1f}" text-anchor="middle" '
            f'font-size="12" font-weight="600" fill="#30363b">{esc(label[0])}</text>'
        )
        parts.append(
            f'<text x="{cx:.1f}" y="{base_y + 37:.1f}" text-anchor="middle" '
            f'font-size="11" fill="#697077">{esc(label[1])}</text>'
        )
    return "\n".join(parts)


def render_svg(medians, title, rotations, subtitle=None):
    cols, rows = 2, 2
    pw, ph = 570, 315
    margin_x, gap_x, margin_top = 25, 10, 112
    W, H = 1200, 850
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="Arial, Helvetica, sans-serif">'
    ]
    out.append(f'<rect width="{W}" height="{H}" fill="#ffffff"/>')
    out.append(
        f'<text x="{W / 2:.1f}" y="38" text-anchor="middle" font-size="28" '
        f'font-weight="700" fill="#101315">{esc(title)}</text>'
    )
    sub = subtitle or (
        f"two-namespace veth | {rotations} balanced rotations | "
        "median of rotation-level row medians"
    )
    out.append(
        f'<text x="{W / 2:.1f}" y="65" text-anchor="middle" font-size="14" '
        f'fill="#586069">{esc(sub)}</text>'
    )
    out.append(
        f'<text x="{W / 2:.1f}" y="86" text-anchor="middle" font-size="13" '
        f'fill="#697077">64 accepted rows | 60/60/10 samples per row | 640 accepted transfers</text>'
    )
    for idx, (mode, metric, mtitle, context, direction) in enumerate(METRICS):
        r, c = divmod(idx, cols)
        x0 = margin_x + c * (pw + gap_x)
        y0 = margin_top + r * ph
        data = [(tag, label, medians[tag][(mode, metric)]) for tag, label in LABELS]
        out.append(panel_svg(x0, y0, pw, ph, mtitle, context, direction, metric, data))
    out.append(
        f'<text x="{W / 2:.1f}" y="805" text-anchor="middle" font-size="13" '
        f'fill="#4f575e">Common 512 KiB workload; not the canonical 4 MiB campaign.</text>'
    )
    out.append(
        f'<text x="{W / 2:.1f}" y="827" text-anchor="middle" font-size="12" '
        f'fill="#697077">juicity-rs throughput CV: 155.85% on / 136.96% off; '
        f'stock Go on uses shipping client-off/server-on behavior.</text>'
    )
    out.append("</svg>")
    return "\n".join(out)


def render_markdown(medians, title, rotations, subtitle=None):
    sub = subtitle or "Two-namespace veth matched four-product benchmark"
    lines = [
        f"# {title}",
        "",
        f"{sub}; median of {rotations} accepted rotation-level row medians.",
        "",
        "| Implementation | GSO | TCP connect+RTT (ms) | TCP persistent RTT (ms) | TCP throughput (Mbps) |",
        "|---|---|---:|---:|---:|",
    ]
    for mode in ("on", "off"):
        for tag, label in LABELS:
            lines.append(
                f"| {' '.join(label)} | {mode} | "
                f"{medians[tag][(mode, 'tcp_connect_rtt_ms')]:.3f} | "
                f"{medians[tag][(mode, 'tcp_persistent_rtt_ms')]:.3f} | "
                f"{medians[tag][(mode, 'tcp_throughput_mbps')]:.2f} |"
            )
    lines.extend(
        [
            "",
            "Lower is better for RTT; higher is better for throughput.",
            "",
            "The common throughput payload was 512 KiB, not the canonical 4 MiB.",
            "",
        ]
    )
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("summary_json")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--title", default="Zuicity v0.4.0: matched four-product benchmark")
    ap.add_argument("--subtitle", default=None)
    args = ap.parse_args()

    medians, rotations = load_summary(args.summary_json)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    svg = render_svg(medians, args.title, rotations, args.subtitle)
    md = render_markdown(medians, args.title, rotations, args.subtitle)
    (out_dir / "benchmark-chart.svg").write_bytes(svg.encode("utf-8"))
    (out_dir / "benchmark-chart.md").write_bytes(md.encode("utf-8"))
    print(f"wrote {out_dir/'benchmark-chart.svg'}")
    print(f"wrote {out_dir/'benchmark-chart.md'}")
    print(md)


if __name__ == "__main__":
    main()
