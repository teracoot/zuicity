#!/usr/bin/env python3
"""Render a benchmark comparison chart from three-way results.jsonl.

Zero third-party dependencies: emits a standalone SVG (renders in any browse
and on GitHub) plus a Markdown summary. Input is the results.jsonl produced by
the two-namespace benchmark harness (one JSON object per implementation run).

Usage:
  python3 scripts/render-benchmark-chart.py <results.jsonl> [--out-dir DIR] \
      [--title TITLE]

Metrics charted (median of per-run medians):
  - TCP connect+RTT (ms, lower is better)
  - TCP persistent RTT (ms, lower is better)
  - TCP throughput (Mbps, higher is better)
  - UDP RTT (ms, lower is better)
"""
import argparse
import json
import statistics
import sys
from pathlib import Path

# tag -> display label; order defines bar orde
LABELS = [
    ("rust", "zuicity (this port)"),
    ("go", "juicity (Go upstream)"),
    ("juicityrs", "juicity-rs (other)"),
]
COLORS = {"rust": "#2f6f4f", "go": "#3060a8", "juicityrs": "#9a5b2e"}

METRICS = [
    ("tcp_connect_rtt", "median_ms", "TCP connect+RTT (ms)", "lower"),
    ("tcp_persistent_rtt", "median_ms", "TCP persistent RTT (ms)", "lower"),
    ("tcp_throughput_mbps", "median", "TCP throughput (Mbps)", "higher"),
    ("udp_rtt", "median_ms", "UDP RTT (ms)", "lower"),
]


def load_medians(jsonl_path):
    rows = [json.loads(l) for l in Path(jsonl_path).read_text().splitlines() if l.strip()]
    out = {}
    for tag, _ in LABELS:
        out[tag] = {}
        for metric, field, _t, _dir in METRICS:
            vals = []
            for r in rows:
                if r.get("tag") != tag:
                    continue
                item = r.get(metric)
                if item and item.get(field) is not None:
                    vals.append(float(item[field]))
            out[tag][metric] = statistics.median(vals) if vals else None
    return out, len(rows)


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def panel_svg(x0, y0, w, h, title, direction, data):
    # data: list of (tag, label, value-or-None)
    vals = [v for _, _, v in data if v is not None]
    vmax = max(vals) if vals else 1.0
    if vmax <= 0:
        vmax = 1.0
    pad_top, pad_bottom, pad_left = 44, 58, 8
    plot_h = h - pad_top - pad_bottom
    plot_w = w - 2 * pad_left
    n = len(data)
    slot = plot_w / n
    bar_w = slot * 0.56
    parts = []
    better = "lower is better" if direction == "lower" else "higher is better"
    parts.append(f'<text x="{x0 + w/2:.1f}" y="{y0+18:.1f}" text-anchor="middle" '
                 f'font-size="15" font-weight="700" fill="#1b1b1b">{esc(title)}</text>')
    parts.append(f'<text x="{x0 + w/2:.1f}" y="{y0+31:.1f}" text-anchor="middle" '
                 f'font-size="10" fill="#777">{better}</text>')
    base_y = y0 + pad_top + plot_h
    parts.append(f'<line x1="{x0+pad_left:.1f}" y1="{base_y:.1f}" '
                 f'x2="{x0+pad_left+plot_w:.1f}" y2="{base_y:.1f}" stroke="#ccc" stroke-width="1"/>')
    for i, (tag, label, v) in enumerate(data):
        cx = x0 + pad_left + slot * i + slot / 2
        if v is None:
            parts.append(f'<text x="{cx:.1f}" y="{base_y-6:.1f}" text-anchor="middle" '
                         f'font-size="11" fill="#b00">n/a</text>')
            bh = 0
        else:
            bh = (v / vmax) * plot_h
            by = base_y - bh
            parts.append(f'<rect x="{cx-bar_w/2:.1f}" y="{by:.1f}" width="{bar_w:.1f}" '
                         f'height="{bh:.1f}" rx="3" fill="{COLORS.get(tag,"#888")}"/>')
            label_v = f"{v:.2f}" if v < 100 else f"{v:.0f}"
            parts.append(f'<text x="{cx:.1f}" y="{by-5:.1f}" text-anchor="middle" '
                         f'font-size="11" font-weight="600" fill="#222">{label_v}</text>')
        # wrap label over up to 2 lines
        words = label.split(" ")
        mid = (len(words) + 1) // 2
        l1 = " ".join(words[:mid])
        l2 = " ".join(words[mid:])
        parts.append(f'<text x="{cx:.1f}" y="{base_y+16:.1f}" text-anchor="middle" '
                     f'font-size="10" fill="#333">{esc(l1)}</text>')
        if l2:
            parts.append(f'<text x="{cx:.1f}" y="{base_y+28:.1f}" text-anchor="middle" '
                         f'font-size="10" fill="#333">{esc(l2)}</text>')
    return "\n".join(parts)


def render_svg(medians, title, run_count, subtitle=None):
    cols, rows = 2, 2
    pw, ph = 380, 240
    margin_x, margin_top, margin_bottom = 20, 56, 30
    W = margin_x * 2 + cols * pw
    H = margin_top + rows * ph + margin_bottom
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
           f'viewBox="0 0 {W} {H}" font-family="DejaVu Sans, Arial, sans-serif">']
    out.append(f'<rect width="{W}" height="{H}" fill="#ffffff"/>')
    out.append(f'<text x="{W/2:.1f}" y="26" text-anchor="middle" font-size="20" '
               f'font-weight="700" fill="#111">{esc(title)}</text>')
    sub = subtitle or f"two-namespace veth benchmark, median of {run_count // 3} reps"
    out.append(f'<text x="{W/2:.1f}" y="44" text-anchor="middle" font-size="11" '
               f'fill="#666">{esc(sub)} (lower RTT / higher throughput = better)</text>')
    for idx, (metric, field, mtitle, direction) in enumerate(METRICS):
        r, c = divmod(idx, cols)
        x0 = margin_x + c * pw
        y0 = margin_top + r * ph
        data = [(tag, label, medians[tag][metric]) for tag, label in LABELS]
        out.append(panel_svg(x0, y0, pw, ph, mtitle, direction, data))
    out.append("</svg>")
    return "\n".join(out)


def render_markdown(medians, title, run_count, subtitle=None):
    sub = subtitle or "Two-namespace veth benchmark"
    lines = [f"# {title}", "",
             f"{sub}, median of {run_count // 3} reps per implementation.",
             "", "| Implementation | TCP connect+RTT (ms) | TCP persistent RTT (ms) | "
             "TCP throughput (Mbps) | UDP RTT (ms) |",
             "|---|---:|---:|---:|---:|"]

    def fmt(v):
        if v is None:
            return "n/a"
        return f"{v:.3f}" if v < 100 else f"{v:.1f}"
    for tag, label in LABELS:
        m = medians[tag]
        lines.append(f"| {label} | {fmt(m['tcp_connect_rtt'])} | {fmt(m['tcp_persistent_rtt'])} "
                     f"| {fmt(m['tcp_throughput_mbps'])} | {fmt(m['udp_rtt'])} |")
    lines.append("")
    lines.append("Lower is better for RTT metrics; higher is better for throughput.")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--title", default="zuicity QUIC proxy performance")
    ap.add_argument("--subtitle", default=None)
    args = ap.parse_args()

    medians, run_count = load_medians(args.jsonl)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    svg = render_svg(medians, args.title, run_count, args.subtitle)
    md = render_markdown(medians, args.title, run_count, args.subtitle)
    (out_dir / "benchmark-chart.svg").write_text(svg)
    (out_dir / "benchmark-chart.md").write_text(md)
    print(f"wrote {out_dir/'benchmark-chart.svg'}")
    print(f"wrote {out_dir/'benchmark-chart.md'}")
    print(md)


if __name__ == "__main__":
    main()
